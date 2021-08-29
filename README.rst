systemd cgroup (v2) nftables policy manager
===========================================

.. contents::
  :backlinks: none


Description
-----------

Tool that adds and updates nftables_ cgroupv2 filtering rules for
systemd_-managed per-unit cgroups (slices, services, scopes).

"cgroupv2" is also often referred to as "unified cgroup hierarchy" (considered
stable in linux since 2015), works differently from old cgroup implementation,
and is the only one supported here.

.. _nftables: https://nftables.org/
.. _systemd: https://systemd.io/


Problem that it addressess
~~~~~~~~~~~~~~~~~~~~~~~~~~

nftables supports "socket cgroupv2" matching in rules (since linux-5.13+),
similar to iptables' "-m cgroup --path ...", which can be used to add rules
like this::

  add rule inet filter output socket cgroupv2 level 5 \
    "user.slice/user-1000.slice/user@1000.service/app.slice/myapp.service" accept

(or in iptables: ``iptables -A OUTPUT -m cgroup --path ... -j ACCEPT``)

But when trying to put this into /etc/nftables.conf, it will fail to load on boot
(same as similar iptables rules), as that "myapp.service" cgroup with a long
path does not exist yet.

Both nft/ipt rules use xt_cgroup kernel module that - when looking at the packet -
actually matches numeric cgroup ID, and not the path string, and does not update
those IDs dynamically when cgroups are created/removed in any way.

This means that:

- Firewall rules can't be added for not-yet-existing cgroups.

  Causes "Error: cgroupv2 path fails: No such file or directory" from nft and
  "xt_cgroup: invalid path, errno=-2" error in dmesg for iptables.

- If cgroup gets removed and re-created, none of the existing rules will apply to it.

  This is because new cgroup gets a new unique ID, which can't be present in any
  pre-existing netfilter tables, so none of the rules will match it.

So basically such rules in a system-wide policy-config only work for cgroups
that are created early on boot and never removed after that.

This is not what happens with most systemd services and slices, restarting which
will also re-create cgroups, and which are usually started way after system
firewalls are initialized (and often can't be started on boot - e.g. user units).


Solution:
~~~~~~~~~

Monitor cgroup (or systemd unit) creation/removal events and (re-)apply any
relevant rules to these dynamically.

This is `how "socket cgroupv2" matcher in nftables is intended to work`_::

  Following the decoupled approach: If the cgroup is gone, the filtering
  policy would not match anymore. You only have to subscribe to events
  and perform an incremental updates to tear down the side of the
  filtering policy that you don't need anymore. If a new cgroup is
  created, you load the filtering policy for the new cgroup and then add
  processes to that cgroup. You only have to follow the right sequence
  to avoid problems.

So that's pretty much what this tool does, subscribing to systemd unit
start/stop events via journal (using libsystemd) and updating any relevant
rules on events from there (using libnftables).

It was proposed for systemd itself to do something like that in `systemd#7327`_,
but is unlikely to be implemented, as (at least so far) systemd does not manage
netfilter firewall configurations.

Note that systemd has built-in network filtering via eBPFs attached to cgroups
(via IPAddressAllow/Deny=, BPFProgram=, IPEgressFilterPath=, and similar options)
which can be used as an alternative to this kind of system-wide policy approach
for at least some use-cases, though might be more difficult to combine and maintain
in multiple places, with more lax permissions, and with limited matching capabilities.

.. _how "socket cgroupv2" matcher in nftables is intended to work: https://patchwork.ozlabs.org/project/netfilter-devel/patch/1479114761-19534-1-git-send-email-pablo@netfilter.org/
.. _systemd#7327: https://github.com/systemd/systemd/issues/7327


Intended use-case:
~~~~~~~~~~~~~~~~~~

Defining system-wide policy to whitelist outgoing connections from specific
systemd units (can be services/apps, slices of those, or ad-hoc scopes)
in an easy and relatively foolproof way.

I.e. if a desktop system is connected to some kind of "intranet" VPN, there's
no reason for random and insecure apps like web browsers or games to be able
to connect to anything there (think fetch() JS call from any site you visit),
and that is trivial to block with a single firewall rule.

This tool is intended to manage a whitelist of rules for systemd units that
should have access there (and hence are allowed to bypass such rule) on top of that.



Build / Install
---------------

This is a simple OCaml_ app with C bindings, which can be built using any modern
(4.10+) ocamlopt compiler and the usual make::

  % make
  % scnpm --help
  Usage: ./scnpm [opts] [nft-configs ...]
  ...

That should produce ~1M binary, linked against libsystemd (for journal access)
and libnftables (to re-apply cgroupv2 nftables rules), which can then be installed
and copied between systems normally.

OCaml compiler is only needed to build the tool, not to run it.

Journal is used as an event source instead of more conventional dbus signals to be
able to monitor state of all "systemd --user" unit instances as well as system ones,
which will be sent over multiple transient dbus'es, so much more difficult to
reliably track otherwise.

.. _OCaml: https://ocaml.org/



Usage
-----

Tool is designed to parse special commented-out rules for it from the same
nftables.conf as used with the rest of ruleset, for consistency
(though of course they can be stored in any other file(s) as well)::

  ## Allow connections to/from vpn for system postfix.service
  # postfix.service :: add rule inet filter vpn.whitelist \
  #   socket cgroupv2 level 2 "system.slice/postfix.service" tcp dport 25 accept

  ## Allow connections to/from vpn for a scope unit running under "systemd --user"
  ## "systemd-run" can be used to easily start apps in custom scopes or slices
  # app-mail.scope :: add rule inet filter vpn.whitelist socket cgroupv2 level 5 \
  #   "user.slice/user-1000.slice/user@1000.service/app.slice/app-mail.scope" \
  #   tcp dport {25, 143} accept

  ## Only allow whitelisted apps to connect over "my-vpn" iface
  add rule inet filter output oifname my-vpn jump vpn.whitelist
  add rule inet filter output oifname my-vpn reject with icmpx type admin-prohibited

  ## Only allow whitelisted apps to receive connections from "my-vpn" iface
  add rule inet filter output iifname my-vpn jump vpn.whitelist
  add rule inet filter output iifname my-vpn reject with icmpx type admin-prohibited

  ## Note: instead of "reject" rules above, chain policy can be used when declaring it:
  # add chain inet filter vpn.whitelist { policy drop; }

Commented-out "add rule" lines would normally make this config fail to apply on
boot, as those service/scope/slice cgroups won't exist yet at that point in time.

Script will parse those "<unit-to-watch> :: <rule>" comments, and try to apply
rules from them on start and whenever any kind of state-change happens to a unit
with the name specified there.

For example, when postfix.service is stopped/restarted with the config above,
corresponding vpn.whitelist rule will be removed and re-added, allowing access
to a new cgroup which systemd will create for it after restart.

To start it in verbose mode: ``./scnpm --flush --debug /etc/nftables.conf``

``-f/--flush`` option will purge (flush) all chains mentioned in the rules
that it will monitor/apply on tool start, so that leftover rules from any
previous runs are removed, and can be replaced with more fine-grained manual
removal if these are not dedicated chains used for such dynamic rules only.

Running without ``-d/--debug`` should not normally produce any output, unless
there are some (non-critical) warnings (e.g. a strange mismatch somewhere),
code bugs or fatal errors.

Starting the tool on boot should be scheduled after nftables.service,
so that ``--flush`` option will be able to find all required chains,
and will exit with an error otherwise.

Multiple nft rules linked to same systemd unit(s) are allowed.

Syntax errors in nft rules are not currently detected and will be silenced,
so check "nft list chain" or debug output when those are supposed to be
enabled at least once.



Links
-----

- `helsinki-systems/nft_cgroupv2`_ - alternative third-party implementation of
  such matching in nftables.

  AFAICT it doesn't rely on cgroup id's and instead resolves these from cgroup
  path for every packet, which is probably not great wrt performance, but might
  be ok for most use-cases where conntrack filters-out traffic before these rules.

  Might conflict with current upstream nftables implementation due to "cgroupv2"
  keyword used there as well.

  .. _helsinki-systems/nft_cgroupv2: https://github.com/helsinki-systems/nft_cgroupv2/

- Systemd RFE-7327 about this sort of thing: https://github.com/systemd/systemd/issues/7327

- `Upstreamed "netfilter: nft_socket: add support for cgroupsv2" patch
  <https://patchwork.ozlabs.org/project/netfilter-devel/patch/20210426171056.345271-3-pablo@netfilter.org/>`_
  for "cgroupv2" matching support in nftables (0.99+) on the linux kernel side (linux-5.13+).

- `"netfilter: implement xt_cgroup cgroup2 path match" patch
  <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c38c4597>`_
  from linux-4.5.
