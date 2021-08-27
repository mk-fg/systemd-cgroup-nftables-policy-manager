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

Both rules use xt_cgroup kernel module that - when looking at the packet -
actually matches cgroup ID, and not the path string, and does not update those
IDs dynamically when cgroups are created/removed in any way.

This means that:

- Firewall rules can't be added for not-yet-existing cgroups.

  Causes "Error: cgroupv2 path fails: No such file or directory" from nft and
  "xt_cgroup: invalid path, errno=-2" error in dmesg for iptables.

- If cgroup gets removed and re-created, none of the existing rules will apply to it.

  This is because new cgroup gets a new unique ID, which can't be present in any
  pre-existing netfilter tables, so none of the rules will match it.

So basically such rules in a global policy only work for cgroups that are
created early on boot and never removed after that.

This is not what happens with most systemd services and slices, restarting which
will also re-create cgroups, and which are usually started way after system-wide
firewalls are initialized (and often can't be started on boot - e.g. user units).


Solution
~~~~~~~~

Monitor cgroup creation/removal events and (re-)apply any relevant rules to
these dynamically.

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
but unlikely to be implemented, as (at least so far) systemd does not manage
netfilter firewall configurations.

Note that systemd has built-in network filtering via eBPF though, which can be
used as an alternative to this kind of system-wide policy approach in at least
some cases.

.. _how "socket cgroupv2" matcher in nftables is intended to work: https://patchwork.ozlabs.org/project/netfilter-devel/patch/1479114761-19534-1-git-send-email-pablo@netfilter.org/
.. _systemd#7327: https://github.com/systemd/systemd/issues/7327


Intended use-case
~~~~~~~~~~~~~~~~~

Defining system-wide policy to whitelist outgoing connections from specific
systemd units (can be services/apps, slices of those, or ad-hoc scopes)
in an easy and relatively foolproof way.

I.e. if a desktop system is connected to some kind of "intranet" VPN, there's
no reason for random and insecure apps like a web browsers or games to be able
to connect to anything there, and that is trivial to block via single firewall
rule.

This tool manages a whitelist of systemd units that should have access there
(and hence are allowed to bypass such rule) on top of that.

This is hard to implement with systemd's resource-control eBPF restrictions,
as they do not cooperate with each other to create exceptions from child cgroups,
but maybe possible with custom eBPFs that mark packets, though these also
require root (or CAP_BPF) to attach, so extra-tricky to use from transient and
numerous lower-level/leaf units under "systemd --user", which tend to be where
such stuff is most needed (i.e. your terminal or whatever client apps).



Build / Install
---------------

This is a simple OCaml_ app with C bindings, which can be built using any modern
(4.10+) ocamlopt compiler and the usual make::

  % make
  % scnpm --help
  Usage: ./scnpm [opts] [nft-configs ...]
  ...

That should produce ~1.5M binary, linked against libsystemd (for journal access)
and libnftables (to re-apply cgroupv2 nftables rules), which can be installed and
copied between systems normally.

.. _OCaml: https://ocaml.org/



Usage
-----

Not implemented yet.

| TODO: should probably use sd-dbus and dbus signals instead of journal
| TODO: note on server-side journal filtering, if I'll stick to using it



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
