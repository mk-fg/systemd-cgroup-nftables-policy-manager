#? replace(sub = "\t", by = "  ")
#
# Debug build/run: nim c -w=on --hints=on -r scnpm.nim -h
# Final build: nim c -d:release -d:strip -d:lto_incremental --opt:size scnpm.nim
# Usage info: ./scnpm -h

import std/[ parseopt, os, posix, logging, sugar,
	strformat, strutils, sequtils, re, tables, times, monotimes ]

template nfmt(v: untyped): string = ($v).insertSep # format integer with digit groups


### sd-journal api wrapper

{.passl: "-lsystemd"}

type
	sd_journal {.importc: "sd_journal*", header: "<systemd/sd-journal.h>".} = object
	sd_journal_msg {.importc: "const void*".} = cstring
let
	SD_JOURNAL_LOCAL_ONLY {.importc, nodecl.}: cint
	SD_JOURNAL_NOP {.importc, nodecl.}: cint

proc c_strerror(errnum: cint): cstring {.importc: "strerror", header: "<string.h>".}

proc sd_journal_open(sdj: ptr sd_journal, flags: cint): cint {.importc, header: "<systemd/sd-journal.h>".}
proc sd_journal_close(sdj: sd_journal) {.importc, header: "<systemd/sd-journal.h>".}
proc sd_journal_get_fd(sdj: sd_journal): cint {.importc, header: "<systemd/sd-journal.h>".}
proc sd_journal_seek_tail(sdj: sd_journal): cint {.importc, header: "<systemd/sd-journal.h>".}
proc sd_journal_wait(sdj: sd_journal, timeout_us: uint64): cint {.importc, header: "<systemd/sd-journal.h>".}
proc sd_journal_next(sdj: sd_journal): cint {.importc, header: "<systemd/sd-journal.h>".}
proc sd_journal_previous(sdj: sd_journal): cint {.importc, header: "<systemd/sd-journal.h>".}
proc sd_journal_get_data( sdj: sd_journal, field: cstring,
	msg: ptr sd_journal_msg, msg_len: ptr csize_t ): cint {.importc, header: "<systemd/sd-journal.h>".}
proc sd_journal_add_match( sdj: sd_journal,
	s: cstring, s_len: csize_t ): cint {.importc, header: "<systemd/sd-journal.h>".}
proc sd_journal_add_disjunction(sdj: sd_journal): cint {.importc, header: "<systemd/sd-journal.h>".} # OR
proc sd_journal_add_conjunction(sdj: sd_journal): cint {.importc, header: "<systemd/sd-journal.h>".} # AND

type
	Journal = object
		ctx: sd_journal
		closed: bool
		ret: cint
		c_msg: sd_journal_msg
		c_msg_len: csize_t
		field: string
	JournalError = object of CatchableError

template sdj_err(call: untyped, args: varargs[untyped]): cint =
	if o.closed: o.ret = -EPIPE
	else: o.ret = when varargsLen(args) > 0:
		`sd journal call`(o.ctx, args) else: `sd journal call`(o.ctx)
	-o.ret
template sdj(call: untyped, args: varargs[untyped]) =
	discard sdj_err(call, args)
	if o.ret < 0: raise newException( JournalError,
		"sd_journal_" & astToStr(call) & &" failed = {c_strerror(-o.ret)}" )
template sdj_ret(call: untyped, args: varargs[untyped]): cint =
	sdj(call, args)
	o.ret

method init(o: var Journal) {.base.} =
	if sd_journal_open(o.ctx.addr, SD_JOURNAL_LOCAL_ONLY) < 0:
		raise newException(JournalError, "systemd journal open failed")
	o.closed = false
	sdj get_fd # to mimic journalctl.c - "means the first sd_journal_wait() will actually wait"
	sdj seek_tail
	sdj previous

method close(o: var Journal) {.base.} =
	o.closed = true
	sd_journal_close(o.ctx)

method setup_filters(o: var Journal) {.base.} =
	# systemd journal match-list uses CNF logic, e.g. "level=X && (unit=A || ... || tag=B || ...) && ..."
	# online CNF calculator: https://www.dcode.fr/boolean-expressions-calculator
	# systemd does not support negation atm - https://github.com/systemd/systemd/pull/12592
	# Using journal_make_match_string in test-journal-match.c is a good way to make sense of this:
	#   meson setup build && ninja -C build -v libsystemd && meson test -C build test-journal-match
	sdj(add_match, "SYSLOG_IDENTIFIER=systemd", 25)
	sdj add_conjunction
	sdj(add_match, "JOB_RESULT=done", 15)
	sdj add_disjunction
	sdj(add_match, "JOB_TYPE=start", 15)
	sdj add_conjunction
	sdj(add_match, "_SYSTEMD_UNIT=init.scope", 24)
	sdj add_disjunction
	sdj(add_match, "_SYSTEMD_USER_UNIT=init.scope", 29)

method read_field(o: var Journal, key: string): bool {.base.} =
	result = sdj_err(get_data, key, o.c_msg.addr, o.c_msg_len.addr) != ENOENT
	if result:
		o.field = newString(o.c_msg_len)
		copyMem(o.field.cstring, o.c_msg, o.c_msg_len)
		o.field = o.field.substr(key.len + 1)

method poll(
		o: var Journal, units: Table[string, seq[string]],
		us: uint64 = 3600_000_000'u64 ): string {.base.} =
	while true:
		while sdj_ret(next) > 0:
			if not o.read_field("UNIT"):
				if not o.read_field("USER_UNIT"): continue
			let relevant = units.hasKey(o.field)
			debug("Detected job-event for unit: ", o.field, " [has-rule=", relevant, "]")
			if relevant: return o.field
		if sdj_ret(wait, us) == SD_JOURNAL_NOP:
			debug("Journal-poll wait-timeout: us=", us.nfmt)
			return ""


### libnftables bindings

{.passl: "-lnftables"}

type nft_ctx {.importc: "nft_ctx*", header: "<nftables/libnftables.h>".} = distinct pointer
let
	NFT_CTX_DEFAULT {.importc, nodecl.}: uint32
	NFT_CTX_OUTPUT_ECHO {.importc, nodecl.}: cuint
	NFT_CTX_OUTPUT_HANDLE {.importc, nodecl.}: cuint
	NFT_CTX_OUTPUT_NUMERIC_ALL {.importc, nodecl.}: cuint
	NFT_CTX_OUTPUT_TERSE {.importc, nodecl.}: cuint

proc nft_ctx_new(flags: uint32): nft_ctx {.importc, header: "<nftables/libnftables.h>".}
proc nft_ctx_free(ctx: nft_ctx) {.importc, header: "<nftables/libnftables.h>".}
proc nft_ctx_buffer_output(ctx: nft_ctx): cint {.importc, header: "<nftables/libnftables.h>".}
proc nft_ctx_buffer_error(ctx: nft_ctx): cint {.importc, header: "<nftables/libnftables.h>".}
proc nft_ctx_output_set_flags(ctx: nft_ctx, flags: cuint) {.importc, header: "<nftables/libnftables.h>".}
proc nft_run_cmd_from_buffer(ctx: nft_ctx, buff: cstring): cint {.importc, header: "<nftables/libnftables.h>".}
proc nft_ctx_get_output_buffer(ctx: nft_ctx): cstring {.importc, header: "<nftables/libnftables.h>".}
proc nft_ctx_get_error_buffer(ctx: nft_ctx): cstring {.importc, header: "<nftables/libnftables.h>".}

type
	NFTables = object
		ctx: nft_ctx
		ret: cint
	NFTablesError = object of CatchableError
	NFTablesCmdFail = object of CatchableError
	NFTablesCmdNoCG = object of CatchableError

let
	re_rule_prefix = re"^(\S+ +\S+ +\S+ +)"
	re_handle = re"^(add|insert) rule .* # handle (\d+)\n"
	re_add_skip = re"^Error: cgroupv2 path fails: No such file or directory\b"

method init(o: var NFTables) {.base.} =
	o.ctx = nft_ctx_new(NFT_CTX_DEFAULT)
	if nft_ctx_buffer_output(o.ctx) != 0:
		raise newException(NFTablesError, "nftables set output buffering failed")
	if nft_ctx_buffer_error(o.ctx) != 0:
		raise newException(NFTablesError, "nftables set error buffering failed")
	nft_ctx_output_set_flags( o.ctx,
		NFT_CTX_OUTPUT_ECHO or NFT_CTX_OUTPUT_HANDLE or
		NFT_CTX_OUTPUT_NUMERIC_ALL or NFT_CTX_OUTPUT_TERSE )

method close(o: var NFTables) {.base.} = nft_ctx_free(o.ctx)

method run(o: NFTables, commands: string): string {.base.} =
	let
		success = nft_run_cmd_from_buffer(o.ctx, commands.cstring) == 0
		buff = if success: nft_ctx_get_output_buffer(o.ctx) else: nft_ctx_get_error_buffer(o.ctx)
	result = ($buff).strip()
	if not success:
		if result =~ re_add_skip: raise newException(NFTablesCmdNoCG, result)
		raise newException(NFTablesCmdFail, result)

method apply(o: NFTables, rule: string): int {.base.} =
	debug("nft apply :: ", rule)
	let s = o.run(rule)
	if s =~ re_handle: return matches[1].parseInt
	raise newException(NFTablesError, "BUG - failed to parse rule handle from nft output:\n" & s.strip())

method delete(o: NFTables, rule: string, handle: int) {.base.} =
	debug("nft delete :: ", handle, " :: ", rule)
	if rule =~ re_rule_prefix:
		discard o.run(&"delete rule {matches[0]} handle {handle}")
	else: raise newException(NFTablesError, "Failed to match table-prefix in a rule")

method flush_rule_chains(o: NFTables, rules: openArray[string]) {.base.} =
	var chains = collect(newSeq):
		for rule in rules:
			if rule =~ re_rule_prefix: matches[0]
	chains = chains.deduplicate
	for chain in chains: debug("nft flush :: ", chain)
	discard o.run(chains.mapIt(&"flush chain {it}").join("\n"))


### main

var # globals for noconv
	sq = Journal()
	nft = NFTables()
	reexec = false

type ParseError = object of CatchableError

proc parse_unit_rules(conf_list: seq[string]): Table[string, seq[string]] =
	result = initTable[string, seq[string]]()
	var
		re_start = re"^#+ *([^ ]+\.[a-zA-Z]+) +:: +(add +(rule +)?)?(.*)$"
		re_cont = re"^#+ (.*)$"
		cg = ""
		line_pre = ""
	for p in conf_list:
		debug("Parsing config-file: ", p)
		for line in readFile(p).splitLines:
			var line = line

			if line_pre != "":
				if line =~ re_cont:
					line_pre &= " " & matches[0].strip(chars={'\\'}).strip()
					if line.endsWith("\\"): continue
					line = line_pre
					cg = ""; line_pre = ""
				else: raise newException( ParseError,
					&"Broken rule continuation [ {cg} ]: '{line_pre}' + '{line}'" )

			if line =~ re_start:
				cg = matches[0]
				if line.endsWith("\\"): line_pre = line.strip(chars={'\\'}).strip()
				else:
					if not result.hasKey(cg): result[cg] = newSeq[string]()
					line = matches[3].strip()
					if not (line =~ re_rule_prefix):
						raise newException( ParseError,
							&"Failed to validate 'family table chain ...' rule [ {cg} ]: {line}" )
					result[cg].add(line)

proc main_help(err="") =
	proc print(s: string) =
		let dst = if err == "": stdout else: stderr
		write(dst, s); write(dst, "\n")
	let app = getAppFilename().lastPathPart
	if err != "": print &"ERROR: {err}"
	print &"\nUsage: {app} [opts] [nft-configs ...]"
	if err != "": print &"Run '{app} --help' for more information"; quit 1
	print dedent(&"""

		systemd cgroup (v2) nftables policy manager.
		Small tool that adds and updates nftables cgroupv2 filtering
			rules for systemd-managed per-unit cgroups (slices, services, scopes).

		 -f / --flush
			Flush nft chain(s) used in all parsed cgroup-rules on start, to cleanup leftovers
				from previous run(s), as otherwise only rules added at runtime get replaced/removed.

		 -u / --reload-with-unit unit-name
			Reload and re-apply all rules (and do -f/--flush if enabled) on systemd unit state changes.
			Can be useful to pass something like nftables.service with this option, as restarting
				that usually flushes nft rulesets and can indicates changes in the dynamic rules there.
			Option can be used multiple times to act on events from any of the specified units.
			Same as restarting the tool, done via simple re-exec internally, runs on SIGHUP.

		 -a / --reapply-with-unit unit-name
			Same as -u/--reload-with-unit, but does not reload the rules.

		 -c / --cooldown milliseconds
			Min interval between applying rules for the same cgroup/unit (default=300ms).
			If multiple events for same unit are detected,
				subsequent ones are queued to apply after this interval.

		 -d / --debug -- Verbose operation mode.
		""")
	quit 0

proc main(argv: seq[string]) =
	var
		opt_flush = false
		opt_debug = false
		opt_cooldown = initDuration(milliseconds=300)
		opt_reapply_units = newSeq[string]()
		opt_reexec_units = newSeq[string]()
		opt_nft_confs = newSeq[string]()

	block cli_parser:
		var opt_last = ""
		proc opt_fmt(opt: string): string =
			if opt.len == 1: &"-{opt}" else: &"--{opt}"
		proc opt_empty_check =
			if opt_last == "": return
			main_help &"{opt_fmt(opt_last)} option unrecognized or requires a value"
		proc opt_set(k: string, v: string) =
			if k in ["u", "reload-with-unit"]: opt_reexec_units.add(v)
			elif k in ["a", "reapply-with-unit"]: opt_reapply_units.add(v)
			elif k in ["c", "cooldown"]: opt_cooldown = initDuration(milliseconds=v.parseInt)
			else: main_help &"Unrecognized option [ {opt_fmt(k)} = {v} ]"

		for t, opt, val in getopt(argv):
			case t
			of cmdEnd: break
			of cmdShortOption, cmdLongOption:
				if opt in ["h", "help"]: main_help()
				elif opt in ["f", "flush"]: opt_flush = true
				elif opt in ["d", "debug"]: opt_debug = true
				elif val == "": opt_empty_check(); opt_last = opt
				else: opt_set(opt, val)
			of cmdArgument:
				if opt_last != "": opt_set(opt_last, opt); opt_last = ""
				else: opt_nft_confs.add(opt)
		opt_empty_check()

	var logger = newConsoleLogger(
		fmtStr="$levelid $datetime :: ", useStderr=true,
		levelThreshold=if opt_debug: lvlAll else: lvlInfo )
	addHandler(logger)

	debug("Processing configuration...")
	var rules = parse_unit_rules(opt_nft_confs)
	for unit in opt_reexec_units: rules[unit] = @[]
	for unit in opt_reapply_units: rules[unit] = @[] # special "rules" to reapply/reexec

	debug("Parsed following cgroup rules (empty=reapply-rules):")
	for unit, rules in rules.pairs:
		for rule in rules: debug("  ", unit, " :: ", rule)

	debug("Initializing nftables/journal components...")
	nft.init()
	defer: nft.close()
	sq.init() # closed from signal handler to interrupt wait
	sq.setup_filters()

	onSignal(SIGINT, SIGTERM, SIGHUP):
		if sig == SIGHUP:
			debug("Got re-exec signal, restarting...")
			reexec = true
		else: debug("Got exit signal, shutting down...")
		sq.close()

	var
		ts_now: MonoTime
		ts_wake: MonoTime
		ts_wake_unit: string
		unit: string
		rule_queue = initTable[string, tuple[ts: MonoTime, apply: bool]]()
		rule_handles = initTable[string, int]() # rule -> handle
		reapply = false

	proc rules_queue_all() =
		debug("Rules schedule: all rules")
		ts_now = getMonoTime()
		for unit, rules in rules.pairs:
			if rules.len > 0: rule_queue[unit] = (ts: ts_now, apply: true)

	proc rules_apply(unit: string, rules: seq[string]) =
		for rule in rules:
			rule_handles.withValue(rule, n):
				try: nft.delete(rule, n[])
				except NFTablesCmdFail: discard
			try:
				let n = nft.apply(rule)
				rule_handles[rule] = n
				debug("Rule added: unit=", unit, " handle=", n, " :: ", rule)
			except NFTablesCmdNoCG:
				debug("Rule skipped - no cgroup: unit=", unit, " :: ", rule)
			except NFTablesCmdFail as err:
				warn("Rule failed to apply: unit=", unit, " :: ", rule)
				for line in err.msg.strip.splitLines: warn(line.indent(2))

	proc rules_flush() =
		nft.flush_rule_chains(rules.values.toSeq.concat)

	if opt_flush:
		debug("Flushing all affected nftables chains...")
		rules_flush()

	debug("Starting main loop...")
	rules_queue_all() # initial try-them-all after flush
	while not sq.closed:
		ts_now = getMonoTime(); ts_wake = ts_now; ts_wake_unit = ""

		for n, (unit, check) in rule_queue.pairs.toSeq:
			if ts_now >= check.ts:
				if check.apply:
					debug("Rules apply: unit=", unit)
					rule_queue[unit] = (ts: ts_now + opt_cooldown, apply: false)
					let rules = rules[unit]
					if rules.len == 0: # one of the -u/--re*-with-unit
						if unit in opt_reexec_units:
							debug("Rule for reload-with-unit event, restarting...")
							reexec = true; sq.close()
						else:
							debug("Rule for reapply-with-unit event")
							reapply = true
						break
					else: rules_apply(unit, rules)
				else:
					rule_queue.del(unit)
					debug("Rules cooldown expired: unit=", unit)
			elif check.ts < ts_wake or ts_wake == ts_now:
				ts_wake = check.ts; ts_wake_unit = unit

		if reapply:
			if opt_flush: rules_flush()
			rules_queue_all()
			reapply = false
			continue

		let delay =
			if ts_wake == ts_now: 3600_000_000'u64
			else: uint64((ts_wake - ts_now).inMicroseconds)
		if ts_wake_unit != "":
			debug("Rules cooldown wait: unit=", ts_wake_unit, " us=", delay.nfmt)
		try: unit = sq.poll(rules, delay)
		except JournalError:
			if sq.closed: break
			raise
		if unit == "": continue # timeout-wakeup

		ts_now = getMonoTime()
		rule_queue.withValue(unit, check):
			if check.ts > ts_now:
				debug( "Rules schedule delayed: unit=", unit,
					" us=", (check.ts - ts_now).inMicroseconds.nfmt )
				check.apply = true; continue # apply after cooldown
		debug("Rules schedule now: unit=", unit)
		rule_queue[unit] = (ts: ts_now, apply: true)

	if reexec:
		debug("Restarting tool via exec...")
		let app = getAppFilename()
		discard execv(app.cstring, concat(@[app], argv).allocCStringArray)
	debug("Finished")

when is_main_module: main(commandLineParams())
