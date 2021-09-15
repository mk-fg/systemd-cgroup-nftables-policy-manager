(* Systemd cgroup (v2) nftables policy manager tool
 *
 * Build with:
 *   % ocamlopt -o scnpm -O2 str.cmxa \
 *       -cclib -lsystemd -cclib -lnftables scnpm.ml scnpm.ml.c
 *   % strip scnpm
 *
 * Usage:
 *   % ./scnpm --help
 *   % ./scnpm --flush --debug /etc/nftables.conf
 *)

let cli_flush_chains = ref false
let cli_quiet = ref false
let cli_debug = ref false
let cli_nft_configs = ref []
let cli_reload_units = ref []
let cli_reload_units_add = (fun u -> cli_reload_units := u :: !cli_reload_units)

let () =
	let t = "\n      " in
	Arg.parse
		[ ("-f", Arg.Set cli_flush_chains, " ");
			("--flush", Arg.Set cli_flush_chains,
				t^"Flush nft chain(s) used in all rules on start, to cleanup any leftover ones" ^
				t^" from previous run(s), as otherwise only rules added during runtime are replaced/removed.");
			("-u", Arg.String cli_reload_units_add, "unit-name");
			("--reload-with-unit", Arg.String cli_reload_units_add, "unit-name" ^
				t^"Reload rules (and flush chain[s] with -f/--flush) on specified system unit state changes." ^
				t^"Can be useful to pass something like nftables.service with this option," ^
				t^" as restarting that usually flushes nft rulesets and all dynamic rules in there." ^
				t^"Option can be used multiple times to reload for any of the specified units.");
			("-q", Arg.Set cli_quiet, " ");
			("--quiet", Arg.Set cli_quiet, "-- Suppress non-fatal logging.");
			("-d", Arg.Set cli_debug, " ");
			("--debug", Arg.Set cli_debug, "-- Verbose operation mode. Overrides -q/--quiet.") ]
		(fun conf -> cli_nft_configs := conf :: !cli_nft_configs)
		("Usage: " ^ Sys.argv.(0) ^ " [opts] [nft-configs ...]\
			\n\nScript that adds and updates nftables cgroupv2 filtering rules\n\
				for systemd-managed per-unit cgroups (slices, services, scopes).\n");


(* journal_record and journal_fields should have same field count/order *)
(* Can also check/use JOB_TYPE=start/stop/restart/etc *)
(* Initially thought that I might need more props than just unit name(s) here... *)
type journal_record = {u: string; uu: string} [@@boxed]
let journal_fields = ["UNIT"; "USER_UNIT"]
let journal_wait_us = 3600_000_000 (* don't need a limit for local journal *)

(* Simple sd-journal bindings from scnpm.ml.c *)
external journal_open : string list -> unit = "mlj_open"
external journal_close : unit -> unit = "mlj_close"
external journal_wait : int -> bool = "mlj_wait"
external journal_read : unit -> journal_record = "mlj_read"
external journal_match : string -> unit = "mlj_match"
external journal_match_or : unit -> unit = "mlj_match_or"
external journal_match_and : unit -> unit = "mlj_match_and"
external journal_match_flush : unit -> unit = "mlj_match_flush"

(* libnftables bindings from scnpm.ml.c *)
let nft_table_size_hint = 8
external nft_init : unit -> unit = "mlnft_init"
external nft_free : unit -> unit = "mlnft_free"
external nft_apply : string -> (string, string) result = "mlnft_apply"

(* Misc minor helpers *)
let log_debug line = if !cli_debug then prerr_endline line; flush stdout
let log_warn line = if !cli_debug || not !cli_quiet then prerr_endline line; flush stderr
let fmt = Printf.sprintf
exception RuntimeFail of string (* for multiline-formatted errors before exit *)


let tail_journal () =

	let init () =
		journal_open journal_fields;
		(* systemd journal match-list uses CNF logic (AND of ORs), e.g. "level=X && (unit=A || ... || tag=B || ...)"
		 * online CNF calculator: https://www.dcode.fr/boolean-expressions-calculator
		 * systemd does not support negation atm - https://github.com/systemd/systemd/pull/12592 *)
		journal_match "SYSLOG_IDENTIFIER=systemd";
		journal_match "JOB_RESULT=done";
		journal_match_and ();
		journal_match "_SYSTEMD_UNIT=init.scope";
		journal_match_or ();
		journal_match "_SYSTEMD_USER_UNIT=init.scope" in
	let cleanup () = journal_close () in

	let tail = (* infinite stream of journal_record *)
		let tail_queue = Queue.create () in
		let tail_parse () =
			(* log_debug "journal :: parsing msg backlog"; *)
			let rec tail_parse_iter () =
				let jr = journal_read () in
				(* log_debug (fmt "journal :: - msg: %s" jr.msg); *)
				Queue.add jr tail_queue;
				tail_parse_iter () in
			try tail_parse_iter ()
			with End_of_file -> () in
				(* let queue_len = Queue.length tail_queue in
				 * log_debug (fmt "journal :: parser-done queue=%d" queue_len) in *)
		let rec tail_parse_wait () =
			(* log_debug "journal :: poll..."; *)
			let update = journal_wait journal_wait_us in
			if update then tail_parse () else tail_parse_wait () in
		let rec tail_iter n =
			try Queue.take tail_queue |> Option.some
			with Queue.Empty -> tail_parse_wait (); tail_iter n in
		Stream.from tail_iter in

	init (); tail, cleanup


exception ParseFail of string

let parse_unit_rules nft_configs =
	let table = Hashtbl.create nft_table_size_hint in
	let re_start, re_cont, re_rule = Str.(
		regexp "^#+ *\\([^ ]+\\.[a-zA-Z]+\\) +:: +\\(add +\\(rule +\\)?\\)?\\(.*\\)$",
		regexp "^#+ \\(.*\\)$", regexp "\\([^ ]+ +[^ ]+ +[^ ]+\\) +\\(.+\\)" ) in
	let rec parse_config fn =
		let src = open_in fn in
		let rec read_line cg rule =
			let cg, rule_start =
				if rule = "" then "", ""
				else if Str.last_chars rule 1 = "\\"
					then cg, Str.first_chars rule (String.length rule - 1) |> String.trim
					else (
						if Str.string_match re_rule rule 0 then Hashtbl.add table cg rule
						else raise (ParseFail (fmt "Missing \
							'family table chain' prefix in rule [ %s ]: %s" cg rule)); "", "" ) in
			let line =
				try (input_line src) ^ "\n"
				with End_of_file -> "" in
			if line <> "" then
				let line = String.trim line in
				let cg, rule_start =
					if rule_start <> "" then (
						if Str.string_match re_cont line 0
							then cg, rule_start ^ " " ^ (Str.matched_group 1 line |> String.trim)
							else raise (ParseFail (fmt "Broken rule \
								continuation in [ %s ]: '%s' + '%s'" fn rule_start line)) )
					else if Str.string_match re_start line 0
						then Str.matched_group 1 line, Str.matched_group 4 line
					else "", "" in
				read_line cg rule_start in
		read_line "" "" in
	List.iter parse_config nft_configs; table


let nft_state rules_cg flush_chains =
	let rules_nft = Hashtbl.create nft_table_size_hint in
	let re_prefix, re_handle, re_add_skip = Str.(
		regexp "^[^ ]+ +[^ ]+ +[^ ]+ +",
		regexp "^add rule .* # handle \\([0-9]+\\)\n",
		regexp "^Error: cgroupv2 path fails: No such file or directory\\b" ) in
	let rule_prefix rule = if Str.string_match re_prefix rule 0
		then Str.matched_string rule else raise (RuntimeFail "BUG - rule prefix mismatch") in
	let nft_output_ext s =
		let s = String.trim s in if s = "" then s else "\n" ^ String.( split_on_char '\n' s |>
			List.filter_map (fun s -> if s = "" then None else Some ("  " ^ s)) |> concat "\n" ) in
	let replace_rule ?(quiet = false) cg rule =
		( match Hashtbl.find_opt rules_nft rule with | None -> () | Some h ->
			match nft_apply (fmt "delete rule %s handle %d" (rule_prefix rule) h)
					with | Ok s -> () | Error s -> if not quiet then
				let nft_err = nft_output_ext s in
				log_warn (fmt "nft :: failed to remove tracked rule [ %s %d ]: %s%s" cg h rule nft_err) );
		Hashtbl.remove rules_nft rule;
		( match nft_apply (fmt "add rule %s" rule) with
			| Error s -> (* rules are expected to be rejected here - racy, no add/remove diff, etc *)
				let nft_err = nft_output_ext s in
				if Str.string_match re_add_skip s 0
					then log_debug (fmt "nft :: add-rule skipped :: %s%s" rule nft_err)
					else log_warn (fmt "nft :: add-rule failed with non-cgroupv2-path error :: %s%s" rule nft_err)
			| Ok s ->
				if Str.string_match re_handle s 0
				then
					let h = Str.matched_group 1 s |> int_of_string in
					Hashtbl.replace rules_nft rule h;
					log_debug (fmt "nft :: rule updated [ %s %d ]: %s" cg h rule)
				else
					let nft_echo = nft_output_ext s in
					raise (RuntimeFail (fmt "BUG - failed to \
						parse rule handle from nft echo:%s" nft_echo)) ) in
	let apply cg = Hashtbl.find_all rules_cg cg |> List.iter (replace_rule cg) in
	let apply_init ~quiet =
		let flush_map = Hashtbl.create 2 in
		if flush_chains then Hashtbl.iter (fun cg rule ->
			Hashtbl.replace flush_map (rule_prefix rule) ()) rules_cg;
		( match Hashtbl.to_seq_keys flush_map |> Seq.fold_left (fun a s ->
				log_debug (fmt "nft :: flush chain %s" s);
				a ^ "\n" ^ "flush chain " ^ s ) "" |> nft_apply with
			| Ok s -> () | Error s ->
				let nft_err = nft_output_ext s in
				raise (RuntimeFail (fmt "Failed to flush rule chains:%s" nft_err)) );
		Hashtbl.iter (replace_rule ~quiet) rules_cg in (* try to apply all initial rules *)
	nft_init (); apply_init, apply, nft_free


let () =
	let unit_rules = parse_unit_rules !cli_nft_configs in
	log_debug (fmt "config :: loaded rules: %d" (Hashtbl.length unit_rules));
	(* Hashtbl.iter (fun k v -> log_debug (fmt "config :: [ %s ] rule %s" k v)) unit_rules; *)
	let nft_apply_init, nft_apply, nft_free = nft_state unit_rules !cli_flush_chains in
	let tail, tail_cleanup = tail_journal () in
	let run_loop =
		let rec run_loop_tail init =
			(* Trying to bruteforce-reapply rule(s) here on any type of change in same-name leaf unit.
			 * cgroup/unit can be in a different tree or removed, so nft_apply might do delete/add or just nothing. *)
			( try
					if init then nft_apply_init ~quiet:false;
					let jr = Stream.next tail in
					log_debug (fmt "journal :: event u=%s uu=%s" jr.u jr.uu);
					if List.exists (String.equal jr.u) !cli_reload_units
						then nft_apply_init ~quiet:true
						else nft_apply (if jr.u = "" then jr.uu else jr.u)
				with RuntimeFail s ->
					prerr_endline (fmt "FATAL ERROR - %s" s);
					if Printexc.backtrace_status () then Printexc.print_backtrace stderr
						else prerr_endline "[run with OCAMLRUNPARAM=b to record/print a backtrace here]";
					exit 1 );
			run_loop_tail false in
		run_loop_tail true in
	Fun.protect ~finally:(fun () -> tail_cleanup (); nft_free ()) run_loop
