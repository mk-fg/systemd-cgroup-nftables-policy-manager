(* Systemd cgroup (v2) nftables policy manager tool
 *
 * Build with:
 *   % ocamlopt -o scnpm -O2 unix.cmxa str.cmxa -cclib -lsystemd scnpm.ml scnpm.ml.c
 *   % strip scnpm
 *
 * Usage:
 *   % ./scnpm --help
 *   % ./scnpm nftables.conf
 *)

let cli_debug = ref false
let cli_nft_configs = ref []
let cli_update_interval = ref 1.0
let cli_update_delay = ref 0.0

(* Command-line args processing *)
let () =
	Arg.parse
		[ ("-i", Arg.Set_float cli_update_interval, " ");
			("--interval", Arg.Set_float cli_update_interval,
				"-- Min interval between nft updates, measured from the last update.\n" ^
				"        Can be used to batch quick changes or filter-out too transient ones.\n" ^
				"        Default: " ^ (string_of_float !cli_update_interval));
			("-w", Arg.Set_float cli_update_delay, " ");
			("--wait-delay", Arg.Set_float cli_update_delay,
				"-- Fixed delay before applying new nft updates, which can be used to avoid\n" ^
				"        changing rules back-and-forth for transient unit state changes. Default: " ^
				(string_of_float !cli_update_delay));
			("-d", Arg.Set cli_debug, " ");
			("--debug", Arg.Set cli_debug, "-- Verbose operation mode.") ]
		(fun arg -> cli_nft_configs :=  arg :: !cli_nft_configs)
		("Usage: " ^ Sys.argv.(0) ^ " [opts] [nft-configs ...]\
			\n\nScript that adds and updates nftables cgroupv2 filtering rules\n\
				for systemd-managed per-unit cgroups (slices, services, scopes).\n");


(* journal_record and journal_fields should have same field count/order *)
(* Can also check/use JOB_TYPE=start/stop/restart/etc *)
type journal_record = {u: string; uu: string} [@@boxed]
let journal_fields = ["MESSAGE"; "UNIT"; "USER_UNIT"]

(* Simple sd-journal bindings from scnpm.ml.c *)
external journal_open : string list -> unit = "mlj_open"
external journal_close : unit -> unit = "mlj_close"
external journal_wait : int -> bool = "mlj_wait"
external journal_read : unit -> journal_record = "mlj_read"

external journal_match : string -> unit = "mlj_match"
external journal_match_or : unit -> unit = "mlj_match_or"
external journal_match_and : unit -> unit = "mlj_match_and"
external journal_match_flush : unit -> unit = "mlj_match_flush"

let journal_wait_us = 3600_000_000 (* don't need a limit for local journal *)


let tail_journal () =
	let try_finally f x finally y =
		let res = try f x with e -> finally y; raise e in finally y; res in
	let debug_print line = if !cli_debug then print_endline line; flush stdout in

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
			(* debug_print "journal :: parsing msg backlog"; *)
			let rec tail_parse_iter () =
				let jr = journal_read () in
				(* debug_print (Printf.sprintf "journal :: - msg: %s" jr.msg); *)
				Queue.add jr tail_queue;
				tail_parse_iter () in
			try tail_parse_iter ()
			with End_of_file -> () in
				(* let queue_len = Queue.length tail_queue in
				 * debug_print (Printf.sprintf "journal :: parser-done queue=%d" queue_len) in *)
		let rec tail_parse_wait () =
			(* debug_print "journal :: poll..."; *)
			let update = journal_wait journal_wait_us in
			if update then tail_parse () else tail_parse_wait () in
		let rec tail_iter n =
			try Option.some (Queue.take tail_queue)
			with Queue.Empty -> tail_parse_wait (); tail_iter n in
		Stream.from tail_iter in

	let rec run_tail_loop () =
		let jr = Stream.next tail in
		debug_print (Printf.sprintf "journal :: event u=%s uu=%s" jr.u jr.uu);
		run_tail_loop () in

	debug_print "Starting journal-parser loop...";
	init (); try_finally run_tail_loop () cleanup ()


let () = Unix.handle_unix_error tail_journal ()
	(* let sig_done = Sys.Signal_handle (fun sig_n -> exit 0) in
	 * 	Sys.set_signal Sys.sigterm sig_done;
	 * 	Sys.set_signal Sys.sigint sig_done;
	 * Unix.handle_unix_error tail_journal () *)
