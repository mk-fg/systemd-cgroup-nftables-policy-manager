#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>

#include <systemd/sd-journal.h>

sd_journal *jj;
char field_count = 0, *fields[10];


value mlj_open(value v_fields) {
	// List of fields to return in a tuple from mlj_read() is specified/checked here
	CAMLparam1(v_fields);

	unsigned flags = SD_JOURNAL_LOCAL_ONLY;
	if (sd_journal_open(&jj, flags) < 0) caml_failwith("sd_journal_open failed");
	if (sd_journal_seek_tail(jj) < 0) caml_failwith("sd_journal_seek_tail failed");

	CAMLlocal1(v_head);
	int slen;
	while (v_fields != Val_emptylist) {
		v_head = Field(v_fields, 0); v_fields = Field(v_fields, 1);
		slen = caml_string_length(v_head);
		fields[field_count] = strncpy(malloc(slen), String_val(v_head), slen+1);
		if (++field_count > 10) caml_failwith("Too many fields"); }

	// Not sure why sd_journal_next_skip seem to be needed after sd_journal_seek_tail
	// Simple next() returns some tail entries, which is weirdly arbitrary, so skip 10 jic
	/* if (sd_journal_next_skip(jj, 10) < 0) caml_failwith("sd_journal_next_skip failed"); */
	// XXX: return 5 last entries for testing
	if (sd_journal_previous_skip(jj, 5) < 0) caml_failwith("sd_journal_prev failed");

	CAMLreturn(Val_unit);
}

value mlj_close() {
	CAMLparam0();
	sd_journal_close(jj);
	CAMLreturn(Val_unit);
}


value mlj_wait(value v_timeout_us) {
	CAMLparam1(v_timeout_us);
	int timeout_us = Unsigned_int_val(v_timeout_us);
	int n = sd_journal_wait(jj, timeout_us);
	if (n < 0) caml_failwith("sd_journal_wait failed");
	value ret = Val_true;
	CAMLreturn(Val_bool(n != SD_JOURNAL_NOP)); // true = new events
}

value mlj_read() {
	// List of fields to return in a tuple here is specified/checked in mlj_open()
	CAMLparam0();

	int n = sd_journal_next(jj);
	if (n == 0) caml_raise_end_of_file();
	else if (n < 0) caml_failwith("sd_journal_next failed");

	size_t msg_len;
	const void* msg;
	const char *delim_ptr, *val;
	CAMLlocal1(v_record);
	v_record = caml_alloc_tuple(field_count);
	for (int n_rec=0; n_rec < field_count; n_rec++) {
		// XXX: check if maybe it'd be more efficient to iterate over fields than multiple get_data()
		n = sd_journal_get_data(jj, fields[n_rec], &msg, &msg_len);
		if (n == -ENOENT) { n = 0; val = ""; }
		else if (n < 0) caml_failwith("sd_journal_get_data failed for one of the fields");
		else {
			delim_ptr = memchr(msg, '=', msg_len);
			if (!delim_ptr) caml_failwith("sd_journal_get_data returned msg without =");
			val = delim_ptr + 1;
			n = (const char*) msg + msg_len - (delim_ptr + 1); }
		Store_field(v_record, n_rec, caml_alloc_initialized_string(n, val)); }
	CAMLreturn(v_record);
}

value mlj_match(value v_match) {
	CAMLparam1(v_match);
	char *match = Bytes_val(v_match);
	uint match_len = caml_string_length(v_match);
	if ( match_len > INT_MAX ||
			sd_journal_add_match(jj, match, (int) match_len) < 0 )
		caml_failwith("sd_journal_add_match failed");
	CAMLreturn(Val_unit);
}

value mlj_match_or() {
	CAMLparam0();
	if (sd_journal_add_disjunction(jj) < 0)
		caml_failwith("sd_journal_add_disjunction failed");
	CAMLreturn(Val_unit);
}

value mlj_match_and() {
	CAMLparam0();
	if (sd_journal_add_conjunction(jj) < 0)
		caml_failwith("sd_journal_add_conjunction failed");
	CAMLreturn(Val_unit);
}

value mlj_match_flush() {
	CAMLparam0();
	sd_journal_flush_matches(jj);
	CAMLreturn(Val_unit);
}
