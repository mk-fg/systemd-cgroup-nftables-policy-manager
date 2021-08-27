LDLIBS = -lsystemd

all: scnpm

scnpm: scnpm.ml scnpm.ml.c
	ocamlopt -o $@ -O2 unix.cmxa str.cmxa -cclib $(LDLIBS) $^
	strip $@

clean:
	rm -f scnpm scnpm.cmi scnpm.cmx scnpm.ml.o scnpm.o

.SUFFIXES: # to disable built-in rules for %.c and such
