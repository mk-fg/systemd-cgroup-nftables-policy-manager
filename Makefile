all: scnpm

scnpm: scnpm.nim
	nim c -d:release --opt:size $<
	strip $@

clean:
	rm -f scnpm

.SUFFIXES: # to disable built-in rules for %.c and such
