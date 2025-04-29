all: scnpm

scnpm: scnpm.nim
	nim c -d:release -d:strip -d:lto_incremental --opt:size $<

clean:
	rm -f scnpm

.SUFFIXES: # to disable built-in rules for %.c and such
