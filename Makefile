CFLAGS	+= -g -O3 -std=c99 -D_DEFAULT_SOURCE -pedantic -Wall -Wextra -Wno-variadic-macros -Wmissing-declarations -Wdeclaration-after-statement -Wformat=2 -Werror
LDFLAGS	+= -g
LDLIBS	+= -lasound

.PHONY:	clean all docs

all:	streamer

streamer:	streamer.o

docs:	Doxyfile *.md *.c
	mkdir -p doc
	doxygen $<

clean:
	rm -rf doc
	rm -f streamer streamer.o
