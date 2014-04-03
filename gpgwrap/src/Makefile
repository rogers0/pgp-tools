CC=${DIET} gcc -s
CFLAGS:=-Wall -O2 -fomit-frame-pointer
CPPFLAGS:=$(shell dpkg-buildflags --get CPPFLAGS)
LDFLAGS:=$(shell dpkg-buildflags --get LDFLAGS)
STRIP=strip -R .note -R .comment
RM=rm -f
TARGET=../bin/gpgwrap

.PHONY: all clean

all: ${TARGET}

${TARGET}: gpgwrap.c
	[ -d $(dir ${TARGET}) ] || mkdir $(dir ${TARGET})
	${CC} ${CPPFLAGS} ${CFLAGS} ${LDFLAGS} -o ${TARGET} gpgwrap.c
	${STRIP} ${TARGET} 2>/dev/null || true

clean:
	${RM} ${TARGET}
