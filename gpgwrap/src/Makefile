CC=${DIET} gcc -s -Wall -O2 -fomit-frame-pointer
STRIP=strip -R .note -R .comment
RM=rm -f
TARGET=../bin/gpgwrap

.PHONY: all clean

all: ${TARGET}

${TARGET}: gpgwrap.c
	${CC} -o ${TARGET} gpgwrap.c
	${STRIP} ${TARGET} 2>/dev/null || true

clean:
	${RM} ${TARGET}
