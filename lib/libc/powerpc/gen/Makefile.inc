# $FreeBSD: releng/12.0/lib/libc/powerpc/gen/Makefile.inc 307892 2016-10-25 01:32:35Z jhibbits $

.include "${LIBC_SRCTOP}/powerpc/gen/Makefile.common"

SRCS += fabs.S flt_rounds.c fpgetmask.c fpgetround.c \
	fpgetsticky.c fpsetmask.c fpsetround.c \
	_setjmp.S setjmp.S sigsetjmp.S
