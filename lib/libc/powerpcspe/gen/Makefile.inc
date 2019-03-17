# $FreeBSD: releng/12.0/lib/libc/powerpcspe/gen/Makefile.inc 307799 2016-10-22 21:51:58Z jhibbits $

.include "${LIBC_SRCTOP}/powerpc/gen/Makefile.common"

SRCS += fabs.S flt_rounds.c fpgetmask.c fpgetround.c \
	fpgetsticky.c fpsetmask.c fpsetround.c \
	_setjmp.S setjmp.S sigsetjmp.S
