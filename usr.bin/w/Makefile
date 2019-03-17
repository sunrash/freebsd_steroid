#	@(#)Makefile	8.1 (Berkeley) 6/6/93
# $FreeBSD: releng/12.0/usr.bin/w/Makefile 315170 2017-03-12 18:58:44Z imp $

PROG=	w
SRCS=	fmt.c pr_time.c proc_compare.c w.c
MAN=	w.1 uptime.1
LIBADD=	kvm sbuf xo util
LINKS=	${BINDIR}/w ${BINDIR}/uptime

.PATH: ${SRCTOP}/bin/ps

.include <bsd.prog.mk>
