# $FreeBSD: releng/12.0/tests/sys/netpfil/Makefile 332358 2018-04-10 12:45:34Z kp $

.include <src.opts.mk>

TESTSDIR=		${TESTSBASE}/sys/netpfil

.if ${MK_PF} != "no"
TESTS_SUBDIRS+=		pf
.endif

.include <bsd.test.mk>
