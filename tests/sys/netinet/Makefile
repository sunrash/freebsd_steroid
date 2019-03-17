# $FreeBSD: releng/12.0/tests/sys/netinet/Makefile 338601 2018-09-11 21:14:07Z markj $

TESTSDIR=	${TESTSBASE}/sys/netinet
BINDIR=		${TESTSDIR}

ATF_TESTS_C=	reuseport_lb

ATF_TESTS_SH=	fibs_test

PROGS=	udp_dontroute tcp_user_cookie

MAN=

WARNS?=	6

.include <bsd.test.mk>
