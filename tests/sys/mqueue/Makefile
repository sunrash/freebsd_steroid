# $FreeBSD: releng/12.0/tests/sys/mqueue/Makefile 306588 2016-10-02 17:02:59Z kib $

TESTSDIR=	${TESTSBASE}/sys/mqueue

ATF_TESTS_SH=	mqueue_test

BINDIR=		${TESTSDIR}

CFLAGS+=	-I${SRCTOP}/tests

PROGS+=		mqtest1
PROGS+=		mqtest2
PROGS+=		mqtest3
PROGS+=		mqtest4
PROGS+=		mqtest5

LIBADD+=	rt

WARNS?=		6

.include <bsd.test.mk>
