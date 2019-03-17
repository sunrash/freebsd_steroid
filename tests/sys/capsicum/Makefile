# $FreeBSD: releng/12.0/tests/sys/capsicum/Makefile 333120 2018-04-30 17:31:06Z emaste $

TESTSDIR=	${TESTSBASE}/sys/capsicum

ATF_TESTS_C+=	bindat_connectat
ATF_TESTS_C+=	ioctls_test

CFLAGS.bindat_connectat.c+=	-I${SRCTOP}/tests

WARNS?=	6

.include <bsd.test.mk>
