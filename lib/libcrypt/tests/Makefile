# $FreeBSD: releng/12.0/lib/libcrypt/tests/Makefile 315035 2017-03-11 00:07:04Z asomers $

ATF_TESTS_C+= crypt_tests

NETBSD_ATF_TESTS_C+= crypt_test

WARNS?=		6
CFLAGS+= -I${.CURDIR:H}
LIBADD=	crypt

.include <netbsd-tests.test.mk>

.include <bsd.test.mk>
