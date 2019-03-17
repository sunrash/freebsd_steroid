# $FreeBSD: releng/12.0/lib/libcasper/services/cap_pwd/tests/Makefile 327583 2018-01-05 09:31:41Z oshogbo $

.include <src.opts.mk>

TAP_TESTS_C=	pwd_test

.if ${MK_CASPER} != "no"
LIBADD+=	casper
LIBADD+=	cap_pwd
CFLAGS+=-DWITH_CASPER
.endif
LIBADD+=	nv

WARNS?=		3

.include <bsd.test.mk>
