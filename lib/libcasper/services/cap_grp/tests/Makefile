# $FreeBSD: releng/12.0/lib/libcasper/services/cap_grp/tests/Makefile 327583 2018-01-05 09:31:41Z oshogbo $

.include <src.opts.mk>

TAP_TESTS_C=	grp_test

.if ${MK_CASPER} != "no"
LIBADD+=	casper
LIBADD+=	cap_grp
CFLAGS+=-DWITH_CASPER
.endif
LIBADD+=	nv

WARNS?=		3

.include <bsd.test.mk>
