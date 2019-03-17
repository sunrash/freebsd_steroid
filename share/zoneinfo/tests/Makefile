# $FreeBSD: releng/12.0/share/zoneinfo/tests/Makefile 320703 2017-07-06 04:30:06Z ngie $

.include <src.opts.mk>

.PATH: ${SRCTOP}/contrib/tzdata

PACKAGE=	tests

FILESGROUPS+=	TESTFILES

.if ${MK_ZONEINFO_OLD_TIMEZONES_SUPPORT} != "no"
ATF_TESTS_SH+=	backward_test
TESTFILES+=	backward
.endif

TESTFILES+=	zoneinfo_common.sh
TESTFILESPACKAGE= ${PACKAGE}
TESTFILESDIR=	${TESTSDIR}

.include <bsd.test.mk>
