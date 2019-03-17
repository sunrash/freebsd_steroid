# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/tests/poolversion/Makefile 329867 2018-02-23 16:31:00Z asomers $

.include <src.opts.mk>

PACKAGE=tests
TESTSDIR=${TESTSBASE}/sys/cddl/zfs/tests/poolversion
FILESDIR=${TESTSDIR}

ATF_TESTS_KSH93+=	poolversion_test
TEST_METADATA+=		required_user="root"
TEST_METADATA+=		is_exclusive=true

${PACKAGE}FILES+=	poolversion_002_pos.ksh
${PACKAGE}FILES+=	poolversion_001_pos.ksh
${PACKAGE}FILES+=	cleanup.ksh
${PACKAGE}FILES+=	setup.ksh

.include <bsd.test.mk>
