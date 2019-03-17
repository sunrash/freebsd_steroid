# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/tests/pool_names/Makefile 329867 2018-02-23 16:31:00Z asomers $

.include <src.opts.mk>

PACKAGE=tests
TESTSDIR=${TESTSBASE}/sys/cddl/zfs/tests/pool_names
FILESDIR=${TESTSDIR}

ATF_TESTS_KSH93+=	pool_names_test
TEST_METADATA+=		required_user="root"
TEST_METADATA+=		is_exclusive=true

${PACKAGE}FILES+=	pool_names_002_neg.ksh
${PACKAGE}FILES+=	pool_names.cfg
${PACKAGE}FILES+=	pool_names_001_pos.ksh

.include <bsd.test.mk>
