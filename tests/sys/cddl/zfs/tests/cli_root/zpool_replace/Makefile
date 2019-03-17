# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/tests/cli_root/zpool_replace/Makefile 329867 2018-02-23 16:31:00Z asomers $

.include <src.opts.mk>

PACKAGE=tests
TESTSDIR=${TESTSBASE}/sys/cddl/zfs/tests/cli_root/zpool_replace
FILESDIR=${TESTSDIR}

ATF_TESTS_KSH93+=	zpool_replace_test
TEST_METADATA+=		required_user="root"
TEST_METADATA+=		is_exclusive=true

${PACKAGE}FILES+=	zpool_replace_001_neg.ksh
${PACKAGE}FILES+=	zpool_replace_002_neg.ksh
${PACKAGE}FILES+=	setup.ksh
${PACKAGE}FILES+=	cleanup.ksh
${PACKAGE}FILES+=	zpool_replace.cfg

.include <bsd.test.mk>
