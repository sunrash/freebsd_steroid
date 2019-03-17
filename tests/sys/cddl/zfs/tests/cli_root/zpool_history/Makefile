# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/tests/cli_root/zpool_history/Makefile 329867 2018-02-23 16:31:00Z asomers $

.include <src.opts.mk>

PACKAGE=tests
TESTSDIR=${TESTSBASE}/sys/cddl/zfs/tests/cli_root/zpool_history
FILESDIR=${TESTSDIR}

ATF_TESTS_KSH93+=	zpool_history_test
TEST_METADATA+=		required_user="root"
TEST_METADATA+=		is_exclusive=true

${PACKAGE}FILES+=	setup.ksh
${PACKAGE}FILES+=	cleanup.ksh
${PACKAGE}FILES+=	zpool_history_001_neg.ksh
${PACKAGE}FILES+=	zpool_history_002_pos.ksh
${PACKAGE}FILES+=	zpool_history.cfg

.include <bsd.test.mk>
