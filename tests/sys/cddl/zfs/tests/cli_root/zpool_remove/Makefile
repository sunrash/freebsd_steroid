# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/tests/cli_root/zpool_remove/Makefile 329867 2018-02-23 16:31:00Z asomers $

.include <src.opts.mk>

PACKAGE=tests
TESTSDIR=${TESTSBASE}/sys/cddl/zfs/tests/cli_root/zpool_remove
FILESDIR=${TESTSDIR}

ATF_TESTS_KSH93+=	zpool_remove_test
TEST_METADATA+=		required_user="root"
TEST_METADATA+=		is_exclusive=true

${PACKAGE}FILES+=	zpool_remove_001_neg.ksh
${PACKAGE}FILES+=	setup.ksh
${PACKAGE}FILES+=	zpool_remove.cfg
${PACKAGE}FILES+=	zpool_remove_002_pos.ksh
${PACKAGE}FILES+=	cleanup.ksh
${PACKAGE}FILES+=	zpool_remove_003_pos.ksh

.include <bsd.test.mk>
