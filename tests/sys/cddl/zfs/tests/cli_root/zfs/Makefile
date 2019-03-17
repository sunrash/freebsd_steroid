# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/tests/cli_root/zfs/Makefile 329867 2018-02-23 16:31:00Z asomers $

.include <src.opts.mk>

PACKAGE=tests
TESTSDIR=${TESTSBASE}/sys/cddl/zfs/tests/cli_root/zfs
FILESDIR=${TESTSDIR}

ATF_TESTS_KSH93+=	zfs_test
TEST_METADATA+=		required_user="root"
TEST_METADATA+=		is_exclusive=true

${PACKAGE}FILES+=	zfs_malformed.cfg
${PACKAGE}FILES+=	zfs_001_neg.ksh
${PACKAGE}FILES+=	cleanup.ksh
${PACKAGE}FILES+=	setup.ksh
${PACKAGE}FILES+=	zfs_003_neg.ksh
${PACKAGE}FILES+=	zfs_002_pos.ksh

.include <bsd.test.mk>
