# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/tests/cli_root/zpool_status/Makefile 329867 2018-02-23 16:31:00Z asomers $

.include <src.opts.mk>

PACKAGE=tests
TESTSDIR=${TESTSBASE}/sys/cddl/zfs/tests/cli_root/zpool_status
FILESDIR=${TESTSDIR}

ATF_TESTS_KSH93+=	zpool_status_test
TEST_METADATA+=		required_user="root"
TEST_METADATA+=		is_exclusive=true

${PACKAGE}FILES+=	zpool_status.cfg
${PACKAGE}FILES+=	zpool_status_001_pos.ksh
${PACKAGE}FILES+=	setup.ksh
${PACKAGE}FILES+=	cleanup.ksh
${PACKAGE}FILES+=	zpool_status_002_pos.ksh

.include <bsd.test.mk>
