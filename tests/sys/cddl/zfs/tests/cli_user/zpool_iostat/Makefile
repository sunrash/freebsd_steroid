# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/tests/cli_user/zpool_iostat/Makefile 329867 2018-02-23 16:31:00Z asomers $

.include <src.opts.mk>

PACKAGE=tests
TESTSDIR=${TESTSBASE}/sys/cddl/zfs/tests/cli_user/zpool_iostat
FILESDIR=${TESTSDIR}

ATF_TESTS_KSH93+=	zpool_iostat_test
TEST_METADATA+=		is_exclusive=true

${PACKAGE}FILES+=	cleanup.ksh
${PACKAGE}FILES+=	zpool_iostat.cfg
${PACKAGE}FILES+=	zpool_iostat_003_neg.ksh
${PACKAGE}FILES+=	zpool_iostat_002_pos.ksh
${PACKAGE}FILES+=	setup.ksh
${PACKAGE}FILES+=	zpool_iostat_001_neg.ksh

.include <bsd.test.mk>
