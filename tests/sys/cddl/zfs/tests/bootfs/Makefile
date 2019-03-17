# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/tests/bootfs/Makefile 329867 2018-02-23 16:31:00Z asomers $

.include <src.opts.mk>

PACKAGE=tests
TESTSDIR=${TESTSBASE}/sys/cddl/zfs/tests/bootfs
FILESDIR=${TESTSDIR}

${PACKAGE}FILES+=	bootfs.cfg
${PACKAGE}FILES+=	bootfs_001_pos.ksh
${PACKAGE}FILES+=	bootfs_002_neg.ksh
${PACKAGE}FILES+=	bootfs_003_pos.ksh
${PACKAGE}FILES+=	bootfs_004_neg.ksh
${PACKAGE}FILES+=	bootfs_005_neg.ksh
${PACKAGE}FILES+=	bootfs_006_pos.ksh
${PACKAGE}FILES+=	bootfs_007_pos.ksh
${PACKAGE}FILES+=	bootfs_008_neg.ksh
${PACKAGE}FILES+=	bootfs_009_neg.ksh

ATF_TESTS_KSH93+=	bootfs_test
TEST_METADATA+=		required_user="root"
TEST_METADATA+=		is_exclusive=true

.include <bsd.test.mk>
