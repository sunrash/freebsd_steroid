# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/tests/nestedfs/Makefile 329867 2018-02-23 16:31:00Z asomers $

.include <src.opts.mk>

PACKAGE=tests
TESTSDIR=${TESTSBASE}/sys/cddl/zfs/tests/nestedfs
FILESDIR=${TESTSDIR}

ATF_TESTS_KSH93+=	nestedfs_test
TEST_METADATA+=		required_user="root"
TEST_METADATA+=		is_exclusive=true

${PACKAGE}FILES+=	nestedfs.cfg
${PACKAGE}FILES+=	setup.ksh
${PACKAGE}FILES+=	nestedfs_001_pos.ksh
${PACKAGE}FILES+=	cleanup.ksh

.include <bsd.test.mk>
