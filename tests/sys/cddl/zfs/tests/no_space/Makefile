# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/tests/no_space/Makefile 329867 2018-02-23 16:31:00Z asomers $

.include <src.opts.mk>

PACKAGE=tests
TESTSDIR=${TESTSBASE}/sys/cddl/zfs/tests/no_space
FILESDIR=${TESTSDIR}

ATF_TESTS_KSH93+=	no_space_test
TEST_METADATA+=		required_user="root"
TEST_METADATA+=		is_exclusive=true

${PACKAGE}FILES+=	enospc.cfg
${PACKAGE}FILES+=	cleanup.ksh
${PACKAGE}FILES+=	setup.ksh
${PACKAGE}FILES+=	enospc_001_pos.ksh

.include <bsd.test.mk>
