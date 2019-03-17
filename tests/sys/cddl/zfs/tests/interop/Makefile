# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/tests/interop/Makefile 329867 2018-02-23 16:31:00Z asomers $

.include <src.opts.mk>

PACKAGE=tests
TESTSDIR=${TESTSBASE}/sys/cddl/zfs/tests/interop
FILESDIR=${TESTSDIR}

ATF_TESTS_KSH93+=	interop_test
TEST_METADATA+=		required_user="root"
TEST_METADATA+=		is_exclusive=true

${PACKAGE}FILES+=	cleanup.ksh
${PACKAGE}FILES+=	interop_001_pos.ksh
${PACKAGE}FILES+=	setup.ksh
${PACKAGE}FILES+=	interop.cfg

.include <bsd.test.mk>
