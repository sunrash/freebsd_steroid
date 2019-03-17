# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/tests/zvol/zvol_swap/Makefile 329867 2018-02-23 16:31:00Z asomers $

.include <src.opts.mk>

PACKAGE=tests
TESTSDIR=${TESTSBASE}/sys/cddl/zfs/tests/zvol/zvol_swap
FILESDIR=${TESTSDIR}

ATF_TESTS_KSH93+=	zvol_swap_test
TEST_METADATA+=		required_user="root"
TEST_METADATA+=		is_exclusive=true

${PACKAGE}FILES+=	zvol_swap_004_pos.ksh
${PACKAGE}FILES+=	setup.ksh
${PACKAGE}FILES+=	zvol_swap_005_pos.ksh
${PACKAGE}FILES+=	zvol_swap_001_pos.ksh
${PACKAGE}FILES+=	zvol_swap.cfg
${PACKAGE}FILES+=	zvol_swap_003_pos.ksh
${PACKAGE}FILES+=	cleanup.ksh
${PACKAGE}FILES+=	zvol_swap_006_pos.ksh
${PACKAGE}FILES+=	zvol_swap_002_pos.ksh

.include <bsd.test.mk>
