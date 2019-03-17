# $FreeBSD: releng/12.0/tests/sys/cddl/zfs/tests/write_dirs/Makefile 329867 2018-02-23 16:31:00Z asomers $

.include <src.opts.mk>

PACKAGE=tests
TESTSDIR=${TESTSBASE}/sys/cddl/zfs/tests/write_dirs
FILESDIR=${TESTSDIR}

ATF_TESTS_KSH93+=	write_dirs_test
TEST_METADATA+=		required_user="root"
TEST_METADATA+=		is_exclusive=true

${PACKAGE}FILES+=	write_dirs.cfg
${PACKAGE}FILES+=	write_dirs_002_pos.ksh
${PACKAGE}FILES+=	cleanup.ksh
${PACKAGE}FILES+=	setup.ksh
${PACKAGE}FILES+=	write_dirs_001_pos.ksh

.include <bsd.test.mk>
