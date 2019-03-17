# $FreeBSD: releng/12.0/tests/Makefile 322515 2017-08-14 19:21:37Z ngie $

PACKAGE= tests

TESTSDIR= ${TESTSBASE}

${PACKAGE}FILES+=		README

KYUAFILE= yes

SUBDIR+= etc
SUBDIR+= sys

SUBDIR_PARALLEL=

afterinstall: install-tests-local
install-tests-local: .PHONY
	${INSTALL_SYMLINK} ../local/tests ${DESTDIR}${TESTSDIR}/local

.include "Makefile.inc0"
.include <bsd.test.mk>
