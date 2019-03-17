# $FreeBSD: releng/12.0/libexec/rtld-elf/tests/Makefile 315040 2017-03-11 00:10:40Z asomers $

SUBDIR+=	libpythagoras target

SUBDIR_DEPEND_target=	libpythagoras
ATF_TESTS_C=	ld_library_pathfds
WARNS?=		3

.include <bsd.test.mk>
