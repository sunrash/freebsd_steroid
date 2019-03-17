# $FreeBSD: releng/12.0/stand/i386/btx/btxldr/Makefile 328769 2018-02-02 06:32:26Z imp $

.include <bsd.init.mk>

PROG=	btxldr
INTERNALPROG=
SRCS=	btxldr.S

CFLAGS+=-DLOADER_ADDRESS=${LOADER_ADDRESS}
CFLAGS+=-I${BOOTSRC}/i386/common

.if defined(BTXLDR_VERBOSE)
CFLAGS+=-DBTXLDR_VERBOSE
.endif

ORG=${LOADER_ADDRESS}
LDFLAGS+=${LDFLAGS_BIN}

.include <bsd.prog.mk>

# XXX: clang integrated-as doesn't grok .codeNN directives yet
CFLAGS.btxldr.S=	${CLANG_NO_IAS}
