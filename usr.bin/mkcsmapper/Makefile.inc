# $FreeBSD: releng/12.0/usr.bin/mkcsmapper/Makefile.inc 315170 2017-03-12 18:58:44Z imp $

.include <bsd.compiler.mk>

SRCS+=	lex.l yacc.y
CFLAGS+= -I${.CURDIR} -I${SRCTOP}/usr.bin/mkcsmapper \
	 -I${SRCTOP}/lib/libc/iconv \
	 -I${SRCTOP}/lib/libiconv_modules/mapper_std
CFLAGS.gcc+= --param max-inline-insns-single=64
