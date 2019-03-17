# $FreeBSD: releng/12.0/lib/libiconv_modules/mapper_parallel/Makefile 312506 2017-01-20 04:53:26Z ngie $

.PATH: ${.CURDIR:H}/mapper_serial

SHLIB=	mapper_parallel
SRCS+=	citrus_mapper_serial.c
CFLAGS.gcc+= --param max-inline-insns-single=32

.include <bsd.lib.mk>
