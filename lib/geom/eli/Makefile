# $FreeBSD: releng/12.0/lib/geom/eli/Makefile 314656 2017-03-04 11:33:01Z ngie $

PACKAGE=runtime
.PATH: ${.CURDIR:H:H}/misc ${SRCTOP}/sys/geom/eli ${SRCTOP}/sys/crypto/sha2

GEOM_CLASS=	eli
SRCS=	g_eli_crypto.c
SRCS+=	g_eli_hmac.c
SRCS+=	g_eli_key.c
SRCS+=	pkcs5v2.c
SRCS+=	sha256c.c
SRCS+=	sha512c.c

LIBADD=	md crypto

WARNS?=	3

CFLAGS+=-I${SRCTOP}/sys

.include <bsd.lib.mk>
