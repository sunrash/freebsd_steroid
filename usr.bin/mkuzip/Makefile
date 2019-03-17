# $FreeBSD: releng/12.0/usr.bin/mkuzip/Makefile 320048 2017-06-17 02:58:31Z sobomax $

PROG=	mkuzip
MAN=	mkuzip.8
SRCS=	mkuzip.c mkuz_blockcache.c mkuz_lzma.c mkuz_zlib.c mkuz_conveyor.c \
	    mkuz_blk.c mkuz_fqueue.c mkuz_time.c mkuz_insize.c

#CFLAGS+=	-DMKUZ_DEBUG

LIBADD=	z md lzma pthread

.include <bsd.prog.mk>
