# $FreeBSD: releng/12.0/tools/tools/net80211/w00t/Makefile.inc 295981 2016-02-24 17:18:52Z bdrewery $

W00T=	../libw00t
# NB: we get crc32 from -lz
DPADD=	${W00T}/libw00t.a
LDFLAGS= -L${W00T}
LDADD=	-lw00t
LIBADD+= crypto z

BINDIR=	/usr/local/bin
CFLAGS=	-g -I${W00T}

MAN=
