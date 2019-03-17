# $FreeBSD: releng/12.0/sys/modules/bhnd/siba_bhndb/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH:	${SRCTOP}/sys/dev/bhnd/siba

KMOD=	siba_bhndb
SRCS=	siba_bhndb.c

SRCS+=	bhnd_bus_if.h bhnd_erom_if.h
SRCS+=	bhndb_bus_if.h bhndb_if.h
SRCS+=	device_if.h bus_if.h

.include <bsd.kmod.mk>
