# $FreeBSD: releng/12.0/sys/modules/geom/geom_raid/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/geom/raid

KMOD=	geom_raid
SRCS=	g_raid.c
SRCS+=	g_raid_ctl.c
SRCS+=	bus_if.h device_if.h
SRCS+=	g_raid_md_if.h g_raid_md_if.c
SRCS+=	g_raid_tr_if.h g_raid_tr_if.c

SRCS+=	md_ddf.c md_intel.c md_jmicron.c md_nvidia.c md_promise.c md_sii.c

SRCS+=	tr_concat.c tr_raid0.c tr_raid1.c tr_raid1e.c tr_raid5.c

.include <bsd.kmod.mk>
