# $FreeBSD: releng/12.0/stand/fdt.mk 325689 2017-11-10 23:54:24Z imp $

.if ${MK_FDT} == "yes"
CFLAGS+=	-I${FDTSRC}
CFLAGS+=	-I${BOOTOBJ}/fdt
CFLAGS+=	-I${SYSDIR}/contrib/libfdt
CFLAGS+=	-DLOADER_FDT_SUPPORT
LIBFDT=		${BOOTOBJ}/fdt/libfdt.a
.endif
