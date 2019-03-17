# $FreeBSD: releng/12.0/stand/uboot.mk 329190 2018-02-13 03:44:50Z jhibbits $

SRCS+=	main.c

.PATH:		${UBOOTSRC}/common

CFLAGS+=	-I${UBOOTSRC}/common

# U-Boot standalone support library
LIBUBOOT=	${BOOTOBJ}/uboot/lib/libuboot.a
CFLAGS+=	-I${UBOOTSRC}/lib
CFLAGS+=	-I${BOOTOBJ}/uboot/lib
.if ${MACHINE_CPUARCH} == "arm"
SRCS+=	metadata.c
.endif

.include "${BOOTSRC}/fdt.mk"

.if ${MK_FDT} == "yes"
LIBUBOOT_FDT=	${BOOTOBJ}/uboot/fdt/libuboot_fdt.a
.endif
