# $FreeBSD: releng/12.0/stand/efi/fdt/Makefile 328769 2018-02-02 06:32:26Z imp $

.include <bsd.init.mk>

.PATH: ${LDRSRC}

LIB=		efi_fdt
WARNS?=		6

SRCS=		efi_fdt.c

# EFI library headers
CFLAGS+=	-I${EFISRC}/include
CFLAGS+=	-I${EFISRC}/include/${MACHINE}

# libfdt headers
CFLAGS+=	-I${FDTSRC}

# Pick up the bootstrap header for some interface items
CFLAGS+=	-I${LDRSRC}

.include <bsd.lib.mk>
