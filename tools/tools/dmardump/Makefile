# $FreeBSD: releng/12.0/tools/tools/dmardump/Makefile 303887 2016-08-09 19:06:05Z jhb $

PROG=	dmardump
SRCS=	dmardump.c
MAN=

# Pull in bits from acpidump
ACPIDUMP=${.CURDIR}/../../../usr.sbin/acpi/acpidump
.PATH:	${ACPIDUMP}
SRCS+=	acpi_user.c acpi.c
CFLAGS+= -I${ACPIDUMP}

CFLAGS+= -I${.CURDIR}/../../../sys

.include <bsd.prog.mk>
