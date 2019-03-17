# $FreeBSD: releng/12.0/sys/modules/bios/Makefile 309491 2016-12-03 17:54:08Z rpokala $
#

SUBDIR=	smbios vpd

.if ${MACHINE_ARCH} == "i386"
SUBDIR+=	smapi
.endif

.include <bsd.subdir.mk>
