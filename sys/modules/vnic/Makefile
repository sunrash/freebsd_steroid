# $FreeBSD: releng/12.0/sys/modules/vnic/Makefile 314651 2017-03-04 10:10:17Z ngie $

SYSDIR?=${SRCTOP}/sys
.include "${SYSDIR}/conf/kern.opts.mk"

CFLAGS+=	-DFDT

SUBDIR = mrmlbus thunder_mdio thunder_bgx vnicpf vnicvf

.include <bsd.subdir.mk>
