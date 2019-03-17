# $FreeBSD: releng/12.0/sys/modules/i2c/controllers/Makefile 330304 2018-03-03 01:53:51Z rpokala $

SUBDIR = alpm amdpm amdsmb ichiic ichsmb intpm ismt nfsmb viapm lpbb pcf

.if ${MACHINE_ARCH} == "i386" || ${MACHINE_ARCH} == "amd64"
SUBDIR += imcsmb
.endif

.include <bsd.subdir.mk>
