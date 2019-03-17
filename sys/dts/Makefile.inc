# $FreeBSD: releng/12.0/sys/dts/Makefile.inc 331499 2018-03-24 21:30:24Z manu $

SYSDIR?=${SRCTOP}/sys

test-dts:
.for dts in ${DTS}
	@env MACHINE=`basename ${.CURDIR}` ${SYSDIR}/tools/fdt/make_dtb.sh ${SYSDIR} ${dts} /tmp

test-dtso:
.for dtso in ${DTSO}
	@env MACHINE=`basename ${.CURDIR}` ${SYSDIR}/tools/fdt/make_dtbo.sh ${SYSDIR} ${dtso} /tmp

.endfor
