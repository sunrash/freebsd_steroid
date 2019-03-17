# $FreeBSD: releng/12.0/usr.sbin/bsnmpd/modules/snmp_usm/Makefile 335885 2018-07-03 08:44:40Z harti $
#
# Author: Shteryana Shopova <syrinx@freebsd.org>

CONTRIB= ${SRCTOP}/contrib/bsnmp
.PATH: ${CONTRIB}/snmp_usm

MOD=	usm
SRCS=	usm_snmp.c
XSYM=	snmpUsmMIB usmNoAuthProtocol usmHMACMD5AuthProtocol \
	usmHMACSHAAuthProtocol usmNoPrivProtocol usmDESPrivProtocol \
	usmAesCfb128Protocol usmUserSecurityName

MAN=	snmp_usm.3

CFLAGS+= -I${CONTRIB}/lib -I${CONTRIB}/snmpd
CFLAGS+= -DHAVE_ERR_H -DHAVE_GETADDRINFO -DHAVE_STRLCPY -DHAVE_SYS_TREE_H

GENSNMPTREEFLAGS+= -I${CONTRIB}/lib

DEFS=	${MOD}_tree.def
BMIBS=

.include <bsd.snmpmod.mk>
