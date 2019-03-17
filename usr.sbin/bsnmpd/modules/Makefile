# $FreeBSD: releng/12.0/usr.sbin/bsnmpd/modules/Makefile 317383 2017-04-24 21:21:49Z brooks $

.include <src.opts.mk>

.PATH: ${SRCTOP}/contrib/bsnmp/snmpd

SUBDIR=	\
	snmp_bridge \
	snmp_hostres \
	snmp_lm75 \
	snmp_mibII \
	snmp_target \
	snmp_usm \
	snmp_vacm \

.if ${MK_HAST} != "no"
SUBDIR+=snmp_hast
.endif

.if ${MK_PF} != "no"
SUBDIR+=snmp_pf
.endif

.if ${MK_NETGRAPH_SUPPORT} != "no"
SUBDIR+=snmp_netgraph
.endif

.if ${MK_WIRELESS} != "no"
SUBDIR+=snmp_wlan
.endif

INCS=	snmpmod.h
INCSDIR= ${INCLUDEDIR}/bsnmp

SUBDIR_TARGETS+=	smilint

.include <bsd.prog.mk>
