#
# $FreeBSD: releng/12.0/usr.sbin/bsnmpd/modules/snmp_wlan/Makefile 335885 2018-07-03 08:44:40Z harti $
#

MOD=	wlan
SRCS=	wlan_snmp.c wlan_sys.c

XSYM=	begemotWlan

BMIBS=	BEGEMOT-WIRELESS-MIB.txt
MAN=	snmp_${MOD}.3
DEFS=	${MOD}_tree.def

.include <bsd.snmpmod.mk>
