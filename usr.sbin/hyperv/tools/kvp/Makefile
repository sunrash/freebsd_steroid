# $FreeBSD: releng/12.0/usr.sbin/hyperv/tools/kvp/Makefile 314659 2017-03-04 11:38:03Z ngie $

.include <bsd.own.mk>

HV_KVP_DAEMON_DISTDIR?= ${SRCTOP}/contrib/hyperv/tools
.PATH: ${HV_KVP_DAEMON_DISTDIR}

PROG= 	hv_kvp_daemon
MAN= 	hv_kvp_daemon.8

CFLAGS+=	-I${SRCTOP}/sys/dev/hyperv/utilities

.include <bsd.prog.mk>
