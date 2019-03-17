# $FreeBSD: releng/12.0/usr.sbin/hyperv/tools/vss/Makefile 314659 2017-03-04 11:38:03Z ngie $
DIRDEPS = lib/libc

.include <bsd.own.mk>

HV_VSS_DAEMON_DISTDIR?= ${SRCTOP}/contrib/hyperv/tools
.PATH: ${HV_VSS_DAEMON_DISTDIR}

PROG= 	hv_vss_daemon
MAN= 	hv_vss_daemon.8

CFLAGS+=	-I${SRCTOP}/sys/dev/hyperv/utilities

.include <bsd.prog.mk>
