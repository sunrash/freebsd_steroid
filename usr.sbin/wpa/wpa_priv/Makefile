# $FreeBSD: releng/12.0/usr.sbin/wpa/wpa_priv/Makefile 314541 2017-03-02 05:04:45Z ngie $

.include "../Makefile.inc"

.PATH.c:${WPA_SUPPLICANT_DISTDIR} \
	${WPA_DISTDIR}/src/drivers

PROG=	wpa_priv
SRCS=	drivers.c os_unix.c eloop.c common.c wpa_debug.c wpabuf.c wpa_priv.c \
	driver_common.c l2_packet_freebsd.c

LIBADD=	pcap

.include "../Makefile.crypto"

.include <bsd.prog.mk>
