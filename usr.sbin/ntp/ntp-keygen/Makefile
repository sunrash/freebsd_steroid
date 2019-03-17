# $FreeBSD: releng/12.0/usr.sbin/ntp/ntp-keygen/Makefile 330104 2018-02-28 07:59:55Z delphij $

MAN=

.include <src.opts.mk>

.PATH:	${SRCTOP}/contrib/ntp/util \
	${SRCTOP}/contrib/ntp/ntpd

PROG=	ntp-keygen
SRCS=	ntp-keygen.c ntp-keygen-opts.c

CFLAGS+= -I${SRCTOP}/contrib/ntp/include \
	-I${SRCTOP}/contrib/ntp/include \
	-I${SRCTOP}/contrib/ntp/lib/isc/include \
	-I${SRCTOP}/contrib/ntp/lib/isc/unix/include \
	-I${SRCTOP}/contrib/ntp/lib/isc/pthreads/include \
	-I${SRCTOP}/contrib/ntp/lib/isc/${NTP_ATOMIC}/include \
	-I${SRCTOP}/contrib/ntp/sntp/libopts \
	-I${.CURDIR}/lib/libc/${MACHINE_ARCH} \
	-I${.CURDIR:H}

LIBADD+=	m ntp opts pthread

.if ${MK_OPENSSL} != "no"
LIBADD+=	crypto
.endif

.include <bsd.prog.mk>
