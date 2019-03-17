# $FreeBSD: releng/12.0/usr.sbin/unbound/checkconf/Makefile 333573 2018-05-12 17:10:36Z des $

# Vendor sources and generated files
LDNSDIR= ${SRCTOP}/contrib/ldns
UNBOUNDDIR= ${SRCTOP}/contrib/unbound

.PATH: ${UNBOUNDDIR} ${UNBOUNDDIR}/smallapp ${UNBOUNDDIR}/util ${UNBOUNDDIR}/doc

PROG=	local-unbound-checkconf
SRCS=	ub_event.c unbound-checkconf.c worker_cb.c
CFLAGS+=	-I${UNBOUNDDIR} -I${LDNSDIR}
LIBADD=	unbound pthread
MAN=	local-unbound-checkconf.8

.include <bsd.prog.mk>
