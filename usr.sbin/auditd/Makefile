#
# $FreeBSD: releng/12.0/usr.sbin/auditd/Makefile 337622 2018-08-11 13:23:09Z brd $
#

OPENBSMDIR=${SRCTOP}/contrib/openbsm
.PATH: ${OPENBSMDIR}/bin/auditd

CFLAGS+=	-I${OPENBSMDIR}

OPENBSMETCDIR=  ${OPENBSMDIR}/etc
CONFS=  ${OPENBSMETCDIR}/audit_class
CONFSMODE_${OPENBSMETCDIR}/audit_class= 444
CONFS+= ${OPENBSMETCDIR}/audit_control
CONFSMODE_${OPENBSMETCDIR}/audit_control=       600
CONFS+= ${OPENBSMETCDIR}/audit_event
CONFSMODE_${OPENBSMETCDIR}/audit_event= 444
CONFS+= ${OPENBSMETCDIR}/audit_user
CONFSMODE_${OPENBSMETCDIR}/audit_user=  600
CONFS+= ${OPENBSMETCDIR}/audit_warn
CONFSMODE_${OPENBSMETCDIR}/audit_warn=  500
CONFSDIR=       /etc/security
PROG=	auditd
SRCS=	auditd.c audit_warn.c auditd_fbsd.c
MAN=	auditd.8

LIBADD=	auditd bsm

WARNS?=	3

.include <bsd.prog.mk>
