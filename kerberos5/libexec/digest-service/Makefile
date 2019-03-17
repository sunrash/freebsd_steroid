# $FreeBSD: releng/12.0/kerberos5/libexec/digest-service/Makefile 287216 2015-08-27 17:16:18Z ume $

PROG=	digest-service
MAN=
CFLAGS+=	-I${KRB5DIR}/kdc \
		-I${KRB5DIR}/lib/asn1 \
		-I${KRB5DIR}/lib/krb5 \
		-I${KRB5DIR}/lib/ipc \
		-I${KRB5DIR}/lib/wind \
		-I${KRB5DIR}/lib/roken
LIBADD=	hdb kdc heimipcs krb5 roken asn1 crypto vers heimntlm
LDFLAGS=${LDAPLDFLAGS}

.include <bsd.prog.mk>

.PATH: ${KRB5DIR}/kdc
