# $FreeBSD: releng/12.0/kerberos5/usr.bin/string2key/Makefile 275022 2014-11-25 09:57:42Z bapt $

PROG=	string2key
MAN=	string2key.8
CFLAGS+=	-I${KRB5DIR}/kdc \
		-I${KRB5DIR}/lib/asn1 \
		-I${KRB5DIR}/lib/krb5 \
		-I${KRB5DIR}/lib/roken \
		-I${KRB5DIR}/lib/windc
LIBADD=	krb5 roken crypto vers

.include <bsd.prog.mk>

.PATH: ${KRB5DIR}/kdc
