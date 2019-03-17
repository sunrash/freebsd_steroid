# $FreeBSD: releng/12.0/kerberos5/usr.bin/verify_krb5_conf/Makefile 336151 2018-07-10 00:26:13Z cy $

PROG=	verify_krb5_conf
MAN=	verify_krb5_conf.8
CFLAGS+=-I${KRB5DIR}/lib/asn1 -I${KRB5DIR}/lib/krb5 -I${KRB5DIR}/lib/roken
LIBADD=	krb5 roken vers

.include <bsd.prog.mk>

.PATH: ${KRB5DIR}/lib/krb5
