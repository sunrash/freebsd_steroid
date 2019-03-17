# From:	@(#)Makefile	8.3 (Berkeley) 4/2/94
# $FreeBSD: releng/12.0/usr.bin/passwd/Makefile 314833 2017-03-07 05:10:38Z rgrimes $

.include <src.opts.mk>

PROG	 = passwd
BINOWN	 = root
BINMODE	 = 4555
PRECIOUSPROG=
LIBADD   = pam
.if ${MK_NIS} != "no"
SYMLINKS = passwd ${BINDIR}/yppasswd
MLINKS	 = passwd.1 yppasswd.1
.endif

beforeinstall:
.for i in passwd yppasswd
	[ ! -e ${DESTDIR}${BINDIR}/$i ] || \
		chflags noschg ${DESTDIR}${BINDIR}/$i || true
.endfor

.include <bsd.prog.mk>
