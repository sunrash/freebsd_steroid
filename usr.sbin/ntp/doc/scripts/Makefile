# $FreeBSD: releng/12.0/usr.sbin/ntp/doc/scripts/Makefile 314472 2017-03-01 04:54:06Z ngie $

.include <src.opts.mk>

FILESDIR=	${SHAREDIR}/doc/ntp/scripts

.if ${MK_HTML} != "no"
FILES=	accopt.txt audio.txt authopt.txt clockopt.txt command.txt config.txt \
	confopt.txt external.txt footer.txt hand.txt install.txt manual.txt \
	misc.txt miscopt.txt monopt.txt refclock.txt special.txt style.css
.endif

.PATH: ${SRCTOP}/contrib/ntp/html/scripts

.include <bsd.prog.mk>
