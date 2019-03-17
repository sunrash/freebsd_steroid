# $FreeBSD: releng/12.0/usr.sbin/crunch/crunchgen/Makefile 270168 2014-08-19 15:04:32Z bdrewery $

PROG=	crunchgen
SRCS=	crunchgen.c crunched_skel.c
CLEANFILES+= crunched_skel.c

crunched_skel.c: crunched_main.c
	sh -e ${.CURDIR}/mkskel.sh ${.CURDIR}/crunched_main.c >crunched_skel.c

.include <bsd.prog.mk>
