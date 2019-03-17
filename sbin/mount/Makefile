#	@(#)Makefile	8.6 (Berkeley) 5/8/95
# $FreeBSD: releng/12.0/sbin/mount/Makefile 319079 2017-05-28 18:07:53Z trasz $

PACKAGE=runtime
PROG=	mount
SRCS=	mount.c mount_fs.c getmntopts.c vfslist.c
MAN=	mount.8
# We do NOT install the getmntopts.3 man page.

LIBADD=	util

.include <bsd.prog.mk>
