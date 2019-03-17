# $FreeBSD: releng/12.0/cddl/sbin/Makefile 321912 2017-08-02 08:35:51Z ngie $

.include <src.opts.mk>

SUBDIR=	${_zfs} ${_zpool}

SUBDIR.${MK_TESTS}+= tests

.if ${MK_ZFS} != "no"
_zfs=	zfs
_zpool=	zpool
.endif

SUBDIR_PARALLEL=

.include <bsd.subdir.mk>
