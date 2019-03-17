/* $FreeBSD: releng/12.0/usr.bin/wall/ttymsg.h 332510 2018-04-15 08:34:16Z ed $ */

#define	TTYMSG_IOV_MAX	32

const char	*ttymsg(struct iovec *, int, const char *, int);
