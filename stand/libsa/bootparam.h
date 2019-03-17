/*	$NetBSD: bootparam.h,v 1.3 1998/01/05 19:19:41 perry Exp $	*/
/*	$FreeBSD: releng/12.0/stand/libsa/bootparam.h 324551 2017-10-12 14:56:28Z imp $ */

int bp_whoami(int sock);
int bp_getfile(int sock, char *key, struct in_addr *addrp, char *path);

