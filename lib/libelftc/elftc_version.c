/* $FreeBSD: releng/12.0/lib/libelftc/elftc_version.c 333063 2018-04-27 13:59:24Z emaste $ */

#include <sys/types.h>
#include <libelftc.h>

const char *
elftc_version(void)
{
	return "elftoolchain r3614M";
}
