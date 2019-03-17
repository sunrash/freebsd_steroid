/* $FreeBSD: releng/12.0/sbin/dhclient/tests/fake.c 329754 2018-02-21 21:13:08Z asomers $ */

#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>

#include "dhcpd.h"

extern jmp_buf env;

void
error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");

	longjmp(env, 1);
}

int
warning(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");

	/*
	 * The original warning() would return "ret" here. We do this to
	 * check warnings explicitely.
	 */
	longjmp(env, 1);
}

int
note(const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");

	return ret;
}

void
bootp(struct packet *packet)
{
}

void
dhcp(struct packet *packet)
{
}
