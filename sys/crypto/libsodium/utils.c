/* This file is in the public domain. */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: releng/12.0/sys/crypto/libsodium/utils.c 337938 2018-08-17 00:27:56Z cem $");
#include <sys/types.h>
#include <sys/systm.h>

#include <sodium/utils.h>

void
sodium_memzero(void *b, size_t n)
{
	explicit_bzero(b, n);
}
