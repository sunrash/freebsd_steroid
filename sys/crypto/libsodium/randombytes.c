/* This file is in the public domain. */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: releng/12.0/sys/crypto/libsodium/randombytes.c 337938 2018-08-17 00:27:56Z cem $");
#include <sys/libkern.h>

#include <sodium/randombytes.h>

void
randombytes_buf(void *buf, size_t size)
{
	arc4random_buf(buf, size);
}
