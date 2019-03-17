/*-
 * Public domain.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: releng/12.0/lib/libc/amd64/string/bzero.c 340688 2018-11-20 18:14:30Z mjg $");

#include <string.h>

void
bzero(void *b, size_t len)
{

	memset(b, 0, len);
}
