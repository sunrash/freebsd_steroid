#include <sys/cdefs.h>
__FBSDID("$FreeBSD: releng/12.0/lib/msun/src/s_llround.c 144771 2005-04-08 00:52:27Z das $");

#define type		double
#define	roundit		round
#define dtype		long long
#define	DTYPE_MIN	LLONG_MIN
#define	DTYPE_MAX	LLONG_MAX
#define	fn		llround

#include "s_lround.c"
