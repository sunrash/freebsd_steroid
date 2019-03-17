/*
 * Written by J.T. Conklin <jtc@netbsd.org>.
 * Public domain.
 */

#include <machine/asm.h>
__FBSDID("$FreeBSD: releng/12.0/lib/msun/i387/e_fmodf.S 305385 2016-09-04 15:08:14Z bde $")

ENTRY(fmodf)
	flds	8(%esp)
	flds	4(%esp)
1:	fprem
	fstsw	%ax
	sahf
	jp	1b
	fstp	%st(1)
	ret
END(fmodf)

	.section .note.GNU-stack,"",%progbits
