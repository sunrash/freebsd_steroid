#include <sys/cdefs.h>
__FBSDID("$FreeBSD: releng/12.0/stand/common/load_elf32.c 261504 2014-02-05 04:39:03Z jhb $");

#define __ELF_WORD_SIZE 32
#define	_MACHINE_ELF_WANT_32BIT

#include "load_elf.c"
