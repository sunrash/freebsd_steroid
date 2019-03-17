/*
 * Stub arm64 vdso linker script.
 * LINUXTODO: update along with VDSO implementation
 *
 * $FreeBSD: releng/12.0/sys/arm64/linux/linux_vdso.lds.s 335775 2018-06-28 20:36:21Z emaste $
 */

SECTIONS
{
	. = . + SIZEOF_HEADERS;
	.text		: { *(.text*) }
	.rodata		: { *(.rodata*) }
	.hash		: { *(.hash) }
	.gnu.hash	: { *(.gnu.hash) }
	.dynsym		: { *(.dynsym) }
	.dynstr		: { *(.dynstr) }
	.gnu.version	: { *(.gnu.version) }
	.gnu.version_d	: { *(.gnu.version_d) }
	.gnu.version_r	: { *(.gnu.version_r) }
	.data		: { *(.data*) }
	.dynamic	: { *(.dynamic) }
}
