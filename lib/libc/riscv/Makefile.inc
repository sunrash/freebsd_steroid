# $FreeBSD: releng/12.0/lib/libc/riscv/Makefile.inc 332792 2018-04-19 20:36:15Z brooks $
#
# Machine dependent definitions for the RISC-V architecture.
#

# Long double is quad precision
GDTOASRCS+=strtorQ.c
SRCS+=machdep_ldisQ.c
SYM_MAPS+=${LIBC_SRCTOP}/riscv/Symbol.map
