/*-
 * Test 0083:	Check that the last instruction is BPF_RET.
 *
 * $FreeBSD: releng/12.0/tools/regression/bpf/bpf_filter/tests/test0083.h 307708 2016-10-21 06:56:30Z jkim $
 */

/* BPF program */
static struct bpf_insn	pc[] = {
	BPF_STMT(BPF_LD|BPF_IMM, 0),
};

/* Packet */
static u_char	pkt[] = {
	0x00,
};

/* Packet length seen on wire */
static u_int	wirelen =	sizeof(pkt);

/* Packet length passed on buffer */
static u_int	buflen =	sizeof(pkt);

/* Invalid instruction */
static int	invalid =	1;

/* Expected return value */
static u_int	expect =	0;

/* Expected signal */
#ifdef BPF_JIT_COMPILER
static int	expect_signal =	SIGSEGV;
#else
static int	expect_signal =	SIGABRT;
#endif
