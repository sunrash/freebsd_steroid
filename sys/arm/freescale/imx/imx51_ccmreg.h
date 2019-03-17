/*	$NetBSD: imx51_ccmreg.h,v 1.1 2012/04/17 09:33:31 bsh Exp $	*/
/*-
 * SPDX-License-Identifier: BSD-2-Clause AND BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2011, 2012  Genetec Corporation.  All rights reserved.
 * Written by Hashimoto Kenichi for Genetec Corporation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY GENETEC CORPORATION ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL GENETEC CORPORATION
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*-
 * Copyright (c) 2012, 2013 The FreeBSD Foundation
 * All rights reserved.
 *
 * Portions of this software were developed by Oleksandr Rybalko
 * under sponsorship from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.	Redistributions of source code must retain the above copyright
 *	notice, this list of conditions and the following disclaimer.
 * 2.	Redistributions in binary form must reproduce the above copyright
 *	notice, this list of conditions and the following disclaimer in the
 *	documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: releng/12.0/sys/arm/freescale/imx/imx51_ccmreg.h 326258 2017-11-27 15:04:10Z pfg $
 */

#ifndef	_IMX51_CCMREG_H
#define	_IMX51_CCMREG_H

#include <sys/cdefs.h>

/* register offset address */

#define	CCMC_BASE	0x73fd4000
#define	CCMC_CCR	0x0000
#define		CCR_FPM_MULT			0x00001000
#define	CCMC_CCDR	0x0004
#define	CCMC_CSR	0x0008
#define	CCMC_CCSR	0x000c
#define		CCSR_LP_APM			0x00000200
#define		CCSR_STEP_SEL_SHIFT		7
#define		CCSR_STEP_SEL_MASK		0x00000180
#define		CCSR_PLL2_DIV_PODF_SHIFT	5
#define		CCSR_PLL2_DIV_PODF_MASK		0x00000060
#define		CCSR_PLL3_DIV_PODF_SHIFT	3
#define		CCSR_PLL3_DIV_PODF_MASK		0x00000030
#define		CCSR_PLL1_SW_CLK_SEL		0x00000004
#define		CCSR_PLL2_SW_CLK_SEL		0x00000002
#define		CCSR_PLL3_SW_CLK_SEL		0x00000001
#define	CCMC_CACRR	0x0010
#define	CCMC_CBCDR	0x0014
#define		CBCDR_DDR_HIGH_FREQ_CLK_SEL	0x40000000
#define		CBCDR_DDR_CLK_PODF_SHIFT	27
#define		CBCDR_DDR_CLK_PODF_MASK		0x38000000
#define		CBCDR_EMI_CLK_SEL		0x04000000
#define		CBCDR_PERIPH_CLK_SEL		0x02000000
#define		CBCDR_EMI_SLOW_PODF_SHIFT	22
#define		CBCDR_EMI_SLOW_PODF_MASK	0x01c00000
#define		CBCDR_AXI_B_PODF_SHIFT		19
#define		CBCDR_AXI_B_PODF_MASK		0x00380000
#define		CBCDR_AXI_A_PODF_SHIFT		16
#define		CBCDR_AXI_A_PODF_MASK		0x1fff0000
#define		CBCDR_NFC_PODF_SHIFT		13
#define		CBCDR_NFC_PODF_MASK		0x00018000
#define		CBCDR_AHB_PODF_SHIFT		10
#define		CBCDR_AHB_PODF_MASK		0x00001c00
#define		CBCDR_IPG_PODF_SHIFT		8
#define		CBCDR_IPG_PODF_MASK		0x00000300
#define		CBCDR_PERCLK_PRED1_SHIFT	6
#define		CBCDR_PERCLK_PRED1_MASK		0x000000c0
#define		CBCDR_PERCLK_PRED2_SHIFT	3
#define		CBCDR_PERCLK_PRED2_MASK		0x00000038
#define		CBCDR_PERCLK_PODF_SHIFT		0
#define		CBCDR_PERCLK_PODF_MASK 		0x00000007
#define	CCMC_CBCMR	0x0018
#define		CBCMR_PERIPH_APM_SEL_SHIFT	12
#define		CBCMR_PERIPH_APM_SEL_MASK	0x00003000
#define		CBCMR_IPU_HSP_CLK_SEL_SHIFT	6
#define		CBCMR_IPU_HSP_CLK_SEL_MASK	0x000000c0
#define		CBCMR_PERCLK_LP_APM_SEL		0x00000002
#define		CBCMR_PERCLK_IPG_SEL		0x00000001
#define	CCMC_CSCMR1	0x001c
#define		CSCMR1_UART_CLK_SEL_SHIFT	24
#define		CSCMR1_UART_CLK_SEL_MASK	0x03000000
#define		CSCMR1_USBPHY_CLK_SEL_SHIFT	26
#define		CSCMR1_USBPHY_CLK_SEL_MASK	0x04000000
#define		CSCMR1_USBOH3_CLK_SEL_SHIFT	22
#define		CSCMR1_USBOH3_CLK_SEL_MASK	0x00c00000
#define	CCMC_CSCMR2	0x0020
#define	CCMC_CSCDR1	0x0024
#define		CSCDR1_UART_CLK_PRED_SHIFT	3
#define		CSCDR1_UART_CLK_PRED_MASK	0x00000038
#define		CSCDR1_UART_CLK_PODF_SHIFT	0
#define		CSCDR1_UART_CLK_PODF_MASK	0x00000007
#define		CSCDR1_USBOH3_CLK_PRED_SHIFT	8
#define		CSCDR1_USBOH3_CLK_PRED_MASK	0x00000700
#define		CSCDR1_USBOH3_CLK_PODF_SHIFT	6
#define		CSCDR1_USBOH3_CLK_PODF_MASK	0x000000c0
#define	CCMC_CS1CDR	0x0028
#define	CCMC_CS2CDR	0x002c
#define	CCMC_CDCDR	0x0030
#define	CCMC_CSCDR2	0x0038
#define	CCMC_CSCDR3	0x003c
#define	CCMC_CSCDR4	0x0040
#define	CCMC_CWDR	0x0044
#define	CCMC_CDHIPR	0x0048
#define	CCMC_CDCR	0x004c
#define		CDCR_PERIPH_CLK_DVFS_PODF_SHIFT	0
#define		CDCR_PERIPH_CLK_DVFS_PODF_MASK 	0x00000003
#define	CCMC_CTOR	0x0050
#define	CCMC_CLPCR	0x0054
#define	CCMC_CISR	0x0058
#define	CCMC_CIMR	0x005c
#define	CCMC_CCOSR	0x0060
#define	CCMC_CGPR	0x0064
#define	CCMC_CCGR(n)	(0x0068 + (n) * 4)
#define	CCMC_CMEOR	0x0084

#define	CCMC_SIZE	0x88

/* CCGR Clock Gate Register */

#define	CCMR_CCGR_NSOURCE	16
#define	CCMR_CCGR_NGROUPS	7
#define	CCMR_CCGR_MODULE(clk)	((clk) / CCMR_CCGR_NSOURCE)
#define	__CCGR_NUM(a, b)	((a) * 16 + (b))

#define	CCGR_ARM_BUS_CLK		__CCGR_NUM(0, 0)
#define	CCGR_ARM_AXI_CLK		__CCGR_NUM(0, 1)
#define	CCGR_ARM_DEBUG_CLK		__CCGR_NUM(0, 2)
#define	CCGR_TZIC_CLK			__CCGR_NUM(0, 3)
#define	CCGR_DAP_CLK			__CCGR_NUM(0, 4)
#define	CCGR_TPIU_CLK			__CCGR_NUM(0, 5)
#define	CCGR_CTI2_CLK			__CCGR_NUM(0, 6)
#define	CCGR_CTI3_CLK			__CCGR_NUM(0, 7)
#define	CCGR_AHBMUX1_CLK		__CCGR_NUM(0, 8)
#define	CCGR_AHBMUX2_CLK		__CCGR_NUM(0, 9)
#define	CCGR_ROMCP_CLK			__CCGR_NUM(0, 10)
#define	CCGR_ROM_CLK			__CCGR_NUM(0, 11)
#define	CCGR_AIPS_TZ1_CLK		__CCGR_NUM(0, 12)
#define	CCGR_AIPS_TZ2_CLK		__CCGR_NUM(0, 13)
#define	CCGR_AHB_MAX_CLK		__CCGR_NUM(0, 14)
#define	CCGR_IIM_CLK			__CCGR_NUM(0, 15)
#define	CCGR_TMAX1_CLK			__CCGR_NUM(1, 0)
#define	CCGR_TMAX2_CLK			__CCGR_NUM(1, 1)
#define	CCGR_TMAX3_CLK			__CCGR_NUM(1, 2)
#define	CCGR_UART1_CLK			__CCGR_NUM(1, 3)
#define	CCGR_UART1_SERIAL_CLK		__CCGR_NUM(1, 4)
#define	CCGR_UART2_CLK			__CCGR_NUM(1, 5)
#define	CCGR_UART2_SERIAL_CLK		__CCGR_NUM(1, 6)
#define	CCGR_UART3_CLK			__CCGR_NUM(1, 7)
#define	CCGR_UART3_SERIAL_CLK		__CCGR_NUM(1, 8)
#define	CCGR_I2C1_SERIAL_CLK		__CCGR_NUM(1, 9)
#define	CCGR_I2C2_SERIAL_CLK		__CCGR_NUM(1, 10)
#define	CCGR_HSI2C_CLK			__CCGR_NUM(1, 11)
#define	CCGR_HSI2C_SERIAL_CLK		__CCGR_NUM(1, 12)
#define	CCGR_FIRI_CLK			__CCGR_NUM(1, 13)
#define	CCGR_FIRI_SERIAL_CLK		__CCGR_NUM(1, 14)
#define	CCGR_SCC_CLK			__CCGR_NUM(1, 15)

#define	CCGR_USB_PHY_CLK		__CCGR_NUM(2, 0)
#define	CCGR_EPIT1_CLK			__CCGR_NUM(2, 1)
#define	CCGR_EPIT1_SERIAL_CLK		__CCGR_NUM(2, 2)
#define	CCGR_EPIT2_CLK			__CCGR_NUM(2, 3)
#define	CCGR_EPIT2_SERIAL_CLK		__CCGR_NUM(2, 4)
#define	CCGR_PWM1_CLK			__CCGR_NUM(2, 5)
#define	CCGR_PWM1_SERIAL_CLK		__CCGR_NUM(2, 6)
#define	CCGR_PWM2_CLK			__CCGR_NUM(2, 7)
#define	CCGR_PWM2_SERIAL_CLK		__CCGR_NUM(2, 8)
#define	CCGR_GPT_CLK			__CCGR_NUM(2, 9)
#define	CCGR_GPT_SERIAL_CLK		__CCGR_NUM(2, 10)
#define	CCGR_OWIRE_CLK			__CCGR_NUM(2, 11)
#define	CCGR_FEC_CLK			__CCGR_NUM(2, 12)
#define	CCGR_USBOH3_IPG_AHB_CLK		__CCGR_NUM(2, 13)
#define	CCGR_USBOH3_60M_CLK		__CCGR_NUM(2, 14)
#define	CCGR_TVE_CLK			__CCGR_NUM(2, 15)

#define	CCGR_ESDHC1_CLK			__CCGR_NUM(3, 0)
#define	CCGR_ESDHC1_SERIAL_CLK		__CCGR_NUM(3, 1)
#define	CCGR_ESDHC2_CLK			__CCGR_NUM(3, 2)
#define	CCGR_ESDHC2_SERIAL_CLK		__CCGR_NUM(3, 3)
#define	CCGR_ESDHC3_CLK			__CCGR_NUM(3, 4)
#define	CCGR_ESDHC3_SERIAL_CLK		__CCGR_NUM(3, 5)
#define	CCGR_ESDHC4_CLK			__CCGR_NUM(3, 6)
#define	CCGR_ESDHC4_SERIAL_CLK		__CCGR_NUM(3, 7)
#define	CCGR_SSI1_CLK			__CCGR_NUM(3, 8)
#define	CCGR_SSI1_SERIAL_CLK		__CCGR_NUM(3, 9)
#define	CCGR_SSI2_CLK			__CCGR_NUM(3, 10)
#define	CCGR_SSI2_SERIAL_CLK		__CCGR_NUM(3, 11)
#define	CCGR_SSI3_CLK			__CCGR_NUM(3, 12)
#define	CCGR_SSI3_SERIAL_CLK		__CCGR_NUM(3, 13)
#define	CCGR_SSI_EXT1_CLK		__CCGR_NUM(3, 14)
#define	CCGR_SSI_EXT2_CLK		__CCGR_NUM(3, 15)

#define	CCGR_PATA_CLK			__CCGR_NUM(4, 0)
#define	CCGR_SIM_CLK			__CCGR_NUM(4, 1)
#define	CCGR_SIM_SERIAL_CLK		__CCGR_NUM(4, 2)
#define	CCGR_SAHARA_CLK			__CCGR_NUM(4, 3)
#define	CCGR_RTIC_CLK			__CCGR_NUM(4, 4)
#define	CCGR_ECSPI1_CLK			__CCGR_NUM(4, 5)
#define	CCGR_ECSPI1_SERIAL_CLK		__CCGR_NUM(4, 6)
#define	CCGR_ECSPI2_CLK			__CCGR_NUM(4, 7)
#define	CCGR_ECSPI2_SERIAL_CLK		__CCGR_NUM(4, 8)
#define	CCGR_CSPI_CLK			__CCGR_NUM(4, 9)
#define	CCGR_SRTC_CLK			__CCGR_NUM(4, 10)
#define	CCGR_SDMA_CLK			__CCGR_NUM(4, 11)

#define	CCGR_SPBA_CLK			__CCGR_NUM(5, 0)
#define	CCGR_GPU_CLK			__CCGR_NUM(5, 1)
#define	CCGR_GARB_CLK			__CCGR_NUM(5, 2)
#define	CCGR_VPU_CLK			__CCGR_NUM(5, 3)
#define	CCGR_VPU_SERIAL_CLK		__CCGR_NUM(5, 4)
#define	CCGR_IPU_CLK			__CCGR_NUM(5, 5)
#define	CCGR_EMI_GARB_CLK		__CCGR_NUM(6, 0)
#define	CCGR_IPU_DI0_CLK		__CCGR_NUM(6, 1)
#define	CCGR_IPU_DI1_CLK		__CCGR_NUM(6, 2)
#define	CCGR_GPU2D_CLK			__CCGR_NUM(6, 3)
#define	CCGR_SLIMBUS_CLK		__CCGR_NUM(6, 4)
#define	CCGR_SLIMBUS_SERIAL_CLK		__CCGR_NUM(6, 5)

#define	CCGR_CLK_MODE_OFF		0
#define	CCGR_CLK_MODE_RUNMODE		1
#define	CCGR_CLK_MODE_ALWAYS		3

#endif /* _IMX51_CCMREG_H */
