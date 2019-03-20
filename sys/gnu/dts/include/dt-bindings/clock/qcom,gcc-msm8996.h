/*
 * Copyright (c) 2015, The Linux Foundation. All rights reserved.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _DT_BINDINGS_CLK_MSM_GCC_8996_H
#define _DT_BINDINGS_CLK_MSM_GCC_8996_H

#define GPLL0_EARLY						0
#define GPLL0							1
#define GPLL1_EARLY						2
#define GPLL1							3
#define GPLL2_EARLY						4
#define GPLL2							5
#define GPLL3_EARLY						6
#define GPLL3							7
#define GPLL4_EARLY						8
#define GPLL4							9
#define SYSTEM_NOC_CLK_SRC					10
#define CONFIG_NOC_CLK_SRC					11
#define PERIPH_NOC_CLK_SRC					12
#define MMSS_BIMC_GFX_CLK_SRC					13
#define USB30_MASTER_CLK_SRC					14
#define USB30_MOCK_UTMI_CLK_SRC					15
#define USB3_PHY_AUX_CLK_SRC					16
#define USB20_MASTER_CLK_SRC					17
#define USB20_MOCK_UTMI_CLK_SRC					18
#define SDCC1_APPS_CLK_SRC					19
#define SDCC1_ICE_CORE_CLK_SRC					20
#define SDCC2_APPS_CLK_SRC					21
#define SDCC3_APPS_CLK_SRC					22
#define SDCC4_APPS_CLK_SRC					23
#define BLSP1_QUP1_SPI_APPS_CLK_SRC				24
#define BLSP1_QUP1_I2C_APPS_CLK_SRC				25
#define BLSP1_UART1_APPS_CLK_SRC				26
#define BLSP1_QUP2_SPI_APPS_CLK_SRC				27
#define BLSP1_QUP2_I2C_APPS_CLK_SRC				28
#define BLSP1_UART2_APPS_CLK_SRC				29
#define BLSP1_QUP3_SPI_APPS_CLK_SRC				30
#define BLSP1_QUP3_I2C_APPS_CLK_SRC				31
#define BLSP1_UART3_APPS_CLK_SRC				32
#define BLSP1_QUP4_SPI_APPS_CLK_SRC				33
#define BLSP1_QUP4_I2C_APPS_CLK_SRC				34
#define BLSP1_UART4_APPS_CLK_SRC				35
#define BLSP1_QUP5_SPI_APPS_CLK_SRC				36
#define BLSP1_QUP5_I2C_APPS_CLK_SRC				37
#define BLSP1_UART5_APPS_CLK_SRC				38
#define BLSP1_QUP6_SPI_APPS_CLK_SRC				39
#define BLSP1_QUP6_I2C_APPS_CLK_SRC				40
#define BLSP1_UART6_APPS_CLK_SRC				41
#define BLSP2_QUP1_SPI_APPS_CLK_SRC				42
#define BLSP2_QUP1_I2C_APPS_CLK_SRC				43
#define BLSP2_UART1_APPS_CLK_SRC				44
#define BLSP2_QUP2_SPI_APPS_CLK_SRC				45
#define BLSP2_QUP2_I2C_APPS_CLK_SRC				46
#define BLSP2_UART2_APPS_CLK_SRC				47
#define BLSP2_QUP3_SPI_APPS_CLK_SRC				48
#define BLSP2_QUP3_I2C_APPS_CLK_SRC				49
#define BLSP2_UART3_APPS_CLK_SRC				50
#define BLSP2_QUP4_SPI_APPS_CLK_SRC				51
#define BLSP2_QUP4_I2C_APPS_CLK_SRC				52
#define BLSP2_UART4_APPS_CLK_SRC				53
#define BLSP2_QUP5_SPI_APPS_CLK_SRC				54
#define BLSP2_QUP5_I2C_APPS_CLK_SRC				55
#define BLSP2_UART5_APPS_CLK_SRC				56
#define BLSP2_QUP6_SPI_APPS_CLK_SRC				57
#define BLSP2_QUP6_I2C_APPS_CLK_SRC				58
#define BLSP2_UART6_APPS_CLK_SRC				59
#define PDM2_CLK_SRC						60
#define TSIF_REF_CLK_SRC					61
#define CE1_CLK_SRC						62
#define GCC_SLEEP_CLK_SRC					63
#define BIMC_CLK_SRC						64
#define HMSS_AHB_CLK_SRC					65
#define BIMC_HMSS_AXI_CLK_SRC					66
#define HMSS_RBCPR_CLK_SRC					67
#define HMSS_GPLL0_CLK_SRC					68
#define GP1_CLK_SRC						69
#define GP2_CLK_SRC						70
#define GP3_CLK_SRC						71
#define PCIE_AUX_CLK_SRC					72
#define UFS_AXI_CLK_SRC						73
#define UFS_ICE_CORE_CLK_SRC					74
#define QSPI_SER_CLK_SRC					75
#define GCC_SYS_NOC_AXI_CLK					76
#define GCC_SYS_NOC_HMSS_AHB_CLK				77
#define GCC_SNOC_CNOC_AHB_CLK					78
#define GCC_SNOC_PNOC_AHB_CLK					79
#define GCC_SYS_NOC_AT_CLK					80
#define GCC_SYS_NOC_USB3_AXI_CLK				81
#define GCC_SYS_NOC_UFS_AXI_CLK					82
#define GCC_CFG_NOC_AHB_CLK					83
#define GCC_PERIPH_NOC_AHB_CLK					84
#define GCC_PERIPH_NOC_USB20_AHB_CLK				85
#define GCC_TIC_CLK						86
#define GCC_IMEM_AXI_CLK					87
#define GCC_MMSS_SYS_NOC_AXI_CLK				88
#define GCC_MMSS_NOC_CFG_AHB_CLK				89
#define GCC_MMSS_BIMC_GFX_CLK					90
#define GCC_USB30_MASTER_CLK					91
#define GCC_USB30_SLEEP_CLK					92
#define GCC_USB30_MOCK_UTMI_CLK					93
#define GCC_USB3_PHY_AUX_CLK					94
#define GCC_USB3_PHY_PIPE_CLK					95
#define GCC_USB20_MASTER_CLK					96
#define GCC_USB20_SLEEP_CLK					97
#define GCC_USB20_MOCK_UTMI_CLK					98
#define GCC_USB_PHY_CFG_AHB2PHY_CLK				99
#define GCC_SDCC1_APPS_CLK					100
#define GCC_SDCC1_AHB_CLK					101
#define GCC_SDCC1_ICE_CORE_CLK					102
#define GCC_SDCC2_APPS_CLK					103
#define GCC_SDCC2_AHB_CLK					104
#define GCC_SDCC3_APPS_CLK					105
#define GCC_SDCC3_AHB_CLK					106
#define GCC_SDCC4_APPS_CLK					107
#define GCC_SDCC4_AHB_CLK					108
#define GCC_BLSP1_AHB_CLK					109
#define GCC_BLSP1_SLEEP_CLK					110
#define GCC_BLSP1_QUP1_SPI_APPS_CLK				111
#define GCC_BLSP1_QUP1_I2C_APPS_CLK				112
#define GCC_BLSP1_UART1_APPS_CLK				113
#define GCC_BLSP1_QUP2_SPI_APPS_CLK				114
#define GCC_BLSP1_QUP2_I2C_APPS_CLK				115
#define GCC_BLSP1_UART2_APPS_CLK				116
#define GCC_BLSP1_QUP3_SPI_APPS_CLK				117
#define GCC_BLSP1_QUP3_I2C_APPS_CLK				118
#define GCC_BLSP1_UART3_APPS_CLK				119
#define GCC_BLSP1_QUP4_SPI_APPS_CLK				120
#define GCC_BLSP1_QUP4_I2C_APPS_CLK				121
#define GCC_BLSP1_UART4_APPS_CLK				122
#define GCC_BLSP1_QUP5_SPI_APPS_CLK				123
#define GCC_BLSP1_QUP5_I2C_APPS_CLK				124
#define GCC_BLSP1_UART5_APPS_CLK				125
#define GCC_BLSP1_QUP6_SPI_APPS_CLK				126
#define GCC_BLSP1_QUP6_I2C_APPS_CLK				127
#define GCC_BLSP1_UART6_APPS_CLK				128
#define GCC_BLSP2_AHB_CLK					129
#define GCC_BLSP2_SLEEP_CLK					130
#define GCC_BLSP2_QUP1_SPI_APPS_CLK				131
#define GCC_BLSP2_QUP1_I2C_APPS_CLK				132
#define GCC_BLSP2_UART1_APPS_CLK				133
#define GCC_BLSP2_QUP2_SPI_APPS_CLK				134
#define GCC_BLSP2_QUP2_I2C_APPS_CLK				135
#define GCC_BLSP2_UART2_APPS_CLK				136
#define GCC_BLSP2_QUP3_SPI_APPS_CLK				137
#define GCC_BLSP2_QUP3_I2C_APPS_CLK				138
#define GCC_BLSP2_UART3_APPS_CLK				139
#define GCC_BLSP2_QUP4_SPI_APPS_CLK				140
#define GCC_BLSP2_QUP4_I2C_APPS_CLK				141
#define GCC_BLSP2_UART4_APPS_CLK				142
#define GCC_BLSP2_QUP5_SPI_APPS_CLK				143
#define GCC_BLSP2_QUP5_I2C_APPS_CLK				144
#define GCC_BLSP2_UART5_APPS_CLK				145
#define GCC_BLSP2_QUP6_SPI_APPS_CLK				146
#define GCC_BLSP2_QUP6_I2C_APPS_CLK				147
#define GCC_BLSP2_UART6_APPS_CLK				148
#define GCC_PDM_AHB_CLK						149
#define GCC_PDM_XO4_CLK						150
#define GCC_PDM2_CLK						151
#define GCC_PRNG_AHB_CLK					152
#define GCC_TSIF_AHB_CLK					153
#define GCC_TSIF_REF_CLK					154
#define GCC_TSIF_INACTIVITY_TIMERS_CLK				155
#define GCC_TCSR_AHB_CLK					156
#define GCC_BOOT_ROM_AHB_CLK					157
#define GCC_MSG_RAM_AHB_CLK					158
#define GCC_TLMM_AHB_CLK					159
#define GCC_TLMM_CLK						160
#define GCC_MPM_AHB_CLK						161
#define GCC_SPMI_SER_CLK					162
#define GCC_SPMI_CNOC_AHB_CLK					163
#define GCC_CE1_CLK						164
#define GCC_CE1_AXI_CLK						165
#define GCC_CE1_AHB_CLK						166
#define GCC_BIMC_HMSS_AXI_CLK					167
#define GCC_BIMC_GFX_CLK					168
#define GCC_HMSS_AHB_CLK					169
#define GCC_HMSS_SLV_AXI_CLK					170
#define GCC_HMSS_MSTR_AXI_CLK					171
#define GCC_HMSS_RBCPR_CLK					172
#define GCC_GP1_CLK						173
#define GCC_GP2_CLK						174
#define GCC_GP3_CLK						175
#define GCC_PCIE_0_SLV_AXI_CLK					176
#define GCC_PCIE_0_MSTR_AXI_CLK					177
#define GCC_PCIE_0_CFG_AHB_CLK					178
#define GCC_PCIE_0_AUX_CLK					179
#define GCC_PCIE_0_PIPE_CLK					180
#define GCC_PCIE_1_SLV_AXI_CLK					181
#define GCC_PCIE_1_MSTR_AXI_CLK					182
#define GCC_PCIE_1_CFG_AHB_CLK					183
#define GCC_PCIE_1_AUX_CLK					184
#define GCC_PCIE_1_PIPE_CLK					185
#define GCC_PCIE_2_SLV_AXI_CLK					186
#define GCC_PCIE_2_MSTR_AXI_CLK					187
#define GCC_PCIE_2_CFG_AHB_CLK					188
#define GCC_PCIE_2_AUX_CLK					189
#define GCC_PCIE_2_PIPE_CLK					190
#define GCC_PCIE_PHY_CFG_AHB_CLK				191
#define GCC_PCIE_PHY_AUX_CLK					192
#define GCC_UFS_AXI_CLK						193
#define GCC_UFS_AHB_CLK						194
#define GCC_UFS_TX_CFG_CLK					195
#define GCC_UFS_RX_CFG_CLK					196
#define GCC_UFS_TX_SYMBOL_0_CLK					197
#define GCC_UFS_RX_SYMBOL_0_CLK					198
#define GCC_UFS_RX_SYMBOL_1_CLK					199
#define GCC_UFS_UNIPRO_CORE_CLK					200
#define GCC_UFS_ICE_CORE_CLK					201
#define GCC_UFS_SYS_CLK_CORE_CLK				202
#define GCC_UFS_TX_SYMBOL_CLK_CORE_CLK				203
#define GCC_AGGRE0_SNOC_AXI_CLK					204
#define GCC_AGGRE0_CNOC_AHB_CLK					205
#define GCC_SMMU_AGGRE0_AXI_CLK					206
#define GCC_SMMU_AGGRE0_AHB_CLK					207
#define GCC_AGGRE1_PNOC_AHB_CLK					208
#define GCC_AGGRE2_UFS_AXI_CLK					209
#define GCC_AGGRE2_USB3_AXI_CLK					210
#define GCC_QSPI_AHB_CLK					211
#define GCC_QSPI_SER_CLK					212
#define GCC_USB3_CLKREF_CLK					213
#define GCC_HDMI_CLKREF_CLK					214
#define GCC_UFS_CLKREF_CLK					215
#define GCC_PCIE_CLKREF_CLK					216
#define GCC_RX2_USB2_CLKREF_CLK					217
#define GCC_RX1_USB2_CLKREF_CLK					218
#define GCC_HLOS1_VOTE_LPASS_CORE_SMMU_CLK			219
#define GCC_HLOS1_VOTE_LPASS_ADSP_SMMU_CLK			220
#define GCC_EDP_CLKREF_CLK					221
#define GCC_MSS_CFG_AHB_CLK					222
#define GCC_MSS_Q6_BIMC_AXI_CLK					223
#define GCC_MSS_SNOC_AXI_CLK					224
#define GCC_MSS_MNOC_BIMC_AXI_CLK				225
#define GCC_DCC_AHB_CLK						226
#define GCC_AGGRE0_NOC_MPU_CFG_AHB_CLK				227
#define GCC_MMSS_GPLL0_DIV_CLK					228
#define GCC_MSS_GPLL0_DIV_CLK					229

#define GCC_SYSTEM_NOC_BCR					0
#define GCC_CONFIG_NOC_BCR					1
#define GCC_PERIPH_NOC_BCR					2
#define GCC_IMEM_BCR						3
#define GCC_MMSS_BCR						4
#define GCC_PIMEM_BCR						5
#define GCC_QDSS_BCR						6
#define GCC_USB_30_BCR						7
#define GCC_USB_20_BCR						8
#define GCC_QUSB2PHY_PRIM_BCR					9
#define GCC_QUSB2PHY_SEC_BCR					10
#define GCC_USB_PHY_CFG_AHB2PHY_BCR				11
#define GCC_SDCC1_BCR						12
#define GCC_SDCC2_BCR						13
#define GCC_SDCC3_BCR						14
#define GCC_SDCC4_BCR						15
#define GCC_BLSP1_BCR						16
#define GCC_BLSP1_QUP1_BCR					17
#define GCC_BLSP1_UART1_BCR					18
#define GCC_BLSP1_QUP2_BCR					19
#define GCC_BLSP1_UART2_BCR					20
#define GCC_BLSP1_QUP3_BCR					21
#define GCC_BLSP1_UART3_BCR					22
#define GCC_BLSP1_QUP4_BCR					23
#define GCC_BLSP1_UART4_BCR					24
#define GCC_BLSP1_QUP5_BCR					25
#define GCC_BLSP1_UART5_BCR					26
#define GCC_BLSP1_QUP6_BCR					27
#define GCC_BLSP1_UART6_BCR					28
#define GCC_BLSP2_BCR						29
#define GCC_BLSP2_QUP1_BCR					30
#define GCC_BLSP2_UART1_BCR					31
#define GCC_BLSP2_QUP2_BCR					32
#define GCC_BLSP2_UART2_BCR					33
#define GCC_BLSP2_QUP3_BCR					34
#define GCC_BLSP2_UART3_BCR					35
#define GCC_BLSP2_QUP4_BCR					36
#define GCC_BLSP2_UART4_BCR					37
#define GCC_BLSP2_QUP5_BCR					38
#define GCC_BLSP2_UART5_BCR					39
#define GCC_BLSP2_QUP6_BCR					40
#define GCC_BLSP2_UART6_BCR					41
#define GCC_PDM_BCR						42
#define GCC_PRNG_BCR						43
#define GCC_TSIF_BCR						44
#define GCC_TCSR_BCR						45
#define GCC_BOOT_ROM_BCR					46
#define GCC_MSG_RAM_BCR						47
#define GCC_TLMM_BCR						48
#define GCC_MPM_BCR						49
#define GCC_SEC_CTRL_BCR					50
#define GCC_SPMI_BCR						51
#define GCC_SPDM_BCR						52
#define GCC_CE1_BCR						53
#define GCC_BIMC_BCR						54
#define GCC_SNOC_BUS_TIMEOUT0_BCR				55
#define GCC_SNOC_BUS_TIMEOUT2_BCR				56
#define GCC_SNOC_BUS_TIMEOUT1_BCR				57
#define GCC_SNOC_BUS_TIMEOUT3_BCR				58
#define GCC_SNOC_BUS_TIMEOUT_EXTREF_BCR				59
#define GCC_PNOC_BUS_TIMEOUT0_BCR				60
#define GCC_PNOC_BUS_TIMEOUT1_BCR				61
#define GCC_PNOC_BUS_TIMEOUT2_BCR				62
#define GCC_PNOC_BUS_TIMEOUT3_BCR				63
#define GCC_PNOC_BUS_TIMEOUT4_BCR				64
#define GCC_CNOC_BUS_TIMEOUT0_BCR				65
#define GCC_CNOC_BUS_TIMEOUT1_BCR				66
#define GCC_CNOC_BUS_TIMEOUT2_BCR				67
#define GCC_CNOC_BUS_TIMEOUT3_BCR				68
#define GCC_CNOC_BUS_TIMEOUT4_BCR				69
#define GCC_CNOC_BUS_TIMEOUT5_BCR				70
#define GCC_CNOC_BUS_TIMEOUT6_BCR				71
#define GCC_CNOC_BUS_TIMEOUT7_BCR				72
#define GCC_CNOC_BUS_TIMEOUT8_BCR				73
#define GCC_CNOC_BUS_TIMEOUT9_BCR				74
#define GCC_CNOC_BUS_TIMEOUT_EXTREF_BCR				75
#define GCC_APB2JTAG_BCR					76
#define GCC_RBCPR_CX_BCR					77
#define GCC_RBCPR_MX_BCR					78
#define GCC_PCIE_0_BCR						79
#define GCC_PCIE_0_PHY_BCR					80
#define GCC_PCIE_1_BCR						81
#define GCC_PCIE_1_PHY_BCR					82
#define GCC_PCIE_2_BCR						83
#define GCC_PCIE_2_PHY_BCR					84
#define GCC_PCIE_PHY_BCR					85
#define GCC_DCD_BCR						86
#define GCC_OBT_ODT_BCR						87
#define GCC_UFS_BCR						88
#define GCC_SSC_BCR						89
#define GCC_VS_BCR						90
#define GCC_AGGRE0_NOC_BCR					91
#define GCC_AGGRE1_NOC_BCR					92
#define GCC_AGGRE2_NOC_BCR					93
#define GCC_DCC_BCR						94
#define GCC_IPA_BCR						95
#define GCC_QSPI_BCR						96
#define GCC_SKL_BCR						97
#define GCC_MSMPU_BCR						98
#define GCC_MSS_Q6_BCR						99
#define GCC_QREFS_VBG_CAL_BCR					100
#define GCC_PCIE_PHY_COM_BCR					101
#define GCC_PCIE_PHY_COM_NOCSR_BCR				102
#define GCC_USB3_PHY_BCR					103
#define GCC_USB3PHY_PHY_BCR					104
#define GCC_MSS_RESTART						105


/* Indexes for GDSCs */
#define AGGRE0_NOC_GDSC			0
#define HLOS1_VOTE_AGGRE0_NOC_GDSC	1
#define HLOS1_VOTE_LPASS_ADSP_GDSC	2
#define HLOS1_VOTE_LPASS_CORE_GDSC	3
#define USB30_GDSC			4
#define PCIE0_GDSC			5
#define PCIE1_GDSC			6
#define PCIE2_GDSC			7
#define UFS_GDSC			8

#endif
