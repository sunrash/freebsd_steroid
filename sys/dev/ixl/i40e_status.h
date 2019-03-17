/******************************************************************************

  Copyright (c) 2013-2018, Intel Corporation
  All rights reserved.
  
  Redistribution and use in source and binary forms, with or without 
  modification, are permitted provided that the following conditions are met:
  
   1. Redistributions of source code must retain the above copyright notice, 
      this list of conditions and the following disclaimer.
  
   2. Redistributions in binary form must reproduce the above copyright 
      notice, this list of conditions and the following disclaimer in the 
      documentation and/or other materials provided with the distribution.
  
   3. Neither the name of the Intel Corporation nor the names of its 
      contributors may be used to endorse or promote products derived from 
      this software without specific prior written permission.
  
  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.

******************************************************************************/
/*$FreeBSD: releng/12.0/sys/dev/ixl/i40e_status.h 335339 2018-06-18 20:32:53Z erj $*/

#ifndef _I40E_STATUS_H_
#define _I40E_STATUS_H_

/* Error Codes */
enum i40e_status_code {
	I40E_SUCCESS				= 0,
	I40E_ERR_NVM				= -1,
	I40E_ERR_NVM_CHECKSUM			= -2,
	I40E_ERR_PHY				= -3,
	I40E_ERR_CONFIG				= -4,
	I40E_ERR_PARAM				= -5,
	I40E_ERR_MAC_TYPE			= -6,
	I40E_ERR_UNKNOWN_PHY			= -7,
	I40E_ERR_LINK_SETUP			= -8,
	I40E_ERR_ADAPTER_STOPPED		= -9,
	I40E_ERR_INVALID_MAC_ADDR		= -10,
	I40E_ERR_DEVICE_NOT_SUPPORTED		= -11,
	I40E_ERR_MASTER_REQUESTS_PENDING	= -12,
	I40E_ERR_INVALID_LINK_SETTINGS		= -13,
	I40E_ERR_AUTONEG_NOT_COMPLETE		= -14,
	I40E_ERR_RESET_FAILED			= -15,
	I40E_ERR_SWFW_SYNC			= -16,
	I40E_ERR_NO_AVAILABLE_VSI		= -17,
	I40E_ERR_NO_MEMORY			= -18,
	I40E_ERR_BAD_PTR			= -19,
	I40E_ERR_RING_FULL			= -20,
	I40E_ERR_INVALID_PD_ID			= -21,
	I40E_ERR_INVALID_QP_ID			= -22,
	I40E_ERR_INVALID_CQ_ID			= -23,
	I40E_ERR_INVALID_CEQ_ID			= -24,
	I40E_ERR_INVALID_AEQ_ID			= -25,
	I40E_ERR_INVALID_SIZE			= -26,
	I40E_ERR_INVALID_ARP_INDEX		= -27,
	I40E_ERR_INVALID_FPM_FUNC_ID		= -28,
	I40E_ERR_QP_INVALID_MSG_SIZE		= -29,
	I40E_ERR_QP_TOOMANY_WRS_POSTED		= -30,
	I40E_ERR_INVALID_FRAG_COUNT		= -31,
	I40E_ERR_QUEUE_EMPTY			= -32,
	I40E_ERR_INVALID_ALIGNMENT		= -33,
	I40E_ERR_FLUSHED_QUEUE			= -34,
	I40E_ERR_INVALID_PUSH_PAGE_INDEX	= -35,
	I40E_ERR_INVALID_IMM_DATA_SIZE		= -36,
	I40E_ERR_TIMEOUT			= -37,
	I40E_ERR_OPCODE_MISMATCH		= -38,
	I40E_ERR_CQP_COMPL_ERROR		= -39,
	I40E_ERR_INVALID_VF_ID			= -40,
	I40E_ERR_INVALID_HMCFN_ID		= -41,
	I40E_ERR_BACKING_PAGE_ERROR		= -42,
	I40E_ERR_NO_PBLCHUNKS_AVAILABLE		= -43,
	I40E_ERR_INVALID_PBLE_INDEX		= -44,
	I40E_ERR_INVALID_SD_INDEX		= -45,
	I40E_ERR_INVALID_PAGE_DESC_INDEX	= -46,
	I40E_ERR_INVALID_SD_TYPE		= -47,
	I40E_ERR_MEMCPY_FAILED			= -48,
	I40E_ERR_INVALID_HMC_OBJ_INDEX		= -49,
	I40E_ERR_INVALID_HMC_OBJ_COUNT		= -50,
	I40E_ERR_INVALID_SRQ_ARM_LIMIT		= -51,
	I40E_ERR_SRQ_ENABLED			= -52,
	I40E_ERR_ADMIN_QUEUE_ERROR		= -53,
	I40E_ERR_ADMIN_QUEUE_TIMEOUT		= -54,
	I40E_ERR_BUF_TOO_SHORT			= -55,
	I40E_ERR_ADMIN_QUEUE_FULL		= -56,
	I40E_ERR_ADMIN_QUEUE_NO_WORK		= -57,
	I40E_ERR_BAD_IWARP_CQE			= -58,
	I40E_ERR_NVM_BLANK_MODE			= -59,
	I40E_ERR_NOT_IMPLEMENTED		= -60,
	I40E_ERR_PE_DOORBELL_NOT_ENABLED	= -61,
	I40E_ERR_DIAG_TEST_FAILED		= -62,
	I40E_ERR_NOT_READY			= -63,
	I40E_NOT_SUPPORTED			= -64,
	I40E_ERR_FIRMWARE_API_VERSION		= -65,
	I40E_ERR_ADMIN_QUEUE_CRITICAL_ERROR	= -66,
};

#endif /* _I40E_STATUS_H_ */
