/*
 * All files except if stated otherwise in the begining of the file are under the ISC license:
 * -----------------------------------------------------------------------------------
 * 
 * Copyright (c) 20010-2012 Design Art Networks Ltd.
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * 
 * -----------------------------------------------------------------------------------
 * 
 * Following open source packages are used in this project.
 * 
 * -----------------------------------------------------------------------------------
 * 
 * ---------- Wireshark ---------- 
 * License: 		GPL
 * Project URL: 	http://www.wireshark.org/
 * -------------------------------
 */

#ifndef _LI_API_H
#define _LI_API_H
/*
 * -----------------------------------------------------------
 * Include section
 * -----------------------------------------------------------
 */
#include "LI_types.h"

/*
 * -----------------------------------------------------------
 * MACRO (define) section
 * -----------------------------------------------------------
 */

/*********************************
 *  DAN API Basic Types
 *
 * The following basic types are used throughtout
 * the entire API.
 *
 *********************************
*/
/*
 * -----------------------------------------------------------
 * Type definition section
 * -----------------------------------------------------------
 */

#define DAN_E_PDCCH_INVALID_FORMAT      (-1)



/*********************************
 *  DAN API Enumerators
 *********************************
*/
/*********************************
 *  MAC-PHY Interface message
 *  types
 *********************************
*/
typedef enum
{
	DAN_E_CFG_GET_REQ =				 	0L,
	DAN_E_CFG_GET_RSP = 	 			1L,
	DAN_E_CFG_SET_REQ = 	 			2L,
	DAN_E_CFG_SET_RSP = 	 			3L,
	DAN_E_AIRDL_PDSCH_REQ =  			4L,
	DAN_E_AIRDL_PDSCH_DATA_ELMS_REQ = 	5L,
	DAN_E_AIRDL_PDCCH_REQ = 			6L,
	DAN_E_AIRDL_PHICH_REQ =  			7L,
	DAN_E_AIRDL_PBCH_REQ = 	 			8L,
	DAN_E_AIRUL_PUSCH_REQ = 	 		9L,
	DAN_E_AIRUL_PUSCH_CTRL_EVT =  		10L,
	DAN_E_AIRUL_PUCCH_REQ = 		    11L,
	DAN_E_AIRUL_PRACH_REQ = 		    12L,
	DAN_E_AIRUL_PRACH_RSP = 	        13L,
	DAN_E_TTI_EVT = 	 		        14L,
	DAN_E_SYS_INIT_EVT = 	 	    	15L,
	DAN_E_SYS_START_REQ = 	 	    	16L,
	DAN_E_SYS_START_RSP = 	 			17L,
	DAN_E_SYS_STOP_REQ = 	 			18L,
	DAN_E_SYS_STOP_RSP = 	 			19L,
	DAN_E_DBG_MSG_ERR_EVT = 	 		20L,
	DAN_E_AIRDL_PUCCH_EVT = 	 		21L,
	DAN_E_AIRUL_UCI_EVT = 	 			22L,
	DAN_E_AIRUL_PUSCH_MEAS_EVT = 	 	23L,
	DAN_E_AIRUL_PUSCH_EVT = 	 		24L,
	DAN_E_GEN_ERR_CODE_REQ = 	 		25L,
	DAN_E_GEN_ERR_CODE_RSP = 	 		26L,
	DAN_E_AIRUL_SRS_REQ = 	 		    28L,
	DAN_E_AIRUL_SRS_EVT = 	 		    29L,
} DAN_E_MSG_TYPE;



/*********************************
 *  Error Code (TBD)
 *********************************
*/
typedef enum {
	DAN_E_ERR_PASS	= 0L,
} DAN_E_ERR_CODE;
/*********************************
 *  Modulation Types
 *********************************
*/
typedef enum {
	DAN_E_MOD_BPSK		= 0L,
	DAN_E_MOD_QPSK		= 1L,
	DAN_E_MOD_QAM16		= 2L,
	DAN_E_MOD_QAM64		= 3L,
	DAN_E_MOD_QAM256	= 4L,
} DAN_E_MODULATION;

/*********************************
 *  Antenna Mode
 *********************************
*/
typedef enum {
	DAN_E_ANT_MOD_SIMO		  =	0,
	DAN_E_ANT_MOD_MIMO_NO_CDD =	1,
	DAN_E_ANT_MOD_MIMO		  = 2,
	DAN_E_ANT_MOD_TX_DIV	  = 3,
} DAN_E_ANT_MODE;

/*********************************
 *  Antenna Port Mode
 *********************************
*/
typedef enum {
	DAN_E_ANT_PORTs1  	= 0L,
	DAN_E_ANT_PORTs2	= 1L,
	DAN_E_ANT_PORTs4 	= 2L,
} DAN_E_ANT_PORT;

/*********************************
 *  Duplexing Mode
 *********************************
*/
typedef enum {
	DAN_E_FDD  = 0L,
	DAN_E_TDD  = 1L,
	DAN_E_HFDD = 2L,
} DAN_E_DUP_MODE;

/*********************************
 *  Frame Type
 *********************************
*/
typedef enum {
	DAN_E_FRAME_TYPE1 = 0L,
	DAN_E_FRAME_TYPE2 = 1L,
} DAN_E_FRAME_TYPE;

/*********************************
 *  Carrier BW options
 *********************************
*/
typedef enum {
	DAN_E_ANT_BW1p4MHz 	= 0L,
	DAN_E_ANT_BW3MHz	= 1L,
	DAN_E_ANT_BW5MHz	= 2L,
	DAN_E_ANT_BW10MHz	= 3L,
	DAN_E_ANT_BW15MHz	= 4L,
	DAN_E_ANT_BW20MHz	= 5L,
} DAN_E_CARRIER_BW;

/*********************************
 *  Cyclic prefix type
 *********************************
*/
typedef enum {
	DAN_E_CP_NORMAL		= 0L,
	DAN_E_CP_EXTENDED	= 1L,
} DAN_E_CP_TYPE ;

/*********************************
 *  PHICH Duration
 *********************************
*/
typedef enum {
	DAN_E_PHICH_NORMAL		= 0L,
	DAN_E_PHICH_EXTENDED	= 1L,
} DAN_E_PHICH_DURATION ;

/*********************************
 *  PHICH Resources
 *********************************
*/
typedef enum {
	DAN_E_PHICH_ONESIXTH	= 0L,
	DAN_E_PHICH_HALF		= 1L,
	DAN_E_PHICH_ONE			= 2L,
	DAN_E_PHICH_TWO			= 3L,
} DAN_E_PHICH_RESOURCE ;

/*********************************
 *  List of Standard's power adjust
 *  options for PDSCH
 *********************************
*/
typedef enum {
	DAN_E_STD_PA_MINUS_6_77dB	= 0L,
	DAN_E_STD_PA_MINUS_4_77dB	= 1L,
	DAN_E_STD_PA_MINUS_3dB		= 2L,
	DAN_E_STD_PA_MINUS_1_77dB	= 3L,
	DAN_E_STD_PA_0dB			= 4L,
	DAN_E_STD_PA_1dB			= 5L,
	DAN_E_STD_PA_2dB			= 6L,
	DAN_E_STD_PA_3dB			= 7L,
} DAN_E_STD_PA  ;

/*********************************
 *  List of Standard's PDCCH formats
 *********************************
*/
typedef enum {
	DAN_E_PDCCH_FORMAT0 = 0L,
	DAN_E_PDCCH_FORMAT1	= 1L,
	DAN_E_PDCCH_FORMAT2	= 2L,
	DAN_E_PDCCH_FORMAT3	= 3L,
} DAN_E_PDCCH_FORMAT  ;

/*********************************
 *  List of Standard's DCI formats
 *********************************
*/
typedef enum {
	DAN_E_DCI_FORMAT0	= 0L,
	DAN_E_DCI_FORMAT1	= 1L,
	DAN_E_DCI_FORMAT1A	= 2L,
	DAN_E_DCI_FORMAT1B	= 3L,
	DAN_E_DCI_FORMAT1C	= 4L,
	DAN_E_DCI_FORMAT1D	= 5L,
	DAN_E_DCI_FORMAT2	= 6L,
	DAN_E_DCI_FORMAT2A	= 7L,
	DAN_E_DCI_FORMAT3	= 8L,
	DAN_E_DCI_FORMAT3A	= 9L,
} DAN_E_DCI_FORMAT   ;

/*********************************
 *  List of Standard's Standard
 *  PUCCH formats
 *********************************
*/
typedef enum {
	DAN_E_PUCCH_FORMAT0			= 0L,
	DAN_E_PUCCH_FORMAT1a		= 1L,
	DAN_E_PUCCH_FORMAT1b		= 2L,
	DAN_E_PUCCH_FORMAT1plus1a	= 3L,
	DAN_E_PUCCH_FORMAT1plus1b	= 4L,
	DAN_E_PUCCH_FORMAT2			= 5L,
	DAN_E_PUCCH_FORMAT2a		= 6L,
	DAN_E_PUCCH_FORMAT2b		= 7L,
} DAN_E_PUCCH_FORMAT   ;

/*********************************
 *  List of Subcarriers spacing
 *  options
 *********************************
*/
typedef enum {
	DAN_E_SC_SPACING_15KHz	= 0L,
	DAN_E_SC_SPACING_7p5KHz	= 1L,
} DAN_E_SC_SPACING   ;

/*********************************
 *  List of Standard's Standard
 *  UCI formats
 *********************************
*/
typedef enum {
	DAN_E_UCI_FORMAT0	= 0L,
	DAN_E_UCI_FORMAT1	= 1L,
	DAN_E_UCI_FORMAT2	= 2L,
	DAN_E_UCI_FORMAT3	= 3L,
	DAN_E_UCI_FORMAT4	= 4L,
	DAN_E_UCI_FORMAT5	= 5L,
	DAN_E_UCI_FORMAT6	= 6L,
	DAN_E_UCI_FORMAT7	= 7L,
} DAN_E_UCI_FORMAT   ;

/*********************************
 *  List of UE Antenna port
 *********************************
*/
typedef enum {
	DAN_E_UE_PORT0	= 0L,
	DAN_E_UE_PORT1	= 1L,
} DAN_E_UE_PORT    ;

/*********************************
 *  List of Ack\Nack Present
 *  payload options
 *********************************
*/
typedef enum {
	DAN_E_UE_SR_BITMASK0	= 0L,
	DAN_E_UE_SR_BITMASK1	= 1L,
} DAN_E_SR_PRESENCE    ;

/*********************************
 *  List of PUCCH Presence
 *  indication options
 *********************************
*/
typedef enum {
	DAN_E_PUCCH_NOTPRESENT	= 0L,
	DAN_E_PUCCH_PRESENT		= 1L,
} DAN_E_PUCCH_PRESENCE    ;

/*********************************
 *  Configuration parameter types
 *********************************
*/
typedef enum {
	DAN_E_CFG_PARAM_TYPE_NUM		= 0L,
	DAN_E_CFG_PARAM_TYPE_DATA		= 1L,
	DAN_E_CFG_PARAM_TYPE_NUM_ARR	= 2L,
} DAN_E_CFG_PARAM_TYPE    ;


/*********************************
 *  DAN API Message definitions
 *********************************
*/

/*********************************
 *  Common header that is included
 *  at the beginning of all
 *  MAC-PHY messages
 *********************************
*/
typedef struct DAN_S_MSG_HDR {
	DAN_UINT32 		seq;			//Running sequence number excluding 0 value.
	DAN_E_MSG_TYPE 	type;			//Message type
	DAN_BOOL		ack_required; 	//If true, then the receiver side shall
									//send the ack message which is by default
									//DAN_GEN_ERR_CODE_ RSP/REQ unless explicitly
									//defined
	DAN_UINT16		size;			//Message size in bytes
	DAN_UINT16		nf;				//Frame number associated with this message
	DAN_UINT8		nsf;			//SF number associated with this message
	DAN_UINT8		sector_id; 		//Sector ID associated with this message
} DAN_T_MSG_HDR;

//The MSG Header is assumed to be encoded compact into network buffer
//with constant size.
//NOTE: the following must alwats be cortrect
#define msgHdrNetSize (2*sizeof(DAN_UINT32) + 2*sizeof(DAN_UINT16) + sizeof(DAN_BOOL) + 2*sizeof(DAN_UINT8))
/*********************************
 *  Common error code
 *********************************
*/
typedef struct DAN_S_MSG_COMMON_ERR_CODE {
	DAN_E_ERR_CODE type;		//Error code
	DAN_E_MSG_TYPE msg_type;	//Message type for which this error
								//code is related or DAN_E_INVALID_MSG_TYPE
								//if N/A
	DAN_UINT32	   msg_seq;		//Running message sequence number for which
								//this error code is related or 0 if N/A
	DAN_UINT32	   usr_data;	//(Optional) Additional app data
} DAN_T_MSG_COMMON_ERR_CODE;

/*********************************
 *  Generic buffer descriptor
 *********************************
*/
typedef struct DAN_S_BUF {
	DAN_UINT32 size;	//Size of buffer in bytes
	DAN_VOID_P data;	//Pointer to the buffer start (void*)
} DAN_T_BUF;

/*********************************
 *  TB Memory Data Element
 *********************************
*/
typedef struct DAN_S_TB_DATA_ELM_MEM {
	DAN_UINT8 *p_data;	//Pointer to buffer with data
	DAN_UINT16 size; 	//Data element size in bytes
} DAN_T_TB_DATA_ELM_MEM;

/*********************************
 *  TB SRIO Data Element
 *********************************
*/
typedef struct DAN_S_TB_DATA_ELM_SRIO {
	DAN_UINT32 offset;		//Offset in the SRIO window
	DAN_UINT16 size; 		//Data element size in bytes
	DAN_UINT8  device_id; 	//SRIO device ID
} DAN_T_TB_DATA_ELM_SRIO;

/*********************************
 *  TB Ethernet Data Element
 *********************************
*/
typedef struct DAN_S_TB_DATA_ELM_ETH {
	DAN_UINT8 *p_data;	//Pointer to buffer with data
	DAN_UINT16 size; 	//Data element size in bytes
} DAN_T_TB_DATA_ELM_ETH;

/*********************************
 *  TB Data Element Union
 *********************************
*/
typedef union DAN_U_TB_DATA_ELM
{
	DAN_T_TB_DATA_ELM_MEM	data_elm_mem;
	DAN_T_TB_DATA_ELM_SRIO	data_elm_srio;
	DAN_T_TB_DATA_ELM_ETH	data_elm_eth;
} DAN_T_TB_DATA_ELM;

/*********************************
 *  Array of data elements (chunks)
 *  to be retrieved for the TB
 *  specified by rnti and mimo_id
 *********************************
*/
typedef struct DAN_S_TB_DATA_ELM_ARR {
	DAN_UINT8	reserved;	//Reserverd
	DAN_UINT8	tb_idx; 	//Running TB ID provided by L2.
							//This TB ID uniquely identifies the TB
							//within the SF and is used to link between
							//the TB descriptor and data
	DAN_UINT16 	num_of_elms;//Number of data elements in the array
	DAN_T_TB_DATA_ELM *data_elm;//Array of data elements
} DAN_T_TB_DATA_ELM_ARR;

/*********************************
 *  Generic error code sent by
 *  PHY to MAC in a response message
 *********************************
*/
typedef struct DAN_S_GEN_ERR_CODE_RSP {
	DAN_T_MSG_HDR 				msg_header; //Common message header
	DAN_T_MSG_COMMON_ERR_CODE	err_code;	//Error Code
} DAN_T_GEN_ERR_CODE_RSP;

/*********************************
 *  Generic error code sent by MAC
 *  to PHY in a request message
 *********************************
*/
typedef struct DAN_S_GEN_ERR_CODE_REQ {
	DAN_T_MSG_HDR 				msg_header; //Common message header
	DAN_T_MSG_COMMON_ERR_CODE	err_code;	//Error Code
} DAN_T_GEN_ERR_CODE_REQ;


/****************************************
*	CONFIGURATION ATTRIBUTE DEFINITION
*****************************************
*/
/*********************************
 *  Numeric configuration parameter
 *  descriptor
 *********************************
*/
typedef struct DAN_S_CFG_PARAM_NUM_DSC {
	DAN_UINT32	param_id;	//Parameter ID
	DAN_UINT16	index;		//Array index or 0xFFFF if single (non-array)
	DAN_UINT32	value;		//Parameter value
} DAN_T_CFG_PARAM_NUM_DSC;

/*********************************
 *  Array configuration parameter
 *  descriptor
 *********************************
*/
typedef struct DAN_S_CFG_PARAM_NUM_ARR_DSC {
	DAN_UINT32	param_id;		//Parameter ID
	DAN_UINT16	start_index ;	//Start index. All CFG arrays are 0-based
	DAN_UINT16	num_of_params ;	//Number of parameters to be get/set
								//starting from start_index
	DAN_UINT32	values[];		//Array of parameter values to be set/get
								//starting from start_index
} DAN_T_CFG_PARAM_NUM_ARR_DSC;

/*********************************
 *  Data buffer configuration
 *  parameter descriptor
 *********************************
*/
typedef struct DAN_S_CFG_PARAM_DATA_DSC {
	DAN_UINT32	param_id;		//Parameter ID
	DAN_UINT16	index ;			//Array index or 0xFFFF if single (non-array)
	DAN_T_BUF	value;			//Parameter value
} DAN_T_CFG_PARAM_DATA_DSC;

/*********************************
 *  Data buffer configuration
 *  parameter descriptor
 *********************************
*/
typedef union DAN_U_CFG_PARAM_DSC {
	DAN_E_CFG_PARAM_TYPE		param_type;	//Parameter type – determines
											//which type is used in the union
	DAN_T_CFG_PARAM_NUM_DSC		num ;		//Descriptor of numeric parameter type
	DAN_T_CFG_PARAM_NUM_ARR_DSC	arr_of_num;	//Descriptor of array of numeric
											//parameter types
	DAN_T_CFG_PARAM_DATA_DSC	data_buf;	//Descriptor of data buffer parameter
											//type
} DAN_T_CFG_PARAM_DSC;

/****************************************
*	CONFIGURATION COMMANDS DEFINITION
*****************************************
*/
/*********************************
 *  Configuration parameter Get
 *  request
 *********************************
*/
typedef struct DAN_S_CFG_GET_REQ {
	DAN_T_MSG_HDR	msg_header;	//Common message header
	DAN_UINT32		param_id ;	//Parameter ID
	DAN_UINT16		index ;		//Array index or 0xFFFF if single (non-array)
} DAN_CFG_GET_REQ;

/*********************************
 *  Get response message includes
 *  the value (or values in case
 *  of array) of the requested
 *  configuration parameters
 *********************************
*/
typedef struct DAN_S_CFG_GET_RSP {
	DAN_T_MSG_HDR		msg_header;	//Common message header
	DAN_T_CFG_PARAM_DSC	param_dsc ;	//Parameter value packed into generic
									//configuration parameter descriptor.
									//Note: includes a union that should be
									//handled according to param_type
} DAN_CFG_GET_RSP;

/*********************************
 *  Set request message includes
 *  the value (or values in case
 *  of array) to be modified.
 *********************************
*/
typedef struct DAN_S_CFG_SET_REQ {
	DAN_T_MSG_HDR		msg_header;	//Common message header
	DAN_T_CFG_PARAM_DSC	param_dsc ;	//Parameter value packed into generic
									//configuration parameter descriptor.
									//Note: includes a union that should be
									//handled according to param_type
} DAN_CFG_SET_REQ;

/*********************************
 *  Set response message includes
 *  the value (or values in case
 *  of array) of the requested
 *  configuration parameters.
 *********************************
*/
typedef struct DAN_S_CFG_SET_RSP {
	DAN_T_MSG_HDR				msg_header;	//Common message header
	DAN_T_MSG_COMMON_ERR_CODE	err_code ;	//Generic error code returns the
											//result of the corresponding
											//DAN_CFG_SET_REQ.
											//Note:  msg_seq should carry the
											//sequence id of corresponding Set
											//Request message
} DAN_CFG_SET_RSP;

/****************************************
*	AIR DL Interface
*****************************************
*/
/********************************************************
 *  TB descriptor provides to PHY all necessary info for
 *  encoding a TB into PDSCH except of the data chunks.
 *  Notice that data arrives in a separate message
 *  linked by tb_idx.
 ********************************************************
*/
typedef struct DAN_S_PDSCH_TB_DSC {
	DAN_UINT8	tb_idx;			//Running TB ID provided by L2.  This TB ID
								//uniquely identifies the TB within the SF and
								//is used to link between the TB descriptor and data.
	DAN_UINT16	rnti ;			//UE ID
	DAN_UINT16	tb_size;		//TB data size in bytes
	DAN_UINT16	n_rb;			//Number of RBs allocated.
	DAN_UINT32	rb_bitmap[4]; 	//RBs bitmap. Bit map represent the standard
								//RB mapping from 0 to n_dl_rb
	DAN_E_ANT_MODE	antenna_mode; //Antenna mode
	DAN_E_STD_PA	pa;			//total power adjust (relative to RS power)
								//for PDSCH REs in all OFDM symbols not
								//containing Cell-Specific RS
 	DAN_UINT8   mcs;			//MCS index of this TB 	Please refer to 7.1.7.1 in 36.213
	DAN_UINT8	pdsch_boost_index;//Additional power boosting to the
								  //channel [20dB:1dB:20dB]
	DAN_UINT8	rv_idx;			//Redundancy Version index
	DAN_UINT8	pmi_codebook_idx;//Pre-coding Matrix Indication Codebook Index
	DAN_UINT8	rank;			//Rank Indication (indicating number of layers)
	DAN_UINT8	n_codeword;		//Specifies the number of codewords
								//(per table 6.3.3.2-1 in 36.211).
	DAN_UINT8	codeword_id;	//codeword ID - indicating the index of the
								//spatial multiplexed TB
	DAN_UINT16	mimo_id;		//Associates TBs that are spatially multiplexed.
	DAN_UINT8	k_mimo;			//Standard Parameter. When the parameter
								//Transmission Mode is set 3 or 4, the
								//Kmimo parameter is set to 2. Otherwise it is
								//set to 1
	DAN_UINT8	ue_category;	//Standard ue category
	DAN_BOOL    mimo;			//True if MIMO applied
	DAN_T_TB_DATA_ELM_ARR *tb_data; //Dynamic array of TB data elements.
									//This field is optional per PI.
} DAN_T_PDSCH_TB_DSC;

/********************************************************
 *  The PDSCH Request contains multiple TB descriptors
 *  to be sent over PDSCH in the specified SF.
 ********************************************************
*/
typedef struct DAN_S_AIRDL_PDSCH_REQ {
	DAN_T_MSG_HDR	msg_header;	//Common message header
	DAN_UINT8		num_of_tbs;	//Number of TB descriptors in the message
	DAN_T_PDSCH_TB_DSC	*tb_dsc;//Dynamic array of TB descriptors
} DAN_AIRDL_PDSCH_REQ;

/********************************************************
 *  This message carries the data to be transmitted over
 *  PDSCH in this SF. It contains a list of data element
 *  arrays where each one in turn contains the data elements.
 *  This is used by the PHY to read the necessary bytes out
 *  of memory for constructing the Transport Block.
 ********************************************************
*/
typedef struct DAN_S_AIRDL_PDSCH_DATA_ELEMS_REQ {
	DAN_T_MSG_HDR	msg_header;			//Common message header
	DAN_UINT8		num_of_data_arrs;	//Number of data element arrays in the message
	DAN_T_TB_DATA_ELM_ARR	*tb_data;	//Dynamic array of TB data elements
} DAN_AIRDL_PDSCH_DATA_ELEMS_REQ;

/********************************************************
 *  Data Structure providing the PHY all the required UE
 *  parameters for encoding of a single PDCCH message
 ********************************************************
*/
typedef struct DAN_S_PDCCH_DSC {
	DAN_UINT16			rnti;			//Radio Network Temporary Identifier value
	DAN_UINT8			cce_offset ;	//Allocation offset of CCE in the PDCCH physical
										//channel. *maximal offset is subject to carrier BW
	DAN_E_PDCCH_FORMAT	pdcch_format;	//3GPP PDCCH Format. Determines the Num of CCE
	DAN_E_DCI_FORMAT	dci_format;	 	//3GPP PDCCH DCI Format
	DAN_E_UE_PORT		antenna_selection; //RUE transmit antenna selection mask
	DAN_E_STD_PA		pdcch_boost;	//total power adjust (relative to RS power) for
										//PDSCH REs in all OFDM symbols not containing
										//Cell-Specific RS
	DAN_UINT16			payload_length; //DCI payload length[bits]
	DAN_UINT32			payload[8];		//The formatted DCI message. (LITTLEENDIAN)
} DAN_T_PDCCH_DSC;

/********************************************************
 *  This message specifies the encoding of PDCCH
 ********************************************************
*/
typedef struct DAN_S_AIRDL_PDCCH_REQ {
	DAN_T_MSG_HDR	msg_header;	//Common message header
	DAN_UINT16		n_ue;		//Number of UE addressed at this message
	DAN_T_PDCCH_DSC *pdcch_dsc;	//dynamic array of  DAN_T_PDCCH_DSC
} DAN_AIRDL_PDCCH_REQ;

/********************************************************
 *  structure of PHICH parameters per UE that are treated
 *  within this message
 ********************************************************
*/
typedef struct DAN_S_PHICH_DSC {
	DAN_UINT16	rnti; 			//Radio Network Temporary Identifier value
	DAN_UINT8	ack_nack;		//ACK\NACK indication
	DAN_UINT8	sequence_idx;	//The Orthogonal Sequence index
								//assigned for the feedback
} DAN_T_PHICH_DSC;

/********************************************************
 *  The PHICH encode request specifies data to be
 *  transmitted on the PHICH channel for the specified
 *  cell and subframe
 ********************************************************
*/
typedef struct DAN_S_AIRDL_PHICH_REQ {
	DAN_T_MSG_HDR	msg_header;	//Common message header
	DAN_UINT8		group_id;	//PHICH Group ID. (subject to
								//the definition in CELL_CONFIGURATION
	DAN_UINT8		power_boosting;//Power adjust to this channel
								   //Index representing – [-20:0..5:20]dB.
	DAN_UINT8		n_ue;		//The number of UEs assigned to this message
	DAN_T_PHICH_DSC	*phich_REQ; //dynamic array of  DAN_T_PHICH_REQ
} DAN_AIRDL_PHICH_REQ;

/********************************************************
 *  Specifies the PBCH PHY configuration payload to be
 *  transmitted periodically on the PBCH channel.
 *  These settings remain in force until arrival
 *  of new message.
 ********************************************************
*/
typedef struct DAN_S_AIRDL_PBCH_REQ {
	DAN_T_MSG_HDR	msg_header;		//Common message header
	DAN_UINT8		power_boosting;	//Power adjust to this channel
									//Index representing –[-20:0.5:20]dB.

	DAN_UINT16		payload_length;	//payload length[bits]
	DAN_UINT16		system_frame_number_pointer;//offset within the payload
												//to point the system frame number field
	DAN_UINT32		payload;		//message payload
} DAN_AIRDL_PBCH_REQ;

/****************************************
*	AIR UL Interface
*****************************************
*/
/********************************************************
 *  TB descriptor provides to PHY all necessary info for
 *  encoding a TB into PDSCH except of the data chunks.
 *  Notice that data arrives in a separate message
 *  linked by tb_idx.
 ********************************************************
*/
typedef struct DAN_S_PUSCH_TB_DSC {
	DAN_UINT16	rnti;				//Radio Network Temporary Identifier value
	DAN_E_MODULATION	modulation;	//Modulation of this TB
	DAN_UINT8	rank; 			//Rank Indication (indicating number of layers)
	DAN_UINT8	rb_start;		//start of resource block allocation associated with
								//this UE (up to n_ul_rb which is subject to carrier BW)
	DAN_UINT8	rb_num;			//Number of resource blocks allocation associated with
								//this UE (up to n_ul_rb which is subject to carrier BW)
	DAN_UINT8	harq_rv;		//HARQ redundancy version
	DAN_UINT8	ul_harq_chan_id;//UL HARQ Channel ID - The UL HARQ channel associated
								//with the PUSCH.
	DAN_UINT8	dl_harq_chan_id;//DL HARQ Channel ID - The downlink HARQ channel
								//associated with the PUSCH event upon it is feedback.
								//This is used when punctured ACK\NACK is occupied.
	DAN_UINT8	n2dmrs;			//n2 parameter belonging to demodulation reference
								//signal (ue specific)
	DAN_UINT8	harq_re_tx;		//HARQ retransmission index
	DAN_E_PUCCH_PRESENCE pucch_indication; //presence of PUCCH in this PUSCH
	DAN_UINT8	cqi_nbits;		//number of uncoded CQI bits to decode (0 is not present)
	DAN_UINT8	ri_nbits;		//number of uncoded RI bits to decode (0 is not present)
	DAN_UINT8	acknack_nbits;	//number of uncoded ACK\NACK bits to decode
								//(0 is not present)
	DAN_UINT8	beta_offset_acknack; //HARQ-ACK offset values, used in calculating the
									 //number of coded HARQ-ACK symbols
	DAN_UINT8	beta_offset_cqi;	 //CQI offset values, used in calculating the number
									 //of coded CQI symbols
	DAN_UINT8	beta_offset_ri;	//RI offset values, used in calculating the number of
								//coded RI symbols
	DAN_UINT32	tb_size;		//Transport block size in bits- required for code rate
								//calculation and Q' for channel coding of control
								//information
	DAN_E_UCI_FORMAT	uci_format;	//uci_format <<<<TBD
	DAN_UINT32			usr_data;	//User data to be returned by PHY with
									//DAN_T_PUSCH_DATA_DSC
	DAN_VOID_P 			p_data;		//Buffer to write user data into
} DAN_T_PUSCH_TB_DSC;

/********************************************************
 *  This message configures PUSCH for a given subframe
 ********************************************************
*/
typedef struct DAN_S_AIRUL_PUSCH_REQ {
	DAN_T_MSG_HDR	msg_header;	//Common message header
	DAN_UINT8		n1dmrs;		//n1 parameter belonging to demodulation reference
								//signal (broadcast value)
	DAN_UINT8		n_ue;		//number of Ues associated with this channel
	DAN_UINT16		system_frame_number_pointer;//offset within the payload
												//to point the system frame number field
	DAN_T_PUSCH_TB_DSC	ue_dsc[];//dynamic array of DAN_T_PUSCH_TB_DSC
} DAN_AIRUL_PUSCH_REQ;

/********************************************************
 *  This struct contains decoded UE data for control plane
 *  messages received on PUSCH when puncturing is used
 ********************************************************
*/
typedef struct DAN_S_PUSCH_CTRL_DSC {
	DAN_UINT16	rnti;	//Radio Network Temporary Identifier value
	DAN_UINT8	ack_nack_presence; //Ack/Nack Present field- bit map for 2 transport
								   //blocks (distinguishing multi codeword).
								   //The 2 LSBs indicate the presence of ACK\NACK
								   //response for TB1 and TB0 respectively
								   //(TB1 being the most LSB)i.e. for each TBi
								   //(where I & {0,1}}, the value 1 in bit(i)
								   //indicates presence of ACK\NACK and 0 indicates
								   //that it is not present
	DAN_UINT8	ack_nack;		//Ack\Nack bitmap for 2 Transport blocks
								//Ack/Nack bit map for 2 transport blocks
								//(distinguishing multi codeword).
								//The 2 LSBs indicate the payload of ACK\NACK response
								//for TB1 and TB0 respectively (TB1 being the most LSB)
								//i.e. for each TBi (where I & {0,1}}, the value 1 in
								//bit(i)  indicates ACK and 0 indicates NACK
	DAN_E_SR_PRESENCE	sr;		//Scheduling Request Present field.
								//the value 1 in the LSB  indicates SR is present and
								//0 indicates NACK
	DAN_UINT8	dl_harq_chan_id;//DL HARQ Channel ID - The downlink HARQ channel
								//associated with the PUCCH event
} DAN_T_PUSCH_CTRL_DSC;

/********************************************************
 *  This message contains the decoded control plane
 *  information extracted from PUSCH, when punctured
 *  control is used
 ********************************************************
*/
typedef struct DAN_S_AIRUL_PUSCH_CTRL_EVT {
	DAN_T_MSG_HDR	msg_header;	//Common message header
	DAN_UINT8		n_ue;		//number of Ues associated with this channel
	DAN_UINT16		system_frame_number_pointer;//offset within the payload
												//to point the system frame number field
	DAN_T_PUSCH_CTRL_DSC	ue_ctrl_data[];     //dynamic array of DAN_T_PUSCH_CTRL_ DSC
} DAN_AIRUL_PUSCH_CTRL_EVT;

/********************************************************
 *  This struct contains the decoded TB data received on
 *  PUSCH and UE specific radio link measurements
 *  estimated for transmission of this TB.
 ********************************************************
*/
typedef struct DAN_S_PUSCH_RX_TB_DSC {
	DAN_UINT8	tb_idx;	//Running TB ID provided by L2.  This TB ID uniquely identifies
						//the TB within the SF and is used to link between the TB
						//descriptor and data.
	DAN_UINT16	rnti;	//Radio Network Temporary Identifier value
	DAN_UINT8	n_rb;	//Number of RBs allocated to PUCCH
	DAN_UINT16	timing_offset;  //ue detected timing offset[Ts]
								//integer values representing
								//[-1024:1023][Ts]
	DAN_UINT16	c2i;	//C/I measurement associated with this reception (as measured by
						//PHY). Integer value representing: [-20:0.2:40]dB.
	DAN_UINT8	rank;	//Rank Indication (indicating number of layers)
	DAN_UINT16	RTWP;	//received signal strength (total over antennas),
						//intergers represent interval of [-130:1:0][dBm]
	DAN_UINT8	ul_harq_chan_id; //UL HARQ Channel ID - The UL HARQ channel associated
								 //with the PUSCH.
	DAN_UINT8	crc_detect;		//CRC detect indication
	DAN_UINT8	sigma_kr;		//Total encoded data for this reception (aiding the MAC
								//for future allocations of control_data on PUSCH
	DAN_UINT32	usr_data;		//32 bit user token specified in DAN_T_PUSCH_TB_DSC.
								//This may be a pointer to the data buffer allocated on
								//MAC side.
} DAN_T_PUSCH_RX_TB_DSC;

/********************************************************
 *  This message contains the decoded data plane information
 *  extracted from PUSCH and radio link measurements
 *  estimated on the common resource of the PUSCH.
 ********************************************************
*/
typedef struct DAN_S_AIRUL_PUSCH_DATA_EVT {
	DAN_T_MSG_HDR	msg_header;	//Common message header
	DAN_UINT8		n_ue;		//number of UEs associated with this channel
	DAN_UINT16		avg_rssi;	//received signal strength (total over antennas)
								//Integer value representing: [-130:1:0]dBm
	DAN_UINT16		avg_c2i;	//C/I measurement associated with this reception
								//(as measured by PHY). Integer value representing:
								//[-20:0.2:40]dB
	DAN_T_PUSCH_RX_TB_DSC	ue_air_data[];//dynamic array of DAN_T_PUSCH_RX_TB_DSC
} DAN_AIRUL_PUSCH_DATA_EVT;

/********************************************************
 *  This message carries the data to be received over PUSCH.
 *  It contains a list of data element arrays where each
 *  one in turn contains the data elements
 ********************************************************
*/
typedef struct DAN_S_AIRUL_PUSCH_DATA_ELMS_EVT {
	DAN_T_MSG_HDR	msg_header;			//Common message header
	DAN_UINT8		num_of_data_arrs;	//Number of data element arrays in the message
	DAN_T_TB_DATA_ELM_ARR	tb_data[];	//Dynamic array of TB data elements
} DAN_AIRUL_PUSCH_DATA_ELMS_EVT;

/********************************************************
 *  Data Structure specifying the set of PUCCH decodes
 *  to be performed for a given subframe
 ********************************************************
*/
typedef struct DAN_S_PUCCH_DSC {
	DAN_UINT16	rnti;					//Radio Network Temporary Identifier value
	DAN_E_PUCCH_FORMAT	pucch_format; 	//PUCCH format for this UE
	DAN_E_UCI_FORMAT	uci_format;	  	//uci format

	DAN_UINT8	 n_pucch;				//Resource index for PUCCH formats 1/1a/1b
										//or for formats 2/2a/2b
	DAN_UINT8	dl_harq_chan_id;		//DL HARQ Channel ID - The downlink HARQ channel
										//associated with the PUCCH event
} DAN_T_PUCCH_DSC;

/********************************************************
 *  This message specifies the set of PUCCH decoding to
 *  perform for a given subframe
 ********************************************************
*/
typedef struct DAN_S_AIRUL_PUCCH_REQ {
	DAN_T_MSG_HDR	msg_header;	//Common message header
	DAN_UINT32		host_dest;  //pointer to system defined routing destination
								//of PUCCH related information
	DAN_UINT8		n_rb;		//Number of RBs allocated to PUCCH
	DAN_UINT8		delta_pucch_shift; //
	DAN_UINT8		n_rb_cqi;	//(n_rb2)Bandwidth available for use by PUCCH formats
								//2/2a/2b, expressed in multiples of  RBs
	DAN_UINT8		n_cs_an;	//(n_cs1) Number of cyclic shifts used for PUCCH
								//formats 1/1a/1b in a resource block with a mix of
								//formats 1/1a/1b and 2/2a/2b
	DAN_UINT16		n_ue;		//Number of UE addressed at this message
	DAN_T_PUCCH_DSC	Pucch_REQ[];//dynamic array of  DAN_T_PUCCH_REQ
} DAN_AIRUL_PUCCH_REQ;

/********************************************************
 *  Data structure containing the PUCCH decoded data for
 *  a particular UE within the message
 ********************************************************
*/
typedef struct DAN_S_PUCCH_DECODED_DSC {
	DAN_UINT16	rnti;				//Radio Network Temporary Identifier value
	DAN_UINT8	ack_nack_presence; 	//Ack/Nack Present field- bit map for 2 transport
									//blocks (distinguishing multi codeword).
									//The 2 LSBs indicate the presence of ACK\NACK
									//response for TB1 and TB0 respectively
									//(TB1 being the most LSB) 	i.e. for each TBi
									//(where I & {0,1}}, the value 1 in bit(i)
									//indicates presence of ACK\NACK and 0 indicates
									//that it is not present
	DAN_UINT8	ack_nack;			//Ack\Nack bitmap for 2 Transport blocks
									//Ack/Nack bit map for 2 transport blocks
									//(distinguishing multi codeword).
									//The 2 LSBs indicate the payload of ACK\NACK
									//response for TB1 and TB0 respectively
									//(TB1 being the most LSB)
									//i.e. for each TBi (where I & {0,1}}, the value
									//1 in bit(i)  indicates ACK and 0 indicates NACK
	DAN_E_SR_PRESENCE	sr;			//Scheduling Request Present field.
									//the value 1 in the LSB  indicates SR is present
									//and 0 indicates NACK
	DAN_UINT8			dl_harq_chan_id; //DL HARQ Channel ID - The downlink HARQ channel
										 //associated with the PUCCH event
} DAN_T_PUCCH_DECODED_DSC;

/********************************************************
 *  PHY event message that contains the data decoded from
 *  the PUCCH for the group of UEs in a given subframe
 *
 *  TBD <--
 ********************************************************
*/
typedef struct DAN_S_AIRDL_PUCCH_EVT {
	DAN_T_MSG_HDR	msg_header;	//Common message header
	DAN_UINT8		error_code; //message error indication (error message
								//would follow)
	DAN_UINT16		n_ue;		//Number of UE addressed at this message
	DAN_T_PUCCH_DECODED_DSC	pucch_ind[];//dynamic array of  DAN_T_PUCCH_DECODED_DSC
} DAN_AIRDL_PUCCH_EVT;

/********************************************************
 *  Data Structure containing the decoded data for a
 *  specific UCI (e.g. CQI, PMI, RI)
 ********************************************************
*/
typedef struct DAN_S_UCI_DSC {
	DAN_UINT16	rnti;					//Radio Network Temporary Identifier value
	DAN_E_PUCCH_FORMAT	pucch_format; 	//Physical channel format
	DAN_E_UCI_FORMAT	uci_format;		//uci format
	DAN_UINT32			payload;		//The formatted UCI message.
	DAN_UINT16			c2i; 			//C/I measurement associated with this
										//reception (as measured by PHY).
										//Integer value representing: [-20:0.2:40]dB.
} DAN_T_UCI_DSC;

/********************************************************
 *  This message sends the decoded UCI data received
 *  (e.g. CQI, PMI, RI) on the PUSCH and PUCCH channels
 *  in a given subframe
 *
 *  TBD <--
 ********************************************************
*/
typedef struct DAN_S_AIRUL_UCI_EVT {
	DAN_T_MSG_HDR	msg_header;	//Common message header
	DAN_UINT8		error_code; //message error indication (error message
								//would follow)
	DAN_UINT16		n_ue;		//Number of UE addressed at this message
	 DAN_T_UCI_DSC	uci_data[];	//dynamic array of DAN_T_UCI_DSC
} DAN_AIRUL_UCI_EVT;

/********************************************************
 *  Data structure containing the results of specific
 *  detected preamble in a PRACH channel
 ********************************************************
*/
typedef struct DAN_S_PRACH_DSC {
	DAN_UINT16	preamble_id;	 //Preamble index detected
	DAN_UINT32	detection_metric;//detection metric for the preamble
								 //(Relative metric in an interval [-20:1:100][dB]
								 //represented by Integer.

	DAN_UINT32	timing_offset; 	 //ue detected timing offset[Ts]
								 //integer values representing [-15000:1:15000][Ts]
} DAN_T_PRACH_DSC;

/********************************************************
 *  This message reconfigures PRACH channel.
 *  (valid until next reconfiguration)
 ********************************************************
*/
typedef struct DAN_S_AIRUL_PRACH_REQ {
	DAN_T_MSG_HDR	msg_header;			//Common message header
	DAN_UINT16		logical_root_sequence_number; //Root zadoff-chu sequence order
												  //logical sequence number
	DAN_UINT16		prach_conf_index; 	//PRACH configuration index
	DAN_UINT8		ncs; 			  	//Ncs configuration  for PRACH cyclic shift
										//("zeroCorrelationZoneConfig")
	DAN_UINT8		prach_FreqOffset; 	//Resource Block offset (beginning of the
										//PRACH allocation)
	DAN_UINT8		highSpeedFlag;	  	//determines if unrestricted set or restricted set shall be used
										//for PRACH cyclic shift
	DAN_UINT8		prach_format;	  	//PRACH Format
	DAN_UINT8		thr;			  	//Threshold Factor for detection criteria in
										//[dB] above noise floor
} DAN_AIRUL_PRACH_REQ;

/********************************************************
 *  This message indicates the result status of the PRACH
 *  configuration request and replies the detected data
 ********************************************************
*/
typedef struct DAN_S_AIRUL_PRACH_RSP {
	DAN_T_MSG_HDR	msg_header;			//Common message header
	DAN_UINT8		error_indication; 	//message error indication (error message
										//would follow)
	DAN_T_PRACH_DSC	preambles[]; 	  	//dynamic array of DAN_T_PRACH_DSC
} DAN_AIRUL_PRACH_RSP;

/********************************************************
 *  This message is sent by PHY to MAC each TTI start.
 * Note: this message is sent only when TTI is configured to
 * SW as described above.
 ********************************************************
*/
typedef struct DAN_S_TTI_EVT {
	DAN_T_MSG_HDR	msg_header;	//Common message header
	DAN_UINT16		nf; 		//Number of frame
	DAN_UINT8		nsf;		//Number of sub-frame
} DAN_TTI_EVT;

/********************************************************
 *  This message is periodically sent by PHY to MAC upon
 *  initialization completed. Once PHY completes Init
 *  phase it starts sending this message until first
 *  message from MAC is received.
 ********************************************************
*/
typedef struct DAN_S_SYS_INIT_EVT {
	DAN_T_MSG_HDR	msg_header;	//Common message header
} DAN_SYS_INIT_EVT;

/********************************************************
 *  This message is sent by MAC to PHY to trigger system
 *  start on PHY side. Once received, PHY starts TX/RX
 *  and begins to send TTI events to MAC.
 ********************************************************
*/
typedef struct DAN_S_SYS_START_REQ {
	DAN_T_MSG_HDR	msg_header;	//Common message header
} DAN_SYS_START_REQ;

/********************************************************
 *  This message is sent by PHY to MAC as a response to
 *  received DAN_START_ SYS_REQ message.
 ********************************************************
*/
typedef struct DAN_S_SYS_START_RSP {
	DAN_T_MSG_HDR	msg_header;	//Common message header
	DAN_E_ERR_CODE	err_code;	//Generic error code returns the result of
								//the corresponding DAN_START_REQ.
} DAN_SYS_START_RSP;

/********************************************************
 *  This message is sent by PHY to MAC up on an invalid
 *  message received from MAC.
 ********************************************************
*/
typedef struct DAN_S_MSG_ERR {
	DAN_T_MSG_HDR	msg_header;	//Common message header
	DAN_UINT32		seq;		//Sequence number of the received message
	DAN_E_ERR_CODE	code;		//Error code
} DAN_MSG_ERR;

/********************************************************
  *  Current LI processing status
  ********************************************************
 */
 typedef struct LI_S_PROC_STATUS {
    DAN_UINT32  last:   		1;   // indicates that last transmission for this frame received
 	DAN_UINT32  pdsch_done:		1;  // sent to PHY
 	DAN_UINT32  pdcch_done:		1;  // sent to PHY
 	DAN_UINT32  pdbch_done:		1;  // sent to PHY
 	DAN_UINT32  pusch_done:		1;  // sent to PHY
	DAN_UINT32  rsrv0:  		3;
	DAN_UINT32  pdsch_dsc:  	8;	// counter of received descriptors
	DAN_UINT32  pdsch_dsc_data: 8;	// counter of received data arrays
 	DAN_UINT32  rsrv1:   		8;

 } LI_T_PROC_STATUS;


/*
 * -----------------------------------------------------------
 * Static inline functions section
 * -----------------------------------------------------------
 */

/*
 * -----------------------------------------------------------
 * Global prototypes section
 * -----------------------------------------------------------
 */
/********************************************************
 *  Function prototypes
 ********************************************************
*/
//Handle API logical message
#if 0
void	LI_handle_pdsch_request		(DAN_AIRDL_PDSCH_REQ *reqPtr);
void 	LI_handle_pdsch_data_request(DAN_AIRDL_PDSCH_DATA_ELEMS_REQ  *reqPtr);
void 	LI_handle_pdcch_request		(DAN_AIRDL_PDCCH_REQ *req);

UINT8 	LI_GetNsf(void);
UINT16 	LI_GetNf(void);
UINT32 	LI_GetPhyTti(void);
void 	LI_send_tti(void);

void 	LI_SetPhyTti(UINT32 stat);
void 	LI_GetProcStatus(LI_T_PROC_STATUS* pstatus);
void 	LI_ResetProcStatus();

//L1 --> L2
DAN_BOOL LI_CheckTTI (DAN_BOOL force);

//Debug Utility functions
void LI_print_li_hdr(DAN_T_MSG_HDR *hdr);
void LI_print_pdsch_request 	 (void *ptr);
void LI_print_pdsch_data_request (void *ptr);
void LI_print_pdcch_request      (void *ptr);
#endif

#endif /*_LI_API_H*/


/*
 * -----------------------------------------------------------
 * End of file
 * -----------------------------------------------------------
 */
