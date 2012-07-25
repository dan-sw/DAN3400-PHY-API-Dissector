/*
 * All files except if stated otherwise in the begining of the file are under the GPLv2 license:
 * -----------------------------------------------------------------------------------
 * 
 * Copyright (c) 2010-2012 Design Art Networks Ltd.
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
#ifndef _PIDAN_DEF_H
#define _PIDAN_DEF_H

/*
 * -----------------------------------------------------------
 * Include section
 * -----------------------------------------------------------
 */
#include "I_sys_defs.h"
#include "PI.h"



/*
 * -----------------------------------------------------------
 * MACRO (define) section
 * -----------------------------------------------------------
 */





/*
 * -----------------------------------------------------------
 * Type definition section
 * -----------------------------------------------------------
 */


 /********************************************
  *  DAN Physical Interface API Enumerators
  ********************************************
 */
 /************************************
  *  DAN Ethernet Protocol definitions
  ************************************
 */
 typedef enum {
     PIE_E_FRAG_FULL     = 0,
     PIE_E_FRAG_FIRST    = 1,
     PIE_E_FRAG_MID      = 2,
     PIE_E_FRAG_LAST     = 3,
 } PIE_E_FRAG_TYPE;


 /************************************
  *  DAN Fragmented Buffers typedefs
  ************************************
 */
 typedef enum {
     PIE_E_FRAG_STAT_WFM =   0,  //Wait for new message state
                                 // - WNT_PIE_E_FRAG_FULL
                                 // - WNT_PIE_E_FRAG_FIRST
     PIE_E_FRAG_STAT_IMG =   1,  //Wait for MID or Last Fragment
                                 // - WNT_PIE_E_FRAG_MID
                                 // - WNT_PIE_E_FRAG_LAST
 }  PIE_E_FRAG_STAT;

     //VLAN IDs
#define MAC_PHY_API_VLAN	1

 //VLAN TAG Has the following structure
 // +----+----+---+-+----+----+----+
 // | Protocol|pri|f|   vlan id    |
 // |   Id    |   | |              |
 // +----+----+---+-+----+----+----+
 //Ethernet Header
 typedef struct PACK_STRUCT ETH_DIX_HEADER_S {
     UINT8   dest_mac[6];
     UINT8   src_mac[6] ;
     UINT16  type;
 } ETH_DIX_HEADER_T;

 typedef struct PACK_STRUCT RAW_VLAN_HEADER_S {
     UINT8      dest_mac[6];
     UINT8      src_mac[6] ;
     UINT16     vlan_protocol_id;
     UINT16     vlan_id;
     UINT16     type;
 } ETH_VLAN_HEADER_T;

 typedef union PACK_STRUCT ETH_HEADER_S {
     ETH_DIX_HEADER_T    dix;
     ETH_VLAN_HEADER_T   vlan;
 } ETH_HEADER_T;

 typedef struct PACK_STRUCT DAN_S_PIE_E_HDR {
     UINT32      type;           //Message type. Further may be used for
                                     //prioritization (TBD)
     UINT16      seq;            //Message sequence index
     UINT16      size;           //Size of the message payload in bytes
                                     //(not including Ethernet header)
     UINT8	     frag;           //Fragment (0-full, 1-first, 2-middle, 3-last)
     UINT8		 nsf;			 //Optional: Sub-frame number when the message was sent
     UINT16      nf;             //Optional: frame number when the message was sent
 } DAN_T_PIE_E_HDR;

 typedef struct PACK_STRUCT DAN_S_PIE_E_MSG_HDR {
     ETH_HEADER_T    eth_hdr;
     DAN_T_PIE_E_HDR PI_hdr;     //Message type. Further may be used for
 } DAN_T_PIE_E_MSG_HDR;

/*
 * -----------------------------------------------------------
 * PI messages def
 * -----------------------------------------------------------
 */

 /*********************************
  *  Common header that is included
  *  at the beginning of all
  *  MAC-PHY messages
  *********************************
 */
typedef struct PACK_STRUCT PI_DAN_S_MSG_HDR {
     DAN_UINT32      seq;            //Running sequence number excluding 0 value.
     DAN_UINT32      type;           //Message type
     DAN_BOOL        ack_required;   //If true, then the receiver side shall
     DAN_UINT16      size;           //Message size in bytes
                                     //send the ack message which is by default
                                     //DAN_GEN_ERR_CODE_ RSP/REQ unless explicitly
                                     //defined
     DAN_UINT16      nf;             //Frame number associated with this message
     DAN_UINT8       nsf;            //SF number associated with this message
     DAN_UINT8       sector_id;      //Sector ID associated with this message
     DAN_UINT16      rsrv;
 } PI_DAN_T_MSG_HDR;

 /*********************************
  *  TB Memory Data Element
  *********************************
 */
typedef struct PACK_STRUCT PI_DAN_S_TB_DATA_ELM {
	 DAN_UINT16 size; 	//Data element size in bytes
	 DAN_UINT16 reserved;
	 DAN_UINT8 *p_data;	 //Pointer to buffer with data, in ETH the first data byte
						 //is copied into the p_data location
} PI_DAN_T_TB_DATA_ELM;

/*********************************
 *  Array of data elements (chunks)
 *  to be retrieved for the TB
 *  specified by rnti and mimo_id
 *********************************
*/
typedef struct PACK_STRUCT PI_DAN_S_TB_DATA_ELM_ARR {
 	DAN_UINT8	reserved;	//Reserverd
 	DAN_UINT8	tb_idx; 	//Running TB ID provided by L2.
 							//This TB ID uniquely identifies the TB
 							//within the SF and is used to link between
 							//the TB descriptor and data
 	DAN_UINT16 	num_of_elms;//Number of data elements in the array
} PI_DAN_T_TB_DATA_ELM_ARR;

/********************************************************
 *  TB descriptor provides to PHY all necessary info for
 *  encoding a TB into PDSCH except of the data chunks.
 *  Notice that data arrives in a separate message
 *  linked by tb_idx.
 ********************************************************
*/
typedef struct PACK_STRUCT PI_DAN_S_PDSCH_TB_DSC {
 	DAN_UINT8	tb_idx;			//Running TB ID provided by L2.  This TB ID
 								//uniquely identifies the TB within the SF and
 								//is used to link between the TB descriptor and data.
 	DAN_UINT8   resrv1;			//Alignment padding
 	DAN_UINT16	rnti ;			//UE ID
 	DAN_UINT16	tb_size;		//TB data size in bytes
 	DAN_UINT16	n_rb;			//Number of RBs allocated.
 	DAN_UINT32	rb_bitmap[4]; //RBs bitmap. Bit map represent the standard
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
 	DAN_UINT8	k_mimo;			//Standard Parameter. When the parameter
 								//Transmission Mode is set 3 or 4, the
 								//Kmimo parameter is set to 2. Otherwise it is
 								//set to 1
 	DAN_UINT16	mimo_id;		//Associates TBs that are spatially multiplexed.
 	DAN_UINT8	ue_category;	//Standard ue category
 	DAN_UINT8	resrv;			//Alignment padding
} PI_DAN_T_PDSCH_TB_DSC;

/********************************************************
 *  The PDSCH Request contains multiple TB descriptors
 *  to be sent over PDSCH in the specified SF.
 ********************************************************
*/
typedef struct PACK_STRUCT PI_DAN_S_AIRDL_PDSCH_REQ_COMMON {
 	DAN_UINT8			num_of_tbs;	//Number of TB descriptors in the message
 	DAN_UINT8			resrv[3];	//Alignment padding
 } PI_DAN_T_AIRDL_PDSCH_REQ_COMMON;

 /********************************************************
  *  This message carries the data to be transmitted over
  *  PDSCH in this SF. It contains a list of data element
  *  arrays where each one in turn contains the data elements.
  *  This is used by the PHY to read the necessary bytes out
  *  of memory for constructing the Transport Block.
  ********************************************************
 */
typedef struct PACK_STRUCT PI_DAN_S_AIRDL_PDSCH_DATA_ELEMS_REQ_COMMON {
 	DAN_UINT8			num_of_data_arrs;//Number of data element arrays in the message
 	DAN_UINT8			resrv[3];	//Alignment padding
} PI_DAN_T_AIRDL_PDSCH_DATA_ELEMS_REQ_COMMON;

/********************************************************
 *  Data Structure providing the PHY all the required UE
 *  parameters for encoding of a single PDCCH message
 ********************************************************
*/
typedef struct PACK_STRUCT PI_DAN_S_PDCCH_DSC {
	DAN_UINT16	Rnti;			//Radio Network Temporary Identifier value
	DAN_UINT8	cce_offset ;	//Allocation offset of CCE in the PDCCH physical
								//channel. *maximal offset is subject to carrier BW
	DAN_UINT8	resrv1;			//Alignment padding
	DAN_E_PDCCH_FORMAT	pdcch_format;//3GPP PDCCH Format. Determines the Num of CCE
	DAN_E_DCI_FORMAT	dci_format;	 //3GPP PDCCH DCI Format
	DAN_E_UE_PORT		antenna_selection; //RUE transmit antenna selection mask
	DAN_E_STD_PA		Pdcch_boost;//total power adjust (relative to RS power) for
									//PDSCH REs in all OFDM symbols not containing
									//Cell-Specific RS
	DAN_UINT16			payload_length; //DCI payload length[bits]
	DAN_UINT16			resrv2;			//Alignment padding
	DAN_UINT32			Payload[8];		//The formatted DCI message.  (LITTLEENDIAN)
} PI_DAN_T_PDCCH_DSC;

/********************************************************
 *  This message specifies the encoding of PDCCH
 ********************************************************
*/
typedef struct PACK_STRUCT PI_DAN_S_AIRDL_PDCCH_REQ {
	DAN_T_MSG_HDR	msg_header;	//Common message header
	DAN_UINT16		n_ue;		//Number of UE addressed at this message
	DAN_UINT16		resrv;		//Alignment padding
	PI_DAN_T_PDCCH_DSC *pdcch_dsc;	//dynamic array of  DAN_T_PDCCH_DSC
} PI_DAN_AIRDL_PDCCH_REQ;

/********************************************************
 *  This message is sent by PHY to MAC to indicate TTI
 *  Event.
 ********************************************************
*/
typedef struct PACK_STRUCT PI_DAN_S_TTI_EVT {
	PI_DAN_T_MSG_HDR	msg_header;	//Common message header
	DAN_UINT16		    nf; 		//Number of frame
	DAN_UINT8		    nsf;		//Number of sub-frame
	DAN_UINT8			rsrv;
} PI_DAN_TTI_EVT;



/*
 * -----------------------------------------------------------
 * End of file
 * -----------------------------------------------------------
 */
#endif // _PIDANDEF_H





