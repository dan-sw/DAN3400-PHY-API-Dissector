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

#ifndef DAN_LTE_SDK_H
#define DAN_LTE_SDK_H

#define ENDIANESS  LITTLE_ENDIAN

#define PROTO_TAG_dan_lte_sdk	                            "DAN_LTE_SDK"
#define PROTO_DAN_LTE_SDK_ETHERNET                          (0xFFFF)

#if ENDIANESS == BIG_ENDIAN
     //  #warning: "System is BIG_ENDIAN"
  #define htons(A) (A)
  #define htonl(A) (A)
  #define ntohs(A) (A)
  #define ntohl(A) (A)
#elif ENDIANESS == LITTLE_ENDIAN
     //  #warning: "System is LITTLE_ENDIAN"
  #define htons(A) ((((unsigned short)(A) & 0xff00) >> 8) | \
                         (((unsigned short)(A) & 0x00ff) << 8))
  #define htonl(A) ((((unsigned long)(A) & 0xff000000) >> 24) | \
                         (((unsigned long)(A) & 0x00ff0000) >> 8)  | \
                         (((unsigned long)(A) & 0x0000ff00) << 8)  | \
                         (((unsigned long)(A) & 0x000000ff) << 24))

  #define ntohs  htons
  #define ntohl  htonl
#else
  #error: "Must define one of BIG_ENDIAN or LITTLE_ENDIAN"
#endif

/* PI-E header info */
#define PROTO_DAN_LTE_SDK_PI_E_HEADER_TYPE_OFF              (0)
#define PROTO_DAN_LTE_SDK_PI_E_HEADER_SEQ_OFF               (4)
#define PROTO_DAN_LTE_SDK_PI_E_HEADER_SIZE_OFF              (6)
#define PROTO_DAN_LTE_SDK_PI_E_HEADER_FRAG_OFF              (8)
#define PROTO_DAN_LTE_SDK_PI_E_HEADER_NSF_OFF               (9)
#define PROTO_DAN_LTE_SDK_PI_E_HEADER_NF_OFF                (10)

/* DAN Message header info */
#define PROTO_DAN_LTE_SDK_MSG_HEADER_SEQ_OFF                (12)
#define PROTO_DAN_LTE_SDK_MSG_HEADER_TYPE_OFF               (16)
#define PROTO_DAN_LTE_SDK_MSG_HEADER_TYPE_ACK_REQ_OFF       (20)
#define PROTO_DAN_LTE_SDK_MSG_HEADER_TYPE_SIZE_OFF          (24)
#define PROTO_DAN_LTE_SDK_MSG_HEADER_TYPE_NF_OFF            (26)
#define PROTO_DAN_LTE_SDK_MSG_HEADER_TYPE_NSF_OFF           (28)
#define PROTO_DAN_LTE_SDK_MSG_HEADER_TYPE_SECTOR_ID_OFF     (29)
#define PROTO_DAN_LTE_SDK_MSG_HEADER_TYPE_RESERVE_OFF       (30)

/* PI-E Fragmentation Status */
#define FR_FULL   (0)
#define FR_FIRST  (1)
#define FR_MID    (2)
#define FR_LAST   (3)

/* Direction */
#define UPLINK      (0)
#define DOWNLINK    (1)

/* Bit fields in the Payload Format 0/1A */
#define P0_1A_TYPE        (1<<31)       /* DCI Format */
#define P0_HOPPING        (1<<30)       /* Hooping/No Hopping */
#define P1A_ALLOCATION    (1<<30)       /* Localized/Distributed Allocation */

/* 1.4MHZ */                            
#define P0_1A_RIV_1_4M    (0x1F<<25)    /* RIV 1_4M */
#define P0_1A_MCS_1_4M    (0x1F<<20)    /* Modulation */

#define P0_NDI_1_4M       (0x1<<19)     /* New Data Indicator */
#define P0_TPC_1_4M       (0x3<<17)     /* TPC Command */
#define P0_CYC_1_4M       (0x7<<14)     /* Cyclic Shift for DM RS */
#define P0_CQI_1_4M       (0x1<<13)     /* CQI Request */
#define P0_REST_1_4M      (0x3<<11)     /* Rest of data */

#define P1A_COUNTER_1_4M  (0x7<<17)     /* Counter 0-7 */
#define P1A_NDI_1_4M      (0x1<<16)     /* New Data Indicator */
#define P1A_RV_1_4M       (0x3<<14)     /* Redundancy Version */
#define P1A_TPC_1_4M      (0x3<<12)     /* TPC Command */
#define P1A_REST_1_4M     (0x1<<11)     /* Rest of data */

/* 3MHZ */
#define P0_1A_RIV_3M    (0x7F<<23)      /* RIV */
#define P0_1A_MCS_3M    (0x1F<<18)      /* Modulation */

#define P0_NDI_3M       (0x1<<17)       /* New Data Indicator */
#define P0_TPC_3M       (0x3<<15)       /* TPC Command */
#define P0_CYC_3M       (0x7<<12)       /* Cyclic Shift for DM RS */
#define P0_CQI_3M       (0x1<<11)       /* CQI Request */
#define P0_REST_3M      (0x1<<10)       /* Rest of data */

#define P1A_COUNTER_3M  (0x7<<15)       /* Counter 0-7 */
#define P1A_NDI_3M      (0x1<<14)       /* New Data Indicator */
#define P1A_RV_3M       (0x3<<12)       /* Redundancy Version */
#define P1A_TPC_3M      (0x3<<10)       /* TPC Command */

/* 5MHZ */
#define P0_1A_RIV_5M    (0x1FF<<21)    /* RIV */
#define P0_1A_MCS_5M    (0x1F<<16)     /* Modulation */

#define P0_NDI_5M       (0x1<<15)      /* New Data Indicator */
#define P0_TPC_5M       (0x3<<13)      /* TPC Command */
#define P0_CYC_5M       (0x7<<10)      /* Cyclic Shift for DM RS */
#define P0_CQI_5M       (0x1<<9)       /* CQI Request */
#define P0_REST_5M      (0x3<<7)       /* Rest of data */

#define P1A_COUNTER_5M  (0x7<<13)      /* Counter 0-7 */
#define P1A_NDI_5M      (0x1<<12)      /* New Data Indicator */
#define P1A_RV_5M       (0x3<<10)      /* Redundancy Version */
#define P1A_TPC_5M      (0x3<<8)       /* TPC Command */
#define P1A_REST_5M     (0x1<<7)       /* Rest of data */

/* 10MHZ */
#define P0_1A_RIV_10M    	  (0x7FF<<19)     /* RIV */
#define P0_1A_MCS_10M         (0x1F<<14)      /* Modulation */

#define P0_NDI_10M            (0x1<<13)       /* New Data Indicator */
#define P0_TPC_10M            (0x3<<11)       /* TPC Command */
#define P0_CYC_10M            (0x7<<8)        /* Cyclic Shift for DM RS */
#define P0_CQI_10M            (0x1<<7)        /* CQI Request */
#define P0_REST_10M           (0x3<<5)        /* Rest of data */

#define P1A_COUNTER_10M       (0x7<<11)       /* Counter 0-7 */
#define P1A_NDI_10M           (0x1<<10)       /* New Data Indicator */
#define P1A_RV_10M            (0x3<<8)        /* Redundancy Version */
#define P1A_TPC_10M           (0x3<<6)        /* TPC Command */
#define P1A_REST_10M          (0x1<<5)        /* Rest of data */

/* 15MHZ */
#define P0_1A_RIV_15M    (0xFFF<<18)     /* RIV */
#define P0_1A_MCS_15M    (0x1F<<13)      /* Modulation */

#define P0_NDI_15M       (0x1<<12)       /* New Data Indicator */
#define P0_TPC_15M       (0x3<<10)       /* TPC Command */
#define P0_CYC_15M       (0x7<<7)       /* Cyclic Shift for DM RS */
#define P0_CQI_15M       (0x1<<6)       /* CQI Request */
#define P0_REST_15M      (0x1<<5)       /* Rest of data */

#define P1A_COUNTER_15M  (0x7<<10)       /* Counter 0-7 */
#define P1A_NDI_15M      (0x1<<9)       /* New Data Indicator */
#define P1A_RV_15M       (0x3<<7)       /* Redundancy Version */
#define P1A_TPC_15M      (0x3<<5)       /* TPC Command */

/* 20MHZ */
#define P0_1A_RIV_20M    (0x1FFF<<17)    /* RIV */
#define P0_1A_MCS_20M    (0x1F<<12)      /* Modulation */

#define P0_NDI_20M       (0x1<<11)       /* New Data Indicator */
#define P0_TPC_20M       (0x3<<9)       /* TPC Command */
#define P0_CYC_20M       (0x7<<6)       /* Cyclic Shift for DM RS */
#define P0_CQI_20M       (0x1<<5)       /* CQI Request */
#define P0_REST_20M      (0x1<<4)       /* Rest of data */

#define P1A_COUNTER_20M  (0x7<<9)       /* Counter 0-7 */
#define P1A_NDI_20M      (0x1<<8)       /* New Data Indicator */
#define P1A_RV_20M       (0x3<<6)       /* Redundancy Version */
#define P1A_TPC_20M      (0x3<<4)       /* TPC Command */


/* Bit fields in the Payload Format 1/2/2A */
#define P1_2_2A_TYPE      (1<<31)    	/* DCI Format (BW >= 1.4M)*/

/* 1.4MHZ */                            
#define P1_2_2A_RIV_1_4M  (0x3F<<26)  	/* RIV */

#define P1_MCS_1_4M    	  (0x1F<<21)   	/* Modulation */
#define P1_HARQ_1_4M      (0x7<<18)   	/* HARQ*/
#define P1_NDI_1_4M       (0x1<<17)     /* New Data Indicator */
#define P1_RV_1_4M        (0x3<<15)     /* Redundancy Version */ 
#define P1_TPC_1_4M       (0x3<<13)     /* TPC Command */

#define P2_2A_TPC_1_4M    (0x3<<24)   	/* TPC Command */
#define P2_2A_HARQ_1_4M   (0x7<<21)     /* HARQ */
#define P2_2A_SWAP_1_4M   (0x1<<20)     /* Swap Flag */
#define P2_2A_MCS0_1_4M   (0x1F<<15)    /* MCS 0 */
#define P2_2A_NDI0_1_4M   (0x1<<14)     /* New Data Indicator 0 */
#define P2_2A_RV0_1_4M    (0x3<<12)     /* Redundancy Version 0 */
#define P2_2A_MCS1_1_4M   (0x1F<<7)     /* MCS 1 */
#define P2_2A_NDI1_1_4M   (0x1<<6)      /* New Data Indicator 1 */
#define P2_2A_RV1_1_4M    (0x3<<4)      /* Redundancy Version 1 */

#define P2_PRECODING_1_4M (0x7<<1)		/* Precoding Information */

/* 3MHZ */
#define P1_2_2A_RIV_3M    (0xFF<<23)	/* RIV */

#define P1_MCS_3M    	  (0x1F<<18)   	/* Modulation */
#define P1_HARQ_3M		  (0x7<<15)   	/* HARQ*/
#define P1_NDI_3M         (0x1<<14)     /* New Data Indicator */
#define P1_RV_3M          (0x3<<12)     /* Redundancy Version */ 
#define P1_TPC_3M         (0x3<<10)     /* TPC Command */
#define P1_REST_3M        (0x1<<9)		/* Rest of data */

#define P2_2A_TPC_3M      (0x3<<21)   	/* TPC Command */
#define P2_2A_HARQ_3M     (0x7<<18)     /* HARQ */
#define P2_2A_SWAP_3M     (0x1<<17)     /* Swap Flag */
#define P2_2A_MCS0_3M     (0x1F<<12)    /* MCS 0 */
#define P2_2A_NDI0_3M     (0x1<<11)     /* New Data Indicator 0 */
#define P2_2A_RV0_3M      (0x3<<9)		/* Redundancy Version 0 */
#define P2_2A_MCS1_3M     (0x1F<<4)     /* MCS 1 */
#define P2_2A_NDI1_3M     (0x1<<3)      /* New Data Indicator 1 */
#define P2_2A_RV1_3M      (0x3<<1)      /* Redundancy Version 1 */

#define P2_PRECODING1_3M  (0x1)			/* Precoding Information (part 1) */
#define P2_PRECODING2_3M  (0x3<<30)		/* Precoding Information (part 2) */

/* 5MHZ */
#define P1_2_2A_RIV_5M    (0x1FFF<<18)	/* RIV */

#define P1_MCS_5M    	  (0x1F<<13)   	/* Modulation */
#define P1_HARQ_5M        (0x7<<10)   	/* HARQ*/
#define P1_NDI_5M         (0x1<<9)		/* New Data Indicator */
#define P1_RV_5M          (0x3<<7)		/* Redundancy Version */ 
#define P1_TPC_5M         (0x3<<5)		/* TPC Command */

#define P2_2A_TPC_5M    (0x3<<16)		/* TPC Command */
#define P2_2A_HARQ_5M   (0x7<<13)		/* HARQ */
#define P2_2A_SWAP_5M   (0x1<<12)		/* Swap Flag */
#define P2_2A_MCS0_5M   (0x1F<<7)		/* MCS 0 */
#define P2_2A_NDI0_5M   (0x1<<6)		/* New Data Indicator 0 */
#define P2_2A_RV0_5M    (0x3<<4)		/* Redundancy Version 0 */
#define P2_2A_MCS1_0_5M (0xF)			/* MCS 1 (part 1) */
#define P2_2A_MCS1_1_5M (0x1<<31)		/* MCS 1 (part 2) */
#define P2_2A_NDI1_5M   (0x1<<30)		/* New Data Indicator 1 */
#define P2_2A_RV1_5M    (0x3<<28)		/* Redundancy Version 1 */

#define P2_PRECODING_5M (0x7<<25)		/* Precoding Information */

/* 10MHZ */
#define P1_2_2A_RIV_10M  (0x1FFFF<<14)	/* RIV */

#define P1_MCS_10M    	 (0x1F<<9)   	/* Modulation */
#define P1_HARQ_10M      (0x7<<6)   	/* HARQ*/
#define P1_NDI_10M       (0x1<<5)		/* New Data Indicator */
#define P1_RV_10M        (0x3<<3)		/* Redundancy Version */ 
#define P1_TPC_10M       (0x3<<1)		/* TPC Command */

#define P2_2A_TPC_10M    (0x3<<12)		/* TPC Command */
#define P2_2A_HARQ_10M   (0x7<<9)		/* HARQ */
#define P2_2A_SWAP_10M   (0x1<<8)		/* Swap Flag */
#define P2_2A_MCS0_10M   (0x1F<<3)		/* MCS 0 */
#define P2_2A_NDI0_10M   (0x1<<2)		/* New Data Indicator 0 */
#define P2_2A_RV0_10M    (0x3)			/* Redundancy Version 0 */
#define P2_2A_MCS1_10M   (0x1F<<27)		/* MCS 1 */
#define P2_2A_NDI1_10M   (0x1<<26)		/* New Data Indicator 1 */
#define P2_2A_RV1_10M    (0x3<<24)		/* Redundancy Version 1 */

#define P2_PRECODING_10M (0x7<<21)		/* Precoding Information */

#define P2A_REST_10M      (0x1<<23)		/* Padding */

/* 15MHZ */
#define P1_2_2A_RIV_15M  (0x7FFFF<<12)	/* RIV */

#define P1_MCS_15M    	 (0x1F<<7)		/* Modulation */
#define P1_HARQ_15M      (0x7<<4)		/* HARQ*/
#define P1_NDI_15M       (0x1<<3)		/* New Data Indicator */
#define P1_RV_15M        (0x3<<2)		/* Redundancy Version */ 
#define P1_TPC1_15M      (0x1<<1)		/* TPC Command (part 1) */
#define P1_TPC2_15M      (0x1<<31)		/* TPC Command (part 2) */

#define P2_2A_TPC_15M    (0x3<<10)		/* TPC Command */
#define P2_2A_HARQ_15M   (0x7<<7)		/* HARQ */
#define P2_2A_SWAP_15M   (0x1<<6)		/* Swap Flag */
#define P2_2A_MCS0_15M   (0x1F<<1)		/* MCS 0 */
#define P2_2A_NDI0_15M   (0x1)			/* New Data Indicator 0 */
#define P2_2A_RV0_15M    (0x3<<30)		/* Redundancy Version 0 */
#define P2_2A_MCS1_15M   (0x1F<<25)		/* MCS 1 */
#define P2_2A_NDI1_15M   (0x1<<24)		/* New Data Indicator 1 */
#define P2_2A_RV1_15M    (0x3<<22)		/* Redundancy Version 1 */

#define P2_PRECODING_15M (0x7<<19)		/* Precoding Information */

/* 20MHZ */
#define P1_2_2A_RIV_20M  (0x1FFFFFF<<6)	/* RIV */

#define P1_MCS_20M    	 (0x1F<<1)		/* Modulation */
#define P1_HARQ1_20M     (0x1)			/* HARQ (part 1) */
#define P1_HARQ2_20M     (0x3<<30)		/* HARQ (part 2) */
#define P1_NDI_20M       (0x1<<29)		/* New Data Indicator */
#define P1_RV_20M        (0x3<<27)		/* Redundancy Version */ 
#define P1_TPC_20M       (0x3<<25)		/* TPC Command */

#define P2_2A_TPC_20M    (0x3<<4)		/* TPC Command */
#define P2_2A_HARQ_20M   (0x7<<1)		/* HARQ */
#define P2_2A_SWAP_20M   (0x1)			/* Swap Flag */
#define P2_2A_MCS0_20M   (0x1F<<27)		/* MCS 0 */
#define P2_2A_NDI0_20M   (0x1<<26)		/* New Data Indicator 0 */
#define P2_2A_RV0_20M    (0x3<<24)		/* Redundancy Version 0 */
#define P2_2A_MCS1_20M   (0x1F<<19)		/* MCS 1 */
#define P2_2A_NDI1_20M   (0x1<<18)		/* New Data Indicator 1 */
#define P2_2A_RV1_20M    (0x3<<16)		/* Redundancy Version 1 */

#define P2_PRECODING_20M (0x7<<13)		/* Precoding Information */

/* 10 MHZ */
#define P3_TPC_10M		 (0x3FFFFFF<<6) /* TPC Command */
#define P3_REST_10M		 (0x1<<5)		/* Padding */	


/* Bit fields of the MAC Header 4 Bytes*/
#define MAC_4Byte_R1           (1<<31)         /* R1 */
#define MAC_4Byte_R2           (1<<30)         /* R2 */
#define MAC_4Byte_E            (1<<29)         /* E */
#define MAC_4Byte_LCID         (0x1F<<24)      /* LCID */
#define MAC_4Byte_F            (1<<23)         /* F */
#define MAC_4Byte_LENGTH_7     (0x7F<<16)      /* Length 7 Bit */
#define MAC_4Byte_LENGTH_15    (0x7FFF<<8)     /* Length 15 Bit */
#define MAC_4Byte_R1_7         (1<<15)         /* R1 After 7 Bit */
#define MAC_4Byte_R2_7         (1<<14)         /* R2 After 7 Bit */
#define MAC_4Byte_E_7          (1<<13)         /* E1 After 7 Bit */
#define MAC_4Byte_LCID_7       (0x1F<<8)       /* LCID After 7 Bit */
#define MAC_4Byte_R1_15        (1<<7)          /* R1 After 15 Bit */
#define MAC_4Byte_R2_15        (1<<6)          /* R2 After 15 Bit */
#define MAC_4Byte_E_15         (1<<5)          /* E1 After 15 Bit */
#define MAC_4Byte_LCID_15      (0x1F<<0 )      /* LCID After 15 Bit */

/* Bit fields of the MAC Header 3 Bytes */
#define MAC_3Byte_R1           (1<<23)         /* R1 */
#define MAC_3Byte_R2           (1<<22)         /* R2 */
#define MAC_3Byte_E            (1<<21)         /* E */
#define MAC_3Byte_LCID         (0x1F<<16)      /* LCID */
#define MAC_3Byte_F            (1<<15)         /* F */
#define MAC_3Byte_LENGTH_7     (0x7F<<8)      /* Length 7 Bit */
#define MAC_3Byte_LENGTH_15    (0x7FFF<<0)     /* Length 15 Bit */
#define MAC_3Byte_R1_7         (1<<7)         /* R1 After 7 Bit */
#define MAC_3Byte_R2_7         (1<<6)         /* R2 After 7 Bit */
#define MAC_3Byte_E_7          (1<<5)         /* E1 After 7 Bit */
#define MAC_3Byte_LCID_7       (0x1F<<0)       /* LCID After 7 Bit */

/* Bit fields of the MAC Header 2 Bytes */
#define MAC_2Byte_R1           (1<<15)         /* R1 */
#define MAC_2Byte_R2           (1<<14)         /* R2 */
#define MAC_2Byte_E            (1<<13)         /* E */
#define MAC_2Byte_LCID         (0x1F<<8)      /* LCID */
#define MAC_2Byte_F            (1<<7)         /* F */
#define MAC_2Byte_LENGTH_7     (0x7F<<0)      /* Length 7 Bit */

/* Bit fields of the MAC Header 1 Bytes (Also used for padding) */
#define MAC_1Byte_R1           (1<<7)         /* R1 */
#define MAC_1Byte_R2           (1<<6)         /* R2 */
#define MAC_1Byte_E            (1<<5)         /* E */
#define MAC_1Byte_LCID         (0x1F<<0)      /* LCID */


/* Bit fields of the RLC Header 4 Bytes */
#define RLC_4Byte_R1           (1<<31)         /* R1 */
#define RLC_4Byte_R2           (1<<30)         /* R2 */
#define RLC_4Byte_R3           (1<<29)         /* R3 */
#define RLC_4Byte_FI           (3<<27)         /* FI */
#define RLC_4Byte_E1           (1<<26)         /* E1 */
#define RLC_4Byte_SN10         (0x3FF<<16)     /* SN 10 Bit */
#define RLC_4Byte_E2           (1<<15)         /* E2 */
#define RLC_4Byte_LI1          (0x7FF<<4)      /* LI 11 Bit */
#define RLC_4Byte_PADD         (0xF<<0)        /* Padding */

/* Bit fields of the RLC Fixed Header 2 Bytes */
#define RLC_2Byte_R1           (1<<15)         /* R1 */
#define RLC_2Byte_R2           (1<<14)         /* R2 */
#define RLC_2Byte_R3           (1<<13)         /* R3 */
#define RLC_2Byte_FI           (3<<11)         /* FI */
#define RLC_2Byte_E1           (1<<10)         /* E1 */
#define RLC_2Byte_SN10         (0x3FF<<0)     /* SN 10 Bit */

/* Bit field of RLC Sub-Header 12bits */
#define RLC_12bit_E            (1<<11)          /* E */
#define RLC_12bit_LI           (11<<0)          /* LI 11bit */

/* Bit field of RLC Sub-Header 16bits (+ padding) */
#define RLC_16bit_E            (1<<15)          /* E */
#define RLC_16bit_LI           (11<<4)          /* LI 11bit */
#define RLC_16bit_PADD         (4<<0)           /* Padding 4bit */

/* Net To Host and Host to Net Macros */
#if ENDIANESS == BIG_ENDIAN
     //  #warning: "System is BIG_ENDIAN"
  #define htons(A) (A)
  #define htonl(A) (A)
  #define ntohs(A) (A)
  #define ntohl(A) (A)
#elif ENDIANESS == LITTLE_ENDIAN
     //  #warning: "System is LITTLE_ENDIAN"
  #define htons(A) ((((unsigned short)(A) & 0xff00) >> 8) | \
                         (((unsigned short)(A) & 0x00ff) << 8))
  #define htonl(A) ((((unsigned long)(A) & 0xff000000) >> 24) | \
                         (((unsigned long)(A) & 0x00ff0000) >> 8)  | \
                         (((unsigned long)(A) & 0x0000ff00) << 8)  | \
                         (((unsigned long)(A) & 0x000000ff) << 24))

  #define ntohs  htons
  #define ntohl  htonl
#else
  #error: "Must define one of BIG_ENDIAN or LITTLE_ENDIAN"
#endif

#define ntohll(x) (((_int64)(ntohl((int)((x << 32) >> 32))) << 32) | (unsigned int)ntohl(((int)(x >> 32))))
#define htonll(x) ntohll(x)


/* static counters */
static int mac_subh_count = 0;
static int Num_of_LI = 0;
static int MAC_header_cnt = 0;

/* Global Tree's */
static proto_tree  *msg_head = NULL;



static const value_string onoff_string[] = {
	{ 0, "OFF" },
	{ 1, "ON" },
	{ 0, NULL }
};

/* PIE-E Header strings */
static const value_string pie_e_header_fragment_string[] = {
	{ 0, "FULL" },
	{ 1, "FIRST" },
	{ 2, "MID" },
    { 3, "LAST" },
	{ 0, NULL }
};

/* DAN Message Header strings */
static const value_string dan_msg_header_string[] = {
	{ 0, "DAN_E_CFG_GET_REQ" },
	{ 1, "DAN_E_CFG_GET_RSP" },
	{ 2, "DAN_E_CFG_SET_REQ" },
    { 3, "DAN_E_CFG_SET_RSP" },
    { 4, "DAN_E_AIRDL_PDSCH_REQ" },
    { 5, "DAN_E_AIRDL_PDSCH_DATA_ELMS_REQ" },
    { 6, "DAN_E_AIRDL_PDCCH_REQ" },
    { 7, "DAN_E_AIRDL_PHICH_REQ" },
    { 8, "DAN_E_AIRDL_PBCH_REQ" },
    { 9, "DAN_E_AIRUL_PUSCH_REQ" },
    { 10, "DAN_E_AIRUL_PUSCH_CTRL_EVT" },
    { 11, "DAN_E_AIRUL_PUCCH_REQ" },
    { 12, "DAN_E_AIRUL_PRACH_REQ" },
    { 13, "DAN_E_AIRUL_PRACH_RSP" },
    { 14, "DAN_E_TTI_EVT" },
    { 15, "DAN_E_SYS_INIT_EVT" },
    { 16, "DAN_E_SYS_START_REQ" },
    { 17, "DAN_E_SYS_START_RSP" },
    { 18, "DAN_E_SYS_STOP_REQ" },
    { 19, "DAN_E_SYS_STOP_RSP" },
    { 20, "DAN_E_DBG_MSG_ERR_EVT" },
    { 21, "DAN_E_AIRDL_PUCCH_EVT" },
    { 22, "DAN_E_AIRUL_UCI_EVT" },
    { 23, "DAN_E_AIRUL_PUSCH_MEAS_EVT" },
    { 24, "DAN_E_AIRUL_PUSCH_EVT" },
    { 25, "DAN_E_GEN_ERR_CODE_REQ" },
    { 26, "DAN_E_GEN_ERR_CODE_RSP" },
	{ 27, "DAN_E DBG_REQ" },
	{ 28, "DAN_E_AIRUL_SRS_REQ" },
    { 29, "DAN_E_AIRUL_SRS_EVT" },
	{ 0, NULL }
};

static const value_string dan_msg_data_ant_method_string[] = {
        { 0, "SIMO" },
        { 1, "MIMO NO CDD" },
        { 2, "MIMO" },
        { 3, "TX DIV" },
        { 0, NULL }
};

static const value_string dan_msg_data_pa_string[] = {
        { 0, "-6.00 dB" },
        { 1, "-4.77 dB" },
        { 2, "-3 dB" },
        { 3, "-1.77 dB" },
        { 4, "0 dB" },
        { 5, "1 dB" },
        { 6, "2 dB" },
        { 7, "3 dB" },
        { 0, NULL }
};

static const value_string dan_msg_data_dci_format_string[] = {
        { 0, "0" },
        { 1, "1" },
        { 2, "1A" },
        { 3, "1B" },
        { 4, "1C" },
        { 5, "1D" },
        { 6, "2" },
        { 7, "2A" },
        { 8, "3" },
        { 9, "3A" },
        { 0, NULL }
};

static const value_string dan_msg_data_pucch_format_string[] = {
        { 0, "1" },
        { 1, "1A" },
        { 2, "1B" },
        { 3, "1_1A" },
        { 4, "1_1B" },
        { 5, "2" },
        { 6, "2A" },
        { 7, "2B" },
        { 8, "1_2" },
        { 9, "1_2A" },
        { 10, "1_2B" },
        { 0, NULL }
};

static const value_string dan_msg_data_uci_format_string[] = {
        { 0, "4Bit" },
        { 1, "6Bit" },
        { 2, "8Bit" },
        { 3, "8Bit" },
        { 4, "11Bit" },
        { 5, "1Bit" },
        { 6, "1Bit" },
        { 7, "2Bit" },
        { 0xff, "Invalid" },
        { 0, NULL }
};


static const value_string dan_msg_data_pdcch_format_string[] = {
        { 0, "1 CCE" },
        { 1, "2 CCEs" },
        { 2, "4 CCEs" },
        { 3, "8 CCEs" },
        { 0, NULL }
};

static const value_string dan_msg_data_antenna_selection_string[] = {
        { 0, "UE port 0" },
        { 1, "UE port 1" },
        { 0, NULL }
};

static const value_string dan_msg_sr_presence_string[] = {
        { 0, "Not Present" },
        { 1, "Present" },
        { 0, NULL }
};

static const value_string dan_msg_pucch_indication_string[] = {
        { 0, "Not Present" },
        { 1, "Present" },
        { 0, NULL }
};

static const value_string dan_msg_data_ack_nack_string[] = {
        { 0, "NACK TB0 & TB1" },
        { 1, "ACK TB0, NACK TB1" },
        { 2, "NACK TB0, ACK TB1" },
        { 3, "ACK TB0 & TB1" },
        { 0, NULL }
};

static const value_string dan_msg_data_ack_nack_presence_string[] = {
	{ 0, "ACK/NACK Not Present" },
	{ 1, "ACK/NACK Present for TB0" },
    { 2, "ACK/NACK Present for TB1" },
    { 3, "ACK/NACK Present for TB0 & TB1" },
	{ 0, NULL }
};

static const value_string dan_msg_data_param_type_string[] = {
        { 0, "NUM" },
        { 1, "DATA" },
        { 2, "NUM ARRAY" },
        { 0, NULL }
};

static const value_string dan_msg_data_param_payload_NDI[] = {
	{0, "No New Data"},
	{1, "New Data"},
	{0, NULL}
};


static const value_string dan_msg_data_param_payload_all_Type[] = {
	{0, "Type 0"},
	{1, "Type 1"},
	{0, NULL }
};

static const value_string dan_msg_data_param_payload_swap_flag[] = {
	{0, "TB1/TB2"},
    {1, "TB2/TB1"},
	{0, NULL }
};

static const true_false_string tfs_payload_Shift = {
	"Shift",
	"No Shift"
};

static const true_false_string tfs_payload_Type = {
	"Format 1A",
	"Format 0"
};

static const true_false_string tfs_payload_Alloc = {
	"Distributed",
	"Localized"
};

static const true_false_string tfs_payload_NDI = {
	"New Data",
	"No New Data"
};

static const true_false_string tfs_payload_Hop = {
	"Hopping",
	"No Hopping"
};

static const true_false_string tfs_payload_all_Type = {
	"Type 1",
	"Type 0"
};

static const true_false_string tfs_payload_swap_flag = {
	"TB1/TB2",
	"TB2/TB1"
};

static const true_false_string tfs_MAC_E = {
	"More subheaders",
	"No more subheaders"
};

static const true_false_string tfs_MAC_F = {
	"Length 15bit",
	"Length 7bit"
};

static const true_false_string tfs_ACK_NACK = {
	"ACK",
	"NACK"
};

static const value_string dan_msg_data_ack_nack_gen_string[] = {
	{ 0, "NACK" },
	{ 1, "ACK" },
	{ 0, NULL }
};

static const value_string dan_msg_data_cqi_presence_string[] = {
	{ 0, "Not Present" },
	{ 1, "Present" },
	{ 0, NULL }
};

static const value_string dan_msg_data_dan_ack_nack_string[] = {
	{ 0, "Non Restricted Set" },
    { 1, "Restricted Set" },
    { 0, NULL }
};


static const value_string dan_msg_data_highspeedflag[] = {
        { 0, "Non Restricted Set" },
        { 1, "Restricted Set" },
        { 0, NULL }
};

static const value_string dan_msg_data_trans_comb_string[] = {
        { 0, "Even" },
        { 1, "Odd" },
        { 0, NULL }
};

static const value_string dan_msg_data_crc_data_string[] = {
        { 0, "Not Forwarded" },
        { 1, "Forwarded" },
        { 0, NULL }
};

/* Preferences bool to control whether we are in big or little endians */
static gboolean global_dan_lte_sdk_BIG_ENDIAN = TRUE;

/* Preferences bool to control whether or not to parse element array in ul/DL data */
static gboolean global_dan_lte_sdk_IPC_NO_ELM_ARR_UL = TRUE;
static gboolean global_dan_lte_sdk_IPC_NO_ELM_ARR_DL = FALSE;

/* Preferences bool to control whether or not to parse UL data pointer in request */
static gboolean global_dan_lte_sdk_UL_parse_p_data = FALSE;

/* Preferences bool to control whether or not to parse UL data pointer in request */
static gboolean global_dan_lte_sdk_PUCCH_parse_cqi_nbits = FALSE;

/* Preferences bool to control whether or not to parse sounding */
static gboolean global_dan_lte_sdk_parse_sounding = FALSE;


/* Preferences bool to control whether or not to dissect ctrl event as API 1.13 or 1.14 */
static gboolean global_dan_lte_sdk_ctrl_evt_yosi = FALSE;

/* Preferences bool to control whether or not to parse crc failures */
static gboolean global_dan_lte_sdk_parse_crc_data = FALSE;

/* Preferences bool to control whether or not to dissect MAC Layer */
static gboolean global_dan_lte_sdk_dissect_MAC_DL = FALSE;
static gboolean global_dan_lte_sdk_dissect_MAC_UL = FALSE;

/* Preferences bool to control whether or not to dissect RLC Layer */
static gboolean global_dan_lte_sdk_dissect_RLC = TRUE;

/* Preferences enum to control the bandwidth used when dissecting PDCCH payload */
static gint global_dan_lte_sdk_PDCCH_bw_val = 10;

static enum_val_t global_dan_lte_sdk_PDCCH_bw_enum[] = {
	{"1_4_MHz","1.4MHz",1},
	{"3_MHz","3MHz",3},
	{"5_MHz","5MHz",5},
	{"10_MHz","10MHz",10},
	{"15_MHz","15MHz",15},
	{"20_MHz","20MHz",20},
	{ NULL, NULL, 0 }
};

/* Wireshark ID of the DAN LTE SDK protocol */
static int proto_dan_lte_sdk = -1;

/* These are the handles of our subdissectors */
static dissector_handle_t data_handle=NULL;

static dissector_handle_t dan_lte_sdk_handle;
static dissector_handle_t dan_mac_lte_handle;
static dissector_handle_t dan_rlc_lte_handle;

/* static parameters to pass between dissections */
static guint32 rnti = -1;
/*
 * defragmentation of DAN_API
 */
static GHashTable *dan_fragment_table = NULL;
static GHashTable *dan_reassembled_table = NULL;

/* External parameters */
extern int proto_mac_lte_dan;

void dissect_dan_lte_sdk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);


/* The following hf_* variables are used to hold the Wireshark IDs of
* our header fields; they are filled out when we call
* proto_register_field_array() in proto_register_dan_lte_sdk()
*/

/* DAN pi-e header*/
static gint hf_dan_lte_sdk_pi_e_header_type = -1;
static gint hf_dan_lte_sdk_pi_e_header_seq = -1;
static gint hf_dan_lte_sdk_pi_e_header_size = -1;
static gint hf_dan_lte_sdk_pi_e_header_frag = -1;
static gint hf_dan_lte_sdk_pi_e_header_nf = -1;
static gint hf_dan_lte_sdk_pi_e_header_nsf = -1;

/* DAN msg header */
static gint hf_dan_lte_sdk_msg_header_seq = -1;
static gint hf_dan_lte_sdk_msg_header_type = -1;
static gint hf_dan_lte_sdk_msg_header_ack_req = -1;
static gint hf_dan_lte_sdk_msg_header_size = -1;
static gint hf_dan_lte_sdk_msg_header_nf = -1;
static gint hf_dan_lte_sdk_msg_header_nsf = -1;
static gint hf_dan_lte_sdk_msg_header_sector_id = -1;
static gint hf_dan_lte_sdk_msg_header_rsrv = -1;

/* DAN msg data (DAN_E_AIRDL_PDSCH_REQ) */
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_num_of_tbs = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_reserve0 = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_tb_idx = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_reserve1 = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_rnti = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_tb_size = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_n_rb = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_rb_bitmap = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_ant_mode = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_pa = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_mcs = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_pdsch_boost_index = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_rv_idx = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_pmi_codebook_idx = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_rank = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_n_codework = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_codeword_id = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_k_mimo = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_mimo_id = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_ue_category = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_reserve2 = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_p_data = -1;

/* DAN msg data (DAN_E_AIRDL_PDSCH_DATA_ELMS_REQ) */
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_num_of_tbs = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_reserve0 = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_tb_idx = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_reserve1 = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_reserve2 = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_tb_size = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_chunk_data = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_tb_data = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_num_of_data_chunks = -1;

/* DAN msg data (DAN_E_AIRDL_PDCCH_REQ) */
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_n_ue = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_reserve0 = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_rnti = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_cce_offset = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_reserve1 = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_pdcch_format = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_dci_format = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_antenna_selection = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_pdcch_boost = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_pdsch_boost_index = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload_length = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_reserve2 = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload_64b = -1;

/* Payload Bits Format 1/2/2A */
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_TB1 = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_TYPE = -1;

/* Payload Bits Format 1/2/2A (1.4MHz) */
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_1_4M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_MCS_1_4M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_HARQ_1_4M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_NDI_1_4M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_RV_1_4M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_TPC_1_4M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_TPC_1_4M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_HARQ_1_4M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_SWAP_1_4M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS0_1_4M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI0_1_4M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV0_1_4M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_1_4M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI1_1_4M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV1_1_4M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_PRECODING_1_4M = -1;

/* Payload Bits Format 1/2/2A (3MHz) */
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_MCS_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_HARQ_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_NDI_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_RV_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_TPC_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_REST_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_TPC_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_HARQ_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_SWAP_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS0_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI0_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV0_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI1_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV1_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_PRECODING1_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_PRECODING2_3M = -1;

/* Payload Bits Format 1/2/2A (5MHz) */
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_MCS_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_HARQ_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_NDI_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_RV_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_TPC_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_TPC_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_HARQ_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_SWAP_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS0_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI0_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV0_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_0_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_1_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI1_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV1_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_PRECODING_5M = -1;

/* Payload Bits Format 1/2/2A (10MHz) */
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_MCS_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_HARQ_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_NDI_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_RV_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_TPC_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_TPC_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_HARQ_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_SWAP_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS0_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI0_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV0_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI1_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV1_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2A_REST_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_PRECODING_10M = -1;

/* Payload Bits Format 1/2/2A (15MHz) */
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_15M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_MCS_15M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_HARQ_15M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_NDI_15M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_RV_15M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_TPC1_15M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_TPC2_15M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_TPC_15M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_HARQ_15M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_SWAP_15M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS0_15M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI0_15M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV0_15M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_15M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI1_15M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV1_15M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_PRECODING_15M = -1;

/* Payload Bits Format 1/2/2A (20MHz) */
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_20M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_MCS_20M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_HARQ1_20M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_HARQ2_20M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_NDI_20M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_RV_20M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_TPC_20M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_TPC_20M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_HARQ_20M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_SWAP_20M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS0_20M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI0_20M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV0_20M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_20M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI1_20M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV1_20M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_PRECODING_20M = -1;

/* Payload Bits Format 0/1A */
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_TYPE = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_ALLOCATION = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_HOPPING = -1;

/* Payload Bits Format 0/1A (1.4MHz) */
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_RIV_1_4M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_MCS_1_4M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_COUNTER_1_4M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_NDI_1_4M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_RV_1_4M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_TPC_1_4M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_REST_1_4M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_NDI_1_4M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_TPC_1_4M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CYCSHIFT_1_4M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CQI_1_4M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_REST_1_4M = -1;

/* Payload Bits Format 0/1A (3MHz) */
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_RIV_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_MCS_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_COUNTER_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_NDI_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_RV_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_TPC_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_NDI_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_TPC_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CYCSHIFT_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CQI_3M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_REST_3M = -1;

/* Payload Bits Format 0/1A (5MHz) */
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_RIV_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_MCS_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_COUNTER_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_NDI_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_RV_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_TPC_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_REST_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_NDI_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_TPC_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CYCSHIFT_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CQI_5M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_REST_5M = -1;

/* Payload Bits Format 0/1A (10MHz) */
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_RIV_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_MCS_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_COUNTER_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_NDI_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_RV_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_TPC_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_REST_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_NDI_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_TPC_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CYCSHIFT_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CQI_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_REST_10M = -1;

/* Payload Bits Format 0/1A (15MHz) */
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_RIV_15M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_MCS_15M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_COUNTER_15M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_NDI_15M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_RV_15M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_TPC_15M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_NDI_15M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_TPC_15M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CYCSHIFT_15M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CQI_15M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_REST_15M = -1;

/* Payload Bits Format 0/1A (20MHz) */
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_RIV_20M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_MCS_20M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_COUNTER_20M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_NDI_20M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_RV_20M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_TPC_20M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_NDI_20M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_TPC_20M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CYCSHIFT_20M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CQI_20M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_REST_20M = -1;

/* Payload Bits Format 3 (10MHz) */
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P3_TPC_10M = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P3_REST_10M = -1;

/* PHICH Request (DAN_AIRDL_PHICH_REQ) */
static gint hf_dan_lte_sdk_msg_AIRDL_PHICH_REQ_n_ue = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PHICH_REQ_reserve1 = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PHICH_REQ_reserve2 = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PHICH_REQ_group_id = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PHICH_REQ_ack_nack = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PHICH_REQ_seq_idx = -1;
static gint hf_dan_lte_sdk_msg_AIRDL_PHICH_REQ_reserve3 = -1;


/* DAN TTI evt (DAN_E_TTI_EVT) */
static gint hf_dan_lte_sdk_msg_TTI_EVT_nf = -1;
static gint hf_dan_lte_sdk_msg_TTI_EVT_nsf = -1;
static gint hf_dan_lte_sdk_msg_TTI_EVT_reserve = -1;

/* DAN EVT (SYS_START_RSP) Message */
static gint hf_dan_lte_sdk_msg_SYS_START_RSP_err_code = -1;

/* DAN msg data (DAN_E_PUSCH_TB_DSC) */
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_rnti = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_MCS = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_rank = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_rb_start = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_rb_num = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_harq_rv = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_ul_harq_chan_id = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_dl_harq_chan_id = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_n2dmrs = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_harq_re_tx = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_cqi_nbits = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_pucch_indication = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_ri_nbits = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_acknack_nbits = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_beta_offset_acknack = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_beta_offset_cqi = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_beta_offset_ri = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_acknack_bo = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_cqi_bo = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_ri_bo = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_rb_num_init = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_srs_init = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_MCS_init = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_tb_size = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_uci_format = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_crc_data = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_srs_present = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_reserved = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_reserved1 = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_reserved2 = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_user_data = -1;
static gint hf_dan_lte_sdk_msg_PUSCH_TB_DSC_p_data = -1;

/* DAN msg data (DAN_AIRUL_PUSCH_REQ) */
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_REQ_n1dmrs = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_REQ_n_ue = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_REQ_reserved = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_REQ_ue_dsc = -1;

/* DAN msg data (DAN_AIRUL_PUSCH_EVT) */
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_n_ue = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_reserved = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_rnti = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_n_rb = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_rank = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_timing_offset = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_c2i = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_tb_size = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_RSSI = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_data_present = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_crc_detect = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_sigma_kr = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_ec2i = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_user_data = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_p_data = -1;

/* DAN msg data (DAN_AIRUL_PUSCH_CTRL_EVT) */
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_n_ue = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_reserved = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_rnti = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_ack_nack_presence = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_ack_nack = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_dl_harq_chan_id = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_ri_presence = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_ri = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_reseved2 = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_cqi_presence = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_uci_format = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_Payload = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_uci_format_yosi = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_Payload_yosi = -1;

/* DAN msg data (DAN_AIRUL_PUSCH_MEAS_EVT) */
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_avg_rssi = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_avg_ant1_rssi = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_avg_ant2_rssi = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_avg_ant3_rssi = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_avg_ant4_rssi = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_avg_c2i = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_avg_ni = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_n_ue = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_n_tb = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_n_tb_crc = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_reserved = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_reserved2 = -1;

/* DAN msg data (DAN_AIRUL_PUCCH_EVT) */
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_n_ue = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_error_indication = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_reserved = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_rnti = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_n_pucch_sr = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_ack_nack_presence = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_ack_nack = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_SR = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_dl_harq_chan_id = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_reserved2 = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_RSSI= -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_C2I = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_STO = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_n_pucch_an_cqi = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_pucch_format = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_cqi_presence = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_uci_format = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_Payload = -1;


/*DAN msg data (DAN_E_AIRUL_PUCCH_REQ)  */
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_n_rb = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_delta_pucch_shift = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_n_rb_cqi = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_n_cs_an = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_n_pucch_req = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_srs_present = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_reserve = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_rnti = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_n_pucch_sr = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_pucch_format = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_uci_format = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_thr = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_dl_harq_chan_id = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_n_pucch_an_cqi = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_cqi_n_bits = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_reserve2 = -1;

/* DAN msg data (DAN_CFG_GET_REQ) */
static gint hf_dan_lte_sdk_msg_CFG_GET_REQ_param_id = -1;
static gint hf_dan_lte_sdk_msg_CFG_GET_REQ_param_type = -1;
static gint hf_dan_lte_sdk_msg_CFG_GET_REQ_index = -1;
static gint hf_dan_lte_sdk_msg_CFG_GET_REQ_reserved = -1;

/* DAN msg data (DAN_CFG_PARAM_DSC) */
static gint hf_dan_lte_sdk_msg_CFG_PARAM_DSC_param_type = -1;

/* DAN msg data (DAN_CFG_PARAM_DATA_DSC) */
static gint hf_dan_lte_sdk_msg_CFG_PARAM_DATA_DSC_param_id = -1;
static gint hf_dan_lte_sdk_msg_CFG_PARAM_DATA_DSC_index = -1;
static gint hf_dan_lte_sdk_msg_CFG_PARAM_DATA_DSC_reserved = -1;
//static gint hf_dan_lte_sdk_msg_CFG_PARAM_DATA_DSC_value = -1;

/* DAN msg data (DAN_CFG_PARAM_NUM_DSC) */
static gint hf_dan_lte_sdk_msg_CFG_PARAM_NUM_DSC_param_id = -1;
static gint hf_dan_lte_sdk_msg_CFG_PARAM_NUM_DSC_value = -1;
static gint hf_dan_lte_sdk_msg_CFG_PARAM_NUM_DSC_index = -1;
static gint hf_dan_lte_sdk_msg_CFG_PARAM_NUM_DSC_reserved = -1;

/* DAN msg data (DAN_CFG_PARAM_NUM_DSC) */
static gint hf_dan_lte_sdk_msg_CFG_PARAM_NUM_ARR_DSC_param_id = -1;
static gint hf_dan_lte_sdk_msg_CFG_PARAM_NUM_ARR_DSC_start_index = -1;
static gint hf_dan_lte_sdk_msg_CFG_PARAM_NUM_ARR_DSC_num_of_params = -1;
static gint hf_dan_lte_sdk_msg_CFG_PARAM_NUM_ARR_DSC_values = -1;

/* DAN msg data (DAN_T_MSG_COMMON_ERR_CODE) */
static gint hf_dan_lte_sdk_msg_COMMON_ERR_CODE_type = -1;
static gint hf_dan_lte_sdk_msg_COMMON_ERR_CODE_msg_type = -1;
static gint hf_dan_lte_sdk_msg_COMMON_ERR_CODE_msg_seq = -1;
static gint hf_dan_lte_sdk_msg_COMMON_ERR_CODE_user_data = -1;

/*DAN msg data (DAN_E_AIRUL_PRACH_REQ)  */
static gint hf_dan_lte_sdk_msg_AIRUL_PRACH_REQ_logical_root_sn = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PRACH_REQ_prach_conf_index = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PRACH_REQ_Ncs = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PRACH_REQ_prach_req_offset = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PRACH_REQ_highSpeedFlag = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PRACH_REQ_prach_format = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PRACH_REQ_thr = -1;

/*DAN msg data (DAN_E_AIRUL_PRACH_RSP)  */
static gint hf_dan_lte_sdk_msg_AIRUL_PRACH_RSP_num_preambles = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PRACH_RSP_error_indication = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PRACH_RSP_reserve = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PRACH_RSP_preambles = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PRACH_RSP_preamble_id = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PRACH_RSP_detection_metric = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PRACH_RSP_timing_offset = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PRACH_RSP_RTWP = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_PRACH_RSP_reserve2 = -1;

/* DAN msg data (DAN_SRS_DSC) */
static gint hf_dan_lte_sdk_msg_SRS_DSC_rnti = -1;
static gint hf_dan_lte_sdk_msg_SRS_DSC_cs_srs = -1;
static gint hf_dan_lte_sdk_msg_SRS_DSC_nap = -1;
static gint hf_dan_lte_sdk_msg_SRS_DSC_boosting = -1;
static gint hf_dan_lte_sdk_msg_SRS_DSC_rb_start = -1;
static gint hf_dan_lte_sdk_msg_SRS_DSC_b_srs = -1;
static gint hf_dan_lte_sdk_msg_SRS_DSC_trans_comb = -1;
static gint hf_dan_lte_sdk_msg_SRS_DSC_reserved = -1;

/* DAN msg data (DAN_AIRUL_SRS_REQ) */
static gint hf_dan_lte_sdk_msg_AIRUL_SRS_REQ_n_srs = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_SRS_REQ_reserved = -1;

/* DAN msg data (SRS_DECODED_DSC) */
static gint hf_dan_lte_sdk_msg_SRS_DECODED_DSC_rnti = -1;
static gint hf_dan_lte_sdk_msg_SRS_DECODED_DSC_rbg_indx = -1;
static gint hf_dan_lte_sdk_msg_SRS_DECODED_DSC_reserved = -1;
static gint hf_dan_lte_sdk_msg_SRS_DECODED_DSC_ch_state_mag[] = {-1, -1, -1, -1};
static gint hf_dan_lte_sdk_msg_SRS_DECODED_DSC_ch_state_phase[] = {-1, -1, -1, -1};

/* DAN msg data (DAN_AIRUL_SRS_EVT) */
static gint hf_dan_lte_sdk_msg_AIRUL_SRS_EVT_n_srs = -1;
static gint hf_dan_lte_sdk_msg_AIRUL_SRS_EVT_reserved = -1;

/* DAN msg data (DAN_BUF) */
static gint hf_dan_lte_sdk_msg_DAN_BUF_size = -1;
static gint hf_dan_lte_sdk_msg_DAN_BUF_data = -1;

/* -------- MAC Layers Dissecting ------ */

/* MAC header 4 bytes */
static gint hf_dan_lte_msg_MAC_MAC_HEADER_4byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_R1_4byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_R2_4byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_E_4byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_LCID_4byte = -1;
static gint hf_dan_lte_msg_MAC_7bitMAC_Length_4byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_F_4byte = -1;
static gint hf_dan_lte_msg_MAC_15bitMAC_Length_4byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_R1_7_4byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_R2_7_4byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_E_7_4byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_LCID_7_4byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_R1_15_4byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_R2_15_4byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_E_15_4byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_LCID_15_4byte = -1;

/* MAC header 3 Bytes */
static gint hf_dan_lte_msg_MAC_MAC_HEADER_3byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_R1_3byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_R2_3byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_E_3byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_LCID_3byte = -1;
static gint hf_dan_lte_msg_MAC_7bitMAC_Length_3byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_F_3byte = -1;
static gint hf_dan_lte_msg_MAC_15bitMAC_Length_3byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_R1_7_3byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_R2_7_3byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_E_7_3byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_LCID_7_3byte = -1;

/* MAC header 2 Bytes */
static gint hf_dan_lte_msg_MAC_MAC_HEADER_2byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_R1_2byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_R2_2byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_E_2byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_LCID_2byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_F_2byte = -1;
static gint hf_dan_lte_msg_MAC_7bitMAC_Length_2byte = -1;

/* MAC header 1 byte (Padding) */
static gint hf_dan_lte_msg_MAC_MAC_HEADER_1byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_R1_1byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_R2_1byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_E_1byte = -1;
static gint hf_dan_lte_msg_MAC_MAC_LCID_1byte = -1;


/* RLC Header 4 Byte */
static gint hf_dan_lte_msg_MAC_10bitRLC_HEADER_4byte = -1;
static gint hf_dan_lte_msg_MAC_10bitRLC_R1_4byte = -1;
static gint hf_dan_lte_msg_MAC_10bitRLC_R2_4byte = -1;
static gint hf_dan_lte_msg_MAC_10bitRLC_R3_4byte = -1;
static gint hf_dan_lte_msg_MAC_10bitRLC_FI_4byte = -1;
static gint hf_dan_lte_msg_MAC_10bitRLC_E1_4byte = -1;
static gint hf_dan_lte_msg_MAC_10bitRLC_SN_4byte = -1;
static gint hf_dan_lte_msg_MAC_10bitRLC_E2_4byte = -1;
static gint hf_dan_lte_msg_MAC_10bitRLC_LI1_4byte = -1;
static gint hf_dan_lte_msg_MAC_10bitRLC_PADD_4byte = -1;
static gint hf_dan_lte_msg_MAC_10bitRLC_E3_4byte = -1;
static gint hf_dan_lte_msg_MAC_10bitRLC_LI2_4byte = -1;

/* RLC Sub-Header */
static gint hf_dan_lte_msg_MAC_10bitRLC_Sub_Header = -1;
static gint hf_dan_lte_msg_MAC_10bitRLC_E_12bit = -1;
static gint hf_dan_lte_msg_MAC_10bitRLC_LI_12bit = -1;

/* RLC Sub-Header */
static gint hf_dan_lte_msg_MAC_10bitRLC_E_16bit = -1;
static gint hf_dan_lte_msg_MAC_10bitRLC_LI_16bit = -1;
static gint hf_dan_lte_msg_MAC_10bitRLC_PADD_16bit = -1;

/* RLC Header 2 Byte */
static gint hf_dan_lte_msg_MAC_10bitRLC_HEADER_2byte = -1;
static gint hf_dan_lte_msg_MAC_10bitRLC_R1_2byte = -1;
static gint hf_dan_lte_msg_MAC_10bitRLC_R2_2byte = -1;
static gint hf_dan_lte_msg_MAC_10bitRLC_R3_2byte = -1;
static gint hf_dan_lte_msg_MAC_10bitRLC_FI_2byte = -1;
static gint hf_dan_lte_msg_MAC_10bitRLC_E1_2byte = -1;
static gint hf_dan_lte_msg_MAC_10bitRLC_SN_2byte = -1;

/*If can't dissect show data as whole*/
static gint hf_dan_lte_msg_MAC_10bitRLC_data = -1;

/*PDCP Header */
static gint hf_dan_lte_msg_MAC_12bitPDCP_DC= -1;
static gint hf_dan_lte_msg_MAC_12bitPDCP_R1= -1;
static gint hf_dan_lte_msg_MAC_12bitPDCP_R2= -1;
static gint hf_dan_lte_msg_MAC_12bitPDCP_R3= -1;
static gint hf_dan_lte_msg_MAC_12bitPDCP_SN= -1;

/* ------------------------------------- */

/* Fragmentation hf */
static gint hf_msg_fragments = -1;
static gint hf_msg_fragment = -1;
static gint hf_msg_fragment_overlap = -1;
static gint hf_msg_fragment_overlap_conflicts = -1;
static gint hf_msg_fragment_multiple_tails = -1;
static gint hf_msg_fragment_too_long_fragment = -1;
static gint hf_msg_fragment_error = -1;
static gint hf_msg_fragment_count = -1;
static gint hf_msg_reassembled_in = -1;
static gint hf_msg_reassembled_length = -1;

/* These are the ids of the subtrees that we may be creating */
static gint ett_dan_lte_sdk_pi_e_header = -1;
static gint ett_dan_lte_sdk_msg_header = -1;
static gint ett_dan_lte_sdk_msg_data = -1;
static gint ett_dan_lte_sdk_msg_data_subtree1 = -1;
static gint ett_dan_lte_sdk_msg_data_subtree2 = -1;
static gint ett_dan_lte_sdk_msg_data_subtree3 = -1;
static gint ett_dan_lte_sdk_msg_data_subtree4 = -1;
static gint ett_msg_fragment = -1;
static gint ett_msg_fragments = -1;

static const fragment_items dan_frag_items = {
	/* Fragment subtrees */
	&ett_msg_fragment,
	&ett_msg_fragments,
	/* Fragment fields */
	&hf_msg_fragments,
	&hf_msg_fragment,
	&hf_msg_fragment_overlap,
	&hf_msg_fragment_overlap_conflicts,
	&hf_msg_fragment_multiple_tails,
	&hf_msg_fragment_too_long_fragment,
	&hf_msg_fragment_error,
	&hf_msg_fragment_count,
	/* Reassembled in field */
	&hf_msg_reassembled_in,
	/* Reassembled length field */
	&hf_msg_reassembled_length,
	/* Tag */
	"Message fragments"
};
#endif