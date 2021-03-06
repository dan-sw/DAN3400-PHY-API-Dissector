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
/* Routines for LTE MAC disassembly
 *
 * Martin Mathieson
 *
 * $Id: packet-mac-lte.c 34061 2010-09-03 16:45:05Z martinm $
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/uat.h>

#include "packet-mac-lte-dan.h"
#include "packet-rlc-lte-dan.h"


/* Described in:
 * 3GPP TS 36.321 Evolved Universal Terrestrial Radio Access (E-UTRA)
 *                Medium Access Control (MAC) protocol specification (Release 8)
 */


/* TODO:
   - TDD mode?
   - add a preference so that padding can be verified against an expected pattern?
*/

/* Initialize the protocol and registered fields. */
int proto_mac_lte_dan = -1;

static int mac_lte_tap = -1;

/* Decoding context */
static int hf_mac_lte_context = -1;
static int hf_mac_lte_context_radio_type = -1;
static int hf_mac_lte_context_direction = -1;
static int hf_mac_lte_context_rnti = -1;
static int hf_mac_lte_context_rnti_type = -1;
static int hf_mac_lte_context_ueid = -1;
static int hf_mac_lte_context_subframe_number = -1;
static int hf_mac_lte_context_grant_subframe_number = -1;
static int hf_mac_lte_context_predefined_frame = -1;
static int hf_mac_lte_context_length = -1;
static int hf_mac_lte_context_ul_grant_size = -1;
static int hf_mac_lte_context_bch_transport_channel = -1;
static int hf_mac_lte_context_retx_count = -1;
static int hf_mac_lte_context_crc_status = -1;
static int hf_mac_lte_context_rapid = -1;
static int hf_mac_lte_context_rach_attempt_number = -1;

/* Extra PHY context */
static int hf_mac_lte_context_phy_ul = -1;
static int hf_mac_lte_context_phy_ul_modulation_type = -1;
static int hf_mac_lte_context_phy_ul_tbs_index = -1;
static int hf_mac_lte_context_phy_ul_resource_block_length = -1;
static int hf_mac_lte_context_phy_ul_resource_block_start = -1;

static int hf_mac_lte_context_phy_dl = -1;
static int hf_mac_lte_context_phy_dl_dci_format = -1;
static int hf_mac_lte_context_phy_dl_resource_allocation_type = -1;
static int hf_mac_lte_context_phy_dl_aggregation_level = -1;
static int hf_mac_lte_context_phy_dl_mcs_index = -1;
static int hf_mac_lte_context_phy_dl_redundancy_version_index = -1;
static int hf_mac_lte_context_phy_dl_retx = -1;
static int hf_mac_lte_context_phy_dl_resource_block_length = -1;
static int hf_mac_lte_context_phy_dl_crc_status = -1;


/* Out-of-band events */
static int hf_mac_lte_oob_send_preamble = -1;
static int hf_mac_lte_oob_send_sr = -1;
static int hf_mac_lte_oob_sr_failure = -1;

/* MAC SCH header fields */
static int hf_mac_lte_ulsch = -1;
static int hf_mac_lte_ulsch_header = -1;
static int hf_mac_lte_dlsch = -1;
static int hf_mac_lte_dlsch_header = -1;
static int hf_mac_lte_sch_subheader = -1;

static int hf_mac_lte_sch_reserved = -1;
static int hf_mac_lte_dlsch_lcid = -1;
static int hf_mac_lte_ulsch_lcid = -1;
static int hf_mac_lte_sch_extended = -1;
static int hf_mac_lte_sch_format = -1;
static int hf_mac_lte_sch_length = -1;

static int hf_mac_lte_sch_header_only = -1;

/* Data */
static int hf_mac_lte_sch_sdu = -1;
static int hf_mac_lte_bch_pdu = -1;
static int hf_mac_lte_pch_pdu = -1;
static int hf_mac_lte_predefined_pdu = -1;
static int hf_mac_lte_raw_pdu = -1;
static int hf_mac_lte_padding_data = -1;
static int hf_mac_lte_padding_length = -1;


/* RAR fields */
static int hf_mac_lte_rar = -1;
static int hf_mac_lte_rar_headers = -1;
static int hf_mac_lte_rar_header = -1;
static int hf_mac_lte_rar_extension = -1;
static int hf_mac_lte_rar_t = -1;
static int hf_mac_lte_rar_bi = -1;
static int hf_mac_lte_rar_rapid = -1;
static int hf_mac_lte_rar_reserved = -1;
static int hf_mac_lte_rar_body = -1;
static int hf_mac_lte_rar_reserved2 = -1;
static int hf_mac_lte_rar_ta = -1;
static int hf_mac_lte_rar_ul_grant = -1;
static int hf_mac_lte_rar_ul_grant_hopping = -1;
static int hf_mac_lte_rar_ul_grant_fsrba = -1;
static int hf_mac_lte_rar_ul_grant_tmcs = -1;
static int hf_mac_lte_rar_ul_grant_tcsp = -1;
static int hf_mac_lte_rar_ul_grant_ul_delay = -1;
static int hf_mac_lte_rar_ul_grant_cqi_request = -1;
static int hf_mac_lte_rar_temporary_crnti = -1;

/* Common channel control values */
static int hf_mac_lte_control_bsr = -1;
static int hf_mac_lte_control_bsr_lcg_id = -1;
static int hf_mac_lte_control_short_bsr_buffer_size = -1;
static int hf_mac_lte_control_long_bsr_buffer_size_0 = -1;
static int hf_mac_lte_control_long_bsr_buffer_size_1 = -1;
static int hf_mac_lte_control_long_bsr_buffer_size_2 = -1;
static int hf_mac_lte_control_long_bsr_buffer_size_3 = -1;
static int hf_mac_lte_control_crnti = -1;
static int hf_mac_lte_control_timing_advance = -1;
static int hf_mac_lte_control_timing_advance_reserved = -1;
static int hf_mac_lte_control_ue_contention_resolution = -1;
static int hf_mac_lte_control_ue_contention_resolution_identity = -1;
static int hf_mac_lte_control_ue_contention_resolution_msg3 = -1;
static int hf_mac_lte_control_ue_contention_resolution_msg3_matched = -1;
static int hf_mac_lte_control_ue_contention_resolution_time_since_msg3 = -1;
static int hf_mac_lte_control_power_headroom = -1;
static int hf_mac_lte_control_power_headroom_reserved = -1;
static int hf_mac_lte_control_power_headroom_level = -1;
static int hf_mac_lte_control_padding = -1;

static int hf_mac_lte_suspected_dl_retx_original_frame = -1;

static int hf_mac_lte_ul_harq_resend_original_frame = -1;

static int hf_mac_lte_grant_answering_sr = -1;
static int hf_mac_lte_failure_answering_sr = -1;
static int hf_mac_lte_sr_leading_to_failure = -1;
static int hf_mac_lte_sr_leading_to_grant = -1;
static int hf_mac_lte_sr_invalid_event = -1;
static int hf_mac_lte_sr_time_since_request = -1;
static int hf_mac_lte_sr_time_until_answer = -1;


/* Subtrees. */
static int ett_mac_lte = -1;
static int ett_mac_lte_context = -1;
static int ett_mac_lte_phy_context = -1;
static int ett_mac_lte_ulsch_header = -1;
static int ett_mac_lte_dlsch_header = -1;
static int ett_mac_lte_sch_subheader = -1;
static int ett_mac_lte_rar_headers = -1;
static int ett_mac_lte_rar_header = -1;
static int ett_mac_lte_rar_body = -1;
static int ett_mac_lte_rar_ul_grant = -1;
static int ett_mac_lte_bsr = -1;
static int ett_mac_lte_bch = -1;
static int ett_mac_lte_pch = -1;
static int ett_mac_lte_contention_resolution = -1;
static int ett_mac_lte_power_headroom = -1;
static int ett_mac_lte_oob = -1;


/* Constants and value strings */

static const value_string radio_type_vals[] =
{
    { FDD_RADIO,      "FDD"},
    { TDD_RADIO,      "TDD"},
    { 0, NULL }
};


static const value_string direction_vals[] =
{
    { DIRECTION_UPLINK,      "Uplink"},
    { DIRECTION_DOWNLINK,    "Downlink"},
    { 0, NULL }
};


static const value_string rnti_type_vals[] =
{
    { NO_RNTI,     "NO-RNTI"},
    { P_RNTI,      "P-RNTI"},
    { RA_RNTI,     "RA-RNTI"},
    { C_RNTI,      "C-RNTI"},
    { SI_RNTI,     "SI-RNTI"},
    { SPS_RNTI,    "SPS-RNTI"},
    { 0, NULL }
};

static const value_string bch_transport_channel_vals[] =
{
    { SI_RNTI,      "DL-SCH"},
    { NO_RNTI,      "BCH"},
    { 0, NULL }
};

static const value_string crc_status_vals[] =
{
    { 0,  "Failed"},
    { 1,  "OK"},
    { 0, NULL }
};


static const value_string dci_format_vals[] =
{
    { 0, "0"},
    { 1, "1"},
    { 2, "1A"},
    { 3, "1B"},
    { 4, "1C"},
    { 5, "1D"},
    { 6, "2"},
    { 7, "2A"},
    { 8, "3/3A"},
    { 0, NULL }
};

static const value_string aggregation_level_vals[] =
{
    { 0, "1"},
    { 1, "2"},
    { 2, "4"},
    { 3, "8"},
    { 0, NULL }
};

static const value_string modulation_type_vals[] =
{
    { 2, "QPSK"},
    { 4, "QAM16"},
    { 6, "QAM64"},
    { 0, NULL }
};


#define UE_CONTENTION_RESOLUTION_IDENTITY_LCID 0x1c
#define TIMING_ADVANCE_LCID                    0x1d
#define DRX_COMMAND_LCID                       0x1e
#define PADDING_LCID                           0x1f

static const value_string dlsch_lcid_vals[] =
{
    { 0,                                        "CCCH"},
    { 1,                                        "1"},
    { 2,                                        "2"},
    { 3,                                        "3"},
    { 4,                                        "4"},
    { 5,                                        "5"},
    { 6,                                        "6"},
    { 7,                                        "7"},
    { 8,                                        "8"},
    { 9,                                        "9"},
    { 10,                                       "10"},
    { UE_CONTENTION_RESOLUTION_IDENTITY_LCID,   "UE Contention Resolution Identity"},
    { TIMING_ADVANCE_LCID                   ,   "Timing Advance"},
    { DRX_COMMAND_LCID                      ,   "DRX Command"},
    { PADDING_LCID                          ,   "Padding" },
    { 0, NULL }
};

#define POWER_HEADROOM_REPORT_LCID    0x1a
#define CRNTI_LCID                    0x1b
#define TRUNCATED_BSR_LCID            0x1c
#define SHORT_BSR_LCID                0x1d
#define LONG_BSR_LCID                 0x1e

static const value_string ulsch_lcid_vals[] =
{
    { 0,                            "CCCH"},
    { 1,                            "1"},
    { 2,                            "2"},
    { 3,                            "3"},
    { 4,                            "4"},
    { 5,                            "5"},
    { 6,                            "6"},
    { 7,                            "7"},
    { 8,                            "8"},
    { 9,                            "9"},
    { 10,                           "10"},
    { POWER_HEADROOM_REPORT_LCID,   "Power Headroom Report"},
    { CRNTI_LCID,                   "C-RNTI"},
    { TRUNCATED_BSR_LCID,           "Truncated BSR"},
    { SHORT_BSR_LCID,               "Short BSR"},
    { LONG_BSR_LCID,                "Long BSR"},
    { PADDING_LCID,                 "Padding" },
    { 0, NULL }
};


static const value_string format_vals[] =
{
    { 0,      "Data length is < 128 bytes"},
    { 1,      "Data length is >= 128 bytes"},
    { 0, NULL }
};


static const value_string rar_type_vals[] =
{
    { 0,      "Backoff Indicator present"},
    { 1,      "RAPID present"},
    { 0, NULL }
};


static const value_string rar_bi_vals[] =
{
    { 0,      "0"},
    { 1,      "10"},
    { 2,      "20"},
    { 3,      "30"},
    { 4,      "40"},
    { 5,      "60"},
    { 6,      "80"},
    { 7,      "120"},
    { 8,      "160"},
    { 9,      "240"},
    { 10,     "320"},
    { 11,     "480"},
    { 12,     "960"},
    { 0, NULL }
};


static const value_string buffer_size_vals[] =
{
    { 0,      "BS = 0"},
    { 1,      "0   < BS <= 10"},
    { 2,      "10  < BS <= 12"},
    { 3,      "12  < BS <= 14"},
    { 4,      "14  < BS <= 17"},
    { 5,      "17  < BS <= 19"},
    { 6,      "19  < BS <= 22"},
    { 7,      "22  < BS <= 26"},
    { 8,      "26  < BS <= 31"},
    { 9,      "31  < BS <= 36"},
    { 10,     "36  < BS <= 42"},
    { 11,     "42  < BS <= 49"},
    { 12,     "49  < BS <= 57"},
    { 13,     "47  < BS <= 67"},
    { 14,     "67  < BS <= 78"},
    { 15,     "78  < BS <= 91"},
    { 16,     "91  < BS <= 107"},
    { 17,     "107 < BS <= 125"},
    { 18,     "125 < BS <= 146"},
    { 19,     "146 < BS <= 171"},
    { 20,     "171 < BS <= 200"},
    { 21,     "200 < BS <= 234"},
    { 22,     "234 < BS <= 274"},
    { 23,     "274 < BS <= 321"},
    { 24,     "321 < BS <= 376"},
    { 25,     "376 < BS <= 440"},
    { 26,     "440 < BS <= 515"},
    { 27,     "515 < BS <= 603"},
    { 28,     "603 < BS <= 706"},
    { 29,     "706 < BS <= 826"},
    { 30,     "826 < BS <= 967"},
    { 31,     "967  < BS <= 1132"},
    { 32,     "1132 < BS <= 1326"},
    { 33,     "1326 < BS <= 1552"},
    { 34,     "1552 < BS <= 1817"},
    { 35,     "1817 < BS <= 2127"},
    { 36,     "2127 < BS <= 2490"},
    { 37,     "2490 < BS <= 2915"},
    { 38,     "2915 < BS <= 3413"},
    { 39,     "3413 < BS <= 3995"},
    { 40,     "3995 < BS <= 4677"},
    { 41,     "4677 < BS <= 5476"},
    { 42,     "5476 < BS <= 6411"},
    { 43,     "6411 < BS <= 7505"},
    { 44,     "7505 < BS <= 8787"},
    { 45,     "8787 < BS <= 10276"},
    { 46,     "10287 < BS <= 12043"},
    { 47,     "12043 < BS <= 14099"},
    { 48,     "14099 < BS <= 16507"},
    { 49,     "16507 < BS <= 19325"},
    { 50,     "19325 < BS <= 22624"},
    { 51,     "22624 < BS <= 26487"},
    { 52,     "26487 < BS <= 31009"},
    { 53,     "31009 < BS <= 36304"},
    { 54,     "36304 < BS <= 42502"},
    { 55,     "42502 < BS <= 49759"},
    { 56,     "49759 < BS <= 58255"},
    { 57,     "58255 < BS <= 68201"},
    { 58,     "68201 < BS <= 79846"},
    { 59,     "79846 < BS <= 93479"},
    { 60,     "93479 < BS <= 109439"},
    { 61,     "109439 < BS <= 128125"},
    { 62,     "128125 < BS <= 150000"},
    { 63,     "BS > 150000"},
    { 0, NULL }
};

static const value_string power_headroom_size_vals[] =
{
    { 0,      "-23 <= PH < -22"},
    { 1,      "-22 <= PH < -21"},
    { 2,      "-21 <= PH < -20"},
    { 3,      "-20 <= PH < -19"},
    { 4,      "-19 <= PH < -18"},
    { 5,      "-18 <= PH < -17"},
    { 6,      "-17 <= PH < -16"},
    { 7,      "-16 <= PH < -15"},
    { 8,      "-15 <= PH < -14"},
    { 9,      "-14 <= PH < -13"},
    { 10,     "-13 <= PH < -12"},
    { 11,     "-12 <= PH < -11"},
    { 12,     "-11 <= PH < -10"},
    { 13,     "-10 <= PH < -9"},
    { 14,     "-9 <= PH < -8"},
    { 15,     "-8 <= PH < -7"},
    { 16,     "-7 <= PH < -6"},
    { 17,     "-6 <= PH < -5"},
    { 18,     "-5 <= PH < -4"},
    { 19,     "-4 <= PH < -3"},
    { 20,     "-3 <= PH < -2"},
    { 21,     "-2 <= PH < -1"},
    { 22,     "-1 <= PH < 0"},
    { 23,     "0 <= PH < 1"},
    { 24,     "1 <= PH < 2"},
    { 25,     "2 <= PH < 3"},
    { 26,     "3 <= PH < 4"},
    { 27,     "4 <= PH < 5"},
    { 28,     "5 <= PH < 6"},
    { 29,     "6 <= PH < 7"},
    { 30,     "7 <= PH < 8"},
    { 31,     "8 <= PH < 9"},
    { 32,     "9 <= PH < 10"},
    { 33,     "10 <= PH < 11"},
    { 34,     "11 <= PH < 12"},
    { 35,     "12 <= PH < 13"},
    { 36,     "13 <= PH < 14"},
    { 37,     "14 <= PH < 15"},
    { 38,     "15 <= PH < 16"},
    { 39,     "16 <= PH < 17"},
    { 40,     "17 <= PH < 18"},
    { 41,     "18 <= PH < 19"},
    { 42,     "19 <= PH < 20"},
    { 43,     "20 <= PH < 21"},
    { 44,     "21 <= PH < 22"},
    { 45,     "22 <= PH < 23"},
    { 46,     "23 <= PH < 24"},
    { 47,     "24 <= PH < 25"},
    { 48,     "25 <= PH < 26"},
    { 49,     "26 <= PH < 27"},
    { 50,     "27 <= PH < 28"},
    { 51,     "28 <= PH < 29"},
    { 52,     "29 <= PH < 30"},
    { 53,     "30 <= PH < 31"},
    { 54,     "31 <= PH < 32"},
    { 55,     "32 <= PH < 33"},
    { 56,     "33 <= PH < 34"},
    { 57,     "34 <= PH < 35"},
    { 58,     "34 <= PH < 36"},
    { 59,     "36 <= PH < 37"},
    { 60,     "37 <= PH < 38"},
    { 61,     "38 <= PH < 39"},
    { 62,     "39 <= PH < 40"},
    { 63,     "PH >= 40"},
    { 0, NULL }
};

static const value_string header_only_vals[] =
{
    { 0,      "MAC PDU Headers and body present"},
    { 1,      "MAC PDU Headers only"},
    { 0, NULL }
};

static const value_string predefined_frame_vals[] =
{
    { 0,      "Real MAC PDU present - will dissect"},
    { 1,      "Predefined frame present - will not dissect"},
    { 0, NULL }
};


/**************************************************************************/
/* Preferences state                                                      */
/**************************************************************************/

/* If this PDU has been NACK'd (by HARQ) more than a certain number of times,
   we trigger an expert warning. */
static gint global_mac_lte_retx_counter_trigger = 3;

/* By default try to decode transparent data (BCH, PCH and CCCH) data using LTE RRC dissector */
static gboolean global_mac_lte_attempt_rrc_decode = TRUE;

/* Whether should attempt to dissect frames failing CRC check */
static gboolean global_mac_lte_dissect_crc_failures = FALSE;

/* Whether should attempt to decode lcid 1&2 SDUs as srb1/2 (i.e. AM RLC) */
static gboolean global_mac_lte_attempt_srb_decode = TRUE;

/* Whether should attempt to track UL HARQ resends */
static gboolean global_mac_lte_attempt_ul_harq_resend_track = TRUE;

/* Threshold for warning in expert info about high BSR values */
static gint global_mac_lte_bsr_warn_threshold = 50; /* default is 19325 -> 22624 */

/* Whether or not to track SRs and related frames */
static gboolean global_mac_lte_track_sr = TRUE;

/* Which layer info to show in the info column */
enum layer_to_show {
    ShowPHYLayer, ShowMACLayer, ShowRLCLayer
};

static gint     global_mac_lte_layer_to_show = (gint)ShowRLCLayer;
static guint8   s_number_of_rlc_pdus_shown = 0;


/***********************************************************************/
/* How to dissect lcid 3-10 (presume drb logical channels)             */

static const value_string drb_lcid_vals[] = {
    { 3,  "LCID 3"},
    { 4,  "LCID 4"},
    { 5,  "LCID 5"},
    { 6,  "LCID 6"},
    { 7,  "LCID 7"},
    { 8,  "LCID 8"},
    { 9,  "LCID 9"},
    { 10, "LCID 10"},
    { 0, NULL }
};

typedef enum rlc_channel_type_t {
    rlcRaw,
    rlcTM,
    rlcUM5,
    rlcUM10,
    rlcAM
} rlc_channel_type_t;

static const value_string rlc_channel_type_vals[] = {
    { rlcTM,    "TM"},
    { rlcUM5 ,  "UM, SN Len=5"},
    { rlcUM10,  "UM, SN Len=10"},
    { rlcAM  ,  "AM"},
    { 0, NULL }
};


/* Mapping type */
typedef struct drb_mapping_t {
    guint16 lcid;
    gint drbid;
    rlc_channel_type_t channel_type;
} lcid_drb_mapping_t;

/* Mapping entity */
static lcid_drb_mapping_t *lcid_drb_mappings = NULL;
static guint num_lcid_drb_mappings = 0;

UAT_VS_DEF(lcid_drb_mappings, lcid, lcid_drb_mapping_t, 3, "LCID 3")
UAT_DEC_CB_DEF(lcid_drb_mappings, drbid, lcid_drb_mapping_t)
UAT_VS_DEF(lcid_drb_mappings, channel_type, lcid_drb_mapping_t, 2, "AM")

/* UAT object */
static uat_t* lcid_drb_mappings_uat;

extern int proto_rlc_lte_dan;

/***************************************************************/



/***************************************************************/
/* Keeping track of Msg3 bodies so they can be compared with   */
/* Contention Resolution bodies.                               */

typedef struct Msg3Data {
    guint8   data[6];
    nstime_t msg3Time;
    guint32  framenum;
} Msg3Data;


/* This table stores (RNTI -> Msg3Data*).  Will be populated when
   Msg3 frames are first read.  */
static GHashTable *mac_lte_msg3_hash = NULL;

/* Hash table functions for mac_lte_msg3_hash.  Hash is just the (RNTI) key */
static gint mac_lte_rnti_hash_equal(gconstpointer v, gconstpointer v2)
{
    return (v == v2);
}

static guint mac_lte_rnti_hash_func(gconstpointer v)
{
    return GPOINTER_TO_UINT(v);
}



typedef enum ContentionResolutionStatus {
    NoMsg3,
    Msg3Match,
    Msg3NoMatch
} ContentionResolutionStatus;

typedef struct ContentionResolutionResult {
    ContentionResolutionStatus status;
    guint                      msg3FrameNum;
    guint                      msSinceMsg3;
} ContentionResolutionResult;


/* This table stores (CRFrameNum -> CRResult).  It is assigned during the first
   pass and used thereafter */
static GHashTable *mac_lte_cr_result_hash = NULL;

/* Hash table functions for mac_lte_cr_result_hash.  Hash is just the (framenum) key */
static gint mac_lte_framenum_hash_equal(gconstpointer v, gconstpointer v2)
{
    return (v == v2);
}

static guint mac_lte_framenum_hash_func(gconstpointer v)
{
    return GPOINTER_TO_UINT(v);
}

/**************************************************************************/



/****************************************************************/
/* Keeping track of last DL frames per C-RNTI so can guess when */
/* there has been a HARQ retransmission                         */

/* Could be bigger, but more than enough to flag suspected resends */
#define MAX_EXPECTED_PDU_LENGTH 2048

typedef struct LastFrameData {
    gboolean inUse;
    guint32  framenum;
    guint    subframeNumber;
    nstime_t received_time;
    gint     length;
    guint8   data[MAX_EXPECTED_PDU_LENGTH];
} LastFrameData;

typedef struct LastFrameDataAllSubframes {
    LastFrameData subframe[10];
} LastFrameDataAllSubframes;


/* This table stores (RNTI -> LastFrameDataAllSubframes*).  Will be populated when
   DL frames are first read.  */
static GHashTable *mac_lte_dl_harq_hash = NULL;

typedef struct DLHARQResult {
    guint       previousFrameNum;
} DLHARQResult;


/* This table stores (FrameNumber -> DLHARQResult).  It is assigned during the first
   pass and used thereafter */
static GHashTable *mac_lte_dl_harq_result_hash = NULL;

/**************************************************************************/


/*****************************************************************/
/* Keeping track of last UL frames per C-RNTI so can verify when */
/* told that a frame is a retx                                   */

/* This table stores (RNTI -> LastFrameDataAllSubframes*).  Will be populated when
   UL frames are first read.  */
static GHashTable *mac_lte_ul_harq_hash = NULL;

typedef struct ULHARQResult {
    guint       previousFrameNum;
} ULHARQResult;


/* This table stores (CRFrameNum -> ULHARQResult).  It is assigned during the first
   pass and used thereafter */
static GHashTable *mac_lte_ul_harq_result_hash = NULL;

/**************************************************************************/


/**************************************************************************/
/* Tracking of Scheduling Requests (SRs).                                 */
/* Keep track of:                                                         */
/* - last grant before SR                                                 */
/* - SR failures following request                                        */
/* - grant following SR                                                   */

typedef enum SREvent {
    SR_Grant,
    SR_Request,
    SR_Failure
} SREvent;

static const value_string sr_event_vals[] =
{
    { SR_Grant,        "Grant"},
    { SR_Request,      "SR Request"},
    { SR_Failure,      "SR Failure"},
    { 0,               NULL}
};


typedef enum SRStatus {
    None,
    SR_Outstanding,
    SR_Failed
} SRStatus;

static const value_string sr_status_vals[] =
{
    { None,                "Receiving grants"},
    { SR_Outstanding,      "SR Request outstanding"},
    { SR_Failed,           "SR has Failed"},
    { 0,                   NULL}
};


typedef struct SRState {
    SRStatus status;
    guint32  lastSRFramenum;
    guint32  lastGrantFramenum;
    nstime_t requestTime;
} SRState;


/* This table keeps track of the SR state for each UE.
   (RNTI -> SRState) */
static GHashTable *mac_lte_ue_sr_state = NULL;


typedef enum SRResultType {
    GrantAnsweringSR,
    FailureAnsweringSR,
    SRLeadingToGrant,
    SRLeadingToFailure,
    InvalidSREvent
} SRResultType;


typedef struct SRResult {
    SRResultType type;
    guint32      frameNum;
    guint32      timeDifference;

    /* These 2 are only used with InvalidSREvent */
    SRStatus     status;
    SREvent      event;
} SRResult;

/* Entries in this table are created during the first pass
   It maps (SRFrameNum -> SRResult) */
static GHashTable *mac_lte_sr_request_hash = NULL;


/**************************************************************************/
#if 0//Yosi
const gchar*
match_strval_idx(const guint32 val, const value_string *vs, gint *idx) {
  gint i = 0;

  if(vs) {
    while (vs[i].strptr) {
      if (vs[i].value == val) {
        *idx = i;
        return(vs[i].strptr);
      }
      i++;
    }
  }

  *idx = -1;
  return NULL;
}

/* Like match_strval_idx(), but doesn't return the index. */
const gchar*
match_strval(const guint32 val, const value_string *vs) {
    gint ignore_me;
    return match_strval_idx(val, vs, &ignore_me);
}

const gchar*
val_to_str(const guint32 val, const value_string *vs, const char *unknown_str) {
  const gchar *ret;

  g_assert(unknown_str != NULL);

  ret = match_strval(val, vs);
  if (ret != NULL)
    return ret;

  return unknown_str;
}

#endif//Yosi


/* Forward declarations */
void proto_reg_handoff_mac_lte(void);
void dissect_mac_lte(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);


/* Heuristic dissection */
static gboolean global_mac_lte_heur = FALSE;

static void call_with_catch_all(dissector_handle_t handle, tvbuff_t* tvb, packet_info *pinfo, proto_tree *tree)
{

    /* Call it (catch exceptions so that stats will be updated) */
    TRY {
        call_dissector_only(handle, tvb, pinfo, tree);
    }
    CATCH_ALL {
    }
    ENDTRY
}

/* Heuristic dissector looks for supported framing protocol (see wiki page)  */
static gboolean dissect_mac_lte_heur(tvbuff_t *tvb, packet_info *pinfo,
                                     proto_tree *tree)
{
    gint                 offset = 0;
    struct mac_lte_info  *p_mac_lte_info;
    tvbuff_t             *mac_tvb;
    guint8               tag = 0;
    gboolean             infoAlreadySet = FALSE;

    /* This is a heuristic dissector, which means we get all the UDP
     * traffic not sent to a known dissector and not claimed by
     * a heuristic dissector called before us!
     */

    if (!global_mac_lte_heur) {
        return FALSE;
    }

    /* If redissecting, use previous info struct (if available) */
    p_mac_lte_info = p_get_proto_data(pinfo->fd, proto_mac_lte_dan);
    if (p_mac_lte_info == NULL) {
        /* Allocate new info struct for this frame */
        p_mac_lte_info = se_alloc0(sizeof(struct mac_lte_info));
        infoAlreadySet = FALSE;
    }
    else {
        infoAlreadySet = TRUE;
    }

    /* Do this again on re-dissection to re-discover offset of actual PDU */

    /* Needs to be at least as long as:
       - the signature string
       - fixed header bytes
       - tag for data
       - at least one byte of MAC PDU payload */
    if ((size_t)tvb_length_remaining(tvb, offset) < (strlen(MAC_LTE_START_STRING)+3+2)) {
        return FALSE;
    }

    /* OK, compare with signature string */
    if (tvb_strneql(tvb, offset, MAC_LTE_START_STRING, (gint)strlen(MAC_LTE_START_STRING)) != 0) {
        return FALSE;
    }
    offset += (gint)strlen(MAC_LTE_START_STRING);

    /* Read fixed fields */
    p_mac_lte_info->radioType = tvb_get_guint8(tvb, offset++);
    p_mac_lte_info->direction = tvb_get_guint8(tvb, offset++);

    /* TODO: add this info to framing protocol */
    if (p_mac_lte_info->direction == DIRECTION_UPLINK) {
        p_mac_lte_info->detailed_phy_info.ul_info.present = FALSE;
    }
    else {
        p_mac_lte_info->detailed_phy_info.dl_info.present = FALSE;
    }

    p_mac_lte_info->rntiType = tvb_get_guint8(tvb, offset++);

    /* Read optional fields */
    while (tag != MAC_LTE_PAYLOAD_TAG) {
        /* Process next tag */
        tag = tvb_get_guint8(tvb, offset++);
        switch (tag) {
            case MAC_LTE_RNTI_TAG:
                p_mac_lte_info->rnti = tvb_get_ntohs(tvb, offset);
                offset += 2;
                break;
            case MAC_LTE_UEID_TAG:
                p_mac_lte_info->ueid = tvb_get_ntohs(tvb, offset);
                offset += 2;
                break;
            case MAC_LTE_SUBFRAME_TAG:
                p_mac_lte_info->subframeNumber = tvb_get_ntohs(tvb, offset);
                offset += 2;
                break;
            case MAC_LTE_PREDFINED_DATA_TAG:
                p_mac_lte_info->isPredefinedData = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case MAC_LTE_RETX_TAG:
                p_mac_lte_info->reTxCount = tvb_get_guint8(tvb, offset);
                offset++;
                break;
            case MAC_LTE_CRC_STATUS_TAG:
                p_mac_lte_info->crcStatusValid = TRUE;
                p_mac_lte_info->detailed_phy_info.dl_info.crc_status = tvb_get_guint8(tvb, offset);
                offset++;
                break;

            case MAC_LTE_PAYLOAD_TAG:
                /* Have reached data, so set payload length and get out of loop */
                p_mac_lte_info->length= tvb_length_remaining(tvb, offset);
                continue;

            default:
                /* It must be a recognised tag */
                return FALSE;
        }
    }

    if (!infoAlreadySet) {
        /* Store info in packet */
        p_add_proto_data(pinfo->fd, proto_mac_lte_dan, p_mac_lte_info);
    }

    /**************************************/
    /* OK, now dissect as MAC LTE         */

    /* Create tvb that starts at actual MAC PDU */
    mac_tvb = tvb_new_subset(tvb, offset, -1, tvb_reported_length(tvb)-offset);
    dissect_mac_lte(mac_tvb, pinfo, tree);
    return TRUE;
}


/* Write the given formatted text to:
   - the info column (if pinfo != NULL)
   - 1 or 2 other labels (optional)
*/
static void write_pdu_label_and_info(proto_item *ti1, proto_item *ti2,
                                     packet_info *pinfo, const char *format, ...)
{
    #define MAX_INFO_BUFFER 256
    static char info_buffer[MAX_INFO_BUFFER];

    va_list ap;

    va_start(ap, format);
    g_vsnprintf(info_buffer, MAX_INFO_BUFFER, format, ap);
    va_end(ap);

    /* Add to indicated places */
    if (pinfo != NULL) {
        col_append_str(pinfo->cinfo, COL_INFO, info_buffer);
    }
    if (ti1 != NULL) {
        proto_item_append_text(ti1, "%s", info_buffer);
    }
    if (ti2 != NULL) {
        proto_item_append_text(ti2, "%s", info_buffer);
    }
}

/* Show extra PHY parameters (if present) */
static void show_extra_phy_parameters(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tree,
                                      struct mac_lte_info *p_mac_lte_info)
{
    proto_item *phy_ti;
    proto_tree *phy_tree;
    proto_item *ti;

    if (p_mac_lte_info->direction == DIRECTION_UPLINK) {
        if (p_mac_lte_info->detailed_phy_info.ul_info.present) {

            /* Create root */
            phy_ti = proto_tree_add_string_format(tree, hf_mac_lte_context_phy_ul,
                                                  tvb, 0, 0, "", "UL PHY Context");
            phy_tree = proto_item_add_subtree(phy_ti, ett_mac_lte_phy_context);
            PROTO_ITEM_SET_GENERATED(phy_ti);

            /* Add items */
            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_ul_modulation_type,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.ul_info.modulation_type);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_ul_tbs_index,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.ul_info.tbs_index);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_ul_resource_block_length,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.ul_info.resource_block_length);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_ul_resource_block_start,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.ul_info.resource_block_start);
            PROTO_ITEM_SET_GENERATED(ti);

            proto_item_append_text(phy_ti, " (");

            write_pdu_label_and_info(phy_ti, NULL,
                                     (global_mac_lte_layer_to_show == ShowPHYLayer) ? pinfo : NULL,
                                     "%s Tbs_Index=%u RB_len=%u RB_start=%u",
                                     val_to_str(p_mac_lte_info->detailed_phy_info.ul_info.modulation_type,
                                                      modulation_type_vals, "Unknown"),
                                     p_mac_lte_info->detailed_phy_info.ul_info.tbs_index,
                                     p_mac_lte_info->detailed_phy_info.ul_info.resource_block_length,
                                     p_mac_lte_info->detailed_phy_info.ul_info.resource_block_start);

            proto_item_append_text(phy_ti, ")");

            /* Don't want columns to be replaced now */
            if (global_mac_lte_layer_to_show == ShowPHYLayer) {
                col_set_writable(pinfo->cinfo, FALSE);
            }
        }
    }
    else {
        if (p_mac_lte_info->detailed_phy_info.dl_info.present) {

            /* Create root */
            phy_ti = proto_tree_add_string_format(tree, hf_mac_lte_context_phy_dl,
                                                  tvb, 0, 0, "", "DL PHY Context");
            phy_tree = proto_item_add_subtree(phy_ti, ett_mac_lte_phy_context);
            PROTO_ITEM_SET_GENERATED(phy_ti);

            /* Add items */
            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_dl_dci_format,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.dl_info.dci_format);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_dl_resource_allocation_type,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.dl_info.resource_allocation_type);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_dl_aggregation_level,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.dl_info.aggregation_level);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_dl_mcs_index,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.dl_info.mcs_index);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_dl_redundancy_version_index,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.dl_info.redundancy_version_index);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_dl_resource_block_length,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.dl_info.resource_block_length);
            PROTO_ITEM_SET_GENERATED(ti);

            ti = proto_tree_add_uint(phy_tree, hf_mac_lte_context_phy_dl_crc_status,
                                     tvb, 0, 0,
                                     p_mac_lte_info->detailed_phy_info.dl_info.crc_status);
            PROTO_ITEM_SET_GENERATED(ti);

            proto_item_append_text(phy_ti, " (");

            write_pdu_label_and_info(phy_ti, NULL,
                                     (global_mac_lte_layer_to_show == ShowPHYLayer) ? pinfo : NULL,
                                     "DCI_Format=%s Res_Alloc=%u Aggr_Level=%s MCS=%u RV=%u "
                                     "Res_Block_len=%u CRC_status=%s",
                                     val_to_str(p_mac_lte_info->detailed_phy_info.dl_info.dci_format,
                                                      dci_format_vals, "Unknown"),
                                     p_mac_lte_info->detailed_phy_info.dl_info.resource_allocation_type,
                                     val_to_str(p_mac_lte_info->detailed_phy_info.dl_info.aggregation_level,
                                                      aggregation_level_vals, "Unknown"),
                                     p_mac_lte_info->detailed_phy_info.dl_info.mcs_index,
                                     p_mac_lte_info->detailed_phy_info.dl_info.redundancy_version_index,
                                     p_mac_lte_info->detailed_phy_info.dl_info.resource_block_length,
                                     val_to_str(p_mac_lte_info->detailed_phy_info.dl_info.crc_status,
                                                      crc_status_vals, "Unknown"));
            proto_item_append_text(phy_ti, ")");

            /* Don't want columns to be replaced now */
            if (global_mac_lte_layer_to_show == ShowPHYLayer) {
                col_set_writable(pinfo->cinfo, FALSE);
            }
        }
    }
}


/* Dissect a single Random Access Reponse body */
static gint dissect_rar_entry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                              proto_item *pdu_ti,
                              gint offset, guint8 rapid)
{
    guint8 reserved;
    guint start_body_offset = offset;
    proto_item *ti;
    proto_item *rar_body_ti;
    proto_tree *rar_body_tree;
    proto_tree *ul_grant_tree;
    proto_item *ul_grant_ti;
    guint16 timing_advance;
    guint32 ul_grant;
    guint16 temp_crnti;

    /* Create tree for this Body */
    rar_body_ti = proto_tree_add_item(tree,
                                      hf_mac_lte_rar_body,
                                      tvb, offset, 0, FALSE);
    rar_body_tree = proto_item_add_subtree(rar_body_ti, ett_mac_lte_rar_body);

    /* Dissect an RAR entry */

    /* Check reserved bit */
    reserved = (tvb_get_guint8(tvb, offset) & 0x80) >> 7;
    ti = proto_tree_add_item(rar_body_tree, hf_mac_lte_rar_reserved2, tvb, offset, 1, FALSE);
    if (reserved != 0) {
            expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                      "RAR body Reserved bit not zero (found 0x%x)", reserved);
    }

    /* Timing Advance */
    timing_advance = (tvb_get_ntohs(tvb, offset) & 0x7ff0) >> 4;
    ti = proto_tree_add_item(rar_body_tree, hf_mac_lte_rar_ta, tvb, offset, 2, FALSE);
    if (timing_advance != 0) {
        expert_add_info_format(pinfo, ti, PI_SEQUENCE, (timing_advance <= 31) ? PI_NOTE : PI_WARN,
                               "RAR Timing advance not zero (%u)", timing_advance);
    }
    offset++;

    /* UL Grant */
    ul_grant = (tvb_get_ntohl(tvb, offset) & 0x0fffff00) >> 8;
    ul_grant_ti = proto_tree_add_item(rar_body_tree, hf_mac_lte_rar_ul_grant, tvb, offset, 3, FALSE);

    /* Break these 20 bits down as described in 36.213, section 6.2 */
    /* Create subtree for UL grant break-down */
    ul_grant_tree = proto_item_add_subtree(ul_grant_ti, ett_mac_lte_rar_ul_grant);

    /* Hopping flag (1 bit) */
    proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_hopping,
                        tvb, offset, 1, FALSE);

    /* Fixed sized resource block assignment (10 bits) */
    proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_fsrba,
                        tvb, offset, 2, FALSE);

    /* Truncated Modulation and coding scheme (4 bits) */
    proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_tmcs,
                        tvb, offset+1, 2, FALSE);

    /* TPC command for scheduled PUSCH (3 bits) */
    proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_tcsp,
                        tvb, offset+2, 1, FALSE);

    /* UL delay (1 bit) */
    proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_ul_delay,
                        tvb, offset+2, 1, FALSE);

    /* CQI request (1 bit) */
    proto_tree_add_item(ul_grant_tree, hf_mac_lte_rar_ul_grant_cqi_request,
                        tvb, offset+2, 1, FALSE);

    offset += 3;

    /* Temporary C-RNTI */
    temp_crnti = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(rar_body_tree, hf_mac_lte_rar_temporary_crnti, tvb, offset, 2, FALSE);
    offset += 2;

    write_pdu_label_and_info(pdu_ti, rar_body_ti, pinfo,
                             "(RAPID=%u: TA=%u, UL-Grant=%u, Temp C-RNTI=%u) ",
                             rapid, timing_advance, ul_grant, temp_crnti);

    proto_item_set_len(rar_body_ti, offset-start_body_offset);

    return offset;
}


/* Dissect Random Access Reponse (RAR) PDU */
static void dissect_rar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *pdu_ti,
                        gint offset, mac_lte_info *p_mac_lte_info, mac_lte_tap_info *tap_info)
{
    gint     number_of_rars = 0;   /* No of RAR bodies expected following headers */
    guint8   rapids[64];
    gboolean backoff_indicator_seen = FALSE;
    guint8   backoff_indicator = 0;
    guint8   extension;
    gint     n;
    proto_tree *rar_headers_tree;
    proto_item *ti;
    proto_item *rar_headers_ti;
    proto_item *padding_length_ti;
    int        start_headers_offset = offset;

    write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                             "RAR (RA-RNTI=%u, SF=%u) ",
                             p_mac_lte_info->rnti, p_mac_lte_info->subframeNumber);

    /* Create hidden 'virtual root' so can filter on mac-lte.rar */
    ti = proto_tree_add_item(tree, hf_mac_lte_rar, tvb, offset, -1, FALSE);
    PROTO_ITEM_SET_HIDDEN(ti);

    /* Create headers tree */
    rar_headers_ti = proto_tree_add_item(tree,
                                         hf_mac_lte_rar_headers,
                                         tvb, offset, 0, FALSE);
    rar_headers_tree = proto_item_add_subtree(rar_headers_ti, ett_mac_lte_rar_headers);


    /***************************/
    /* Read the header entries */
    do {
        int start_header_offset = offset;
        proto_tree *rar_header_tree;
        proto_item *rar_header_ti;
        guint8 type_value;
        guint8 first_byte = tvb_get_guint8(tvb, offset);

        /* Create tree for this header */
        rar_header_ti = proto_tree_add_item(rar_headers_tree,
                                            hf_mac_lte_rar_header,
                                            tvb, offset, 0, FALSE);
        rar_header_tree = proto_item_add_subtree(rar_header_ti, ett_mac_lte_rar_header);

        /* Extension */
        extension = (first_byte & 0x80) >> 7;
        proto_tree_add_item(rar_header_tree, hf_mac_lte_rar_extension, tvb, offset, 1, FALSE);

        /* Type */
        type_value = (first_byte & 0x40) >> 6;
        proto_tree_add_item(rar_header_tree, hf_mac_lte_rar_t, tvb, offset, 1, FALSE);

        if (type_value == 0) {
            /* Backoff Indicator (BI) case */

            guint8 reserved;
            proto_item *tii;
            proto_item *bi_ti;

            /* 2 Reserved bits */
            reserved = (tvb_get_guint8(tvb, offset) & 0x30) >> 4;
            tii = proto_tree_add_item(rar_header_tree, hf_mac_lte_rar_reserved, tvb, offset, 1, FALSE);
            if (reserved != 0) {
                expert_add_info_format(pinfo, tii, PI_MALFORMED, PI_ERROR,
                                       "RAR header Reserved bits not zero (found 0x%x)", reserved);
            }

            /* Backoff Indicator */
            backoff_indicator = tvb_get_guint8(tvb, offset) & 0x0f;
            bi_ti = proto_tree_add_item(rar_header_tree, hf_mac_lte_rar_bi, tvb, offset, 1, FALSE);

            /* As of March 2009 spec, it must be first, and may only appear once */
            if (backoff_indicator_seen) {
                expert_add_info_format(pinfo, bi_ti, PI_MALFORMED, PI_ERROR,
                                       "MAC RAR PDU has > 1 Backoff Indicator subheader present");
            }
            backoff_indicator_seen = TRUE;

            write_pdu_label_and_info(pdu_ti, rar_header_ti, pinfo,
                                     "(Backoff Indicator=%sms)",
                                     val_to_str(backoff_indicator, rar_bi_vals, "Illegal-value "));

            /* If present, it must be the first subheader */
            if (number_of_rars > 0) {
                expert_add_info_format(pinfo, bi_ti, PI_MALFORMED, PI_WARN,
                                       "Backoff Indicator must appear as first subheader");
            }

        }
        else {
            /* RAPID case */
            /* TODO: complain if the same RAPID appears twice in same frame? */
            rapids[number_of_rars] = tvb_get_guint8(tvb, offset) & 0x3f;
            proto_tree_add_item(rar_header_tree, hf_mac_lte_rar_rapid, tvb, offset, 1, FALSE);

            proto_item_append_text(rar_header_ti, "(RAPID=%u)", rapids[number_of_rars]);

            number_of_rars++;
        }

        offset++;

        /* Finalise length of header tree selection */
        proto_item_set_len(rar_header_ti, offset - start_header_offset);

    } while (extension);

    /* Append summary to headers root */
    proto_item_append_text(rar_headers_ti, " (%u RARs", number_of_rars);
    if (backoff_indicator_seen) {
        proto_item_append_text(rar_headers_ti, ", BI=%sms)",
                               val_to_str(backoff_indicator, rar_bi_vals, "Illegal-value "));
    }
    else {
        proto_item_append_text(rar_headers_ti, ")");
    }

    /* Set length for headers root */
    proto_item_set_len(rar_headers_ti, offset-start_headers_offset);


    /***************************/
    /* Read any indicated RARs */
    for (n=0; n < number_of_rars; n++) {
        offset = dissect_rar_entry(tvb, pinfo, tree, pdu_ti, offset, rapids[n]);
    }

    /* Update TAP info */
    tap_info->number_of_rars += number_of_rars;

    /* Padding may follow */
    if (tvb_length_remaining(tvb, offset) > 0) {
        proto_tree_add_item(tree, hf_mac_lte_padding_data,
                            tvb, offset, -1, FALSE);
    }
    padding_length_ti = proto_tree_add_int(tree, hf_mac_lte_padding_length,
                                           tvb, offset, 0,
                                           p_mac_lte_info->length - offset);
    PROTO_ITEM_SET_GENERATED(padding_length_ti);

    /* Update padding bytes in stats */
    tap_info->padding_bytes += (p_mac_lte_info->length - offset);
}


/* Dissect BCH PDU */
static void dissect_bch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        proto_item *pdu_ti,
                        int offset, mac_lte_info *p_mac_lte_info)
{
    proto_item *ti;

    write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                             "BCH PDU (%u bytes, on %s transport)  ",
                             tvb_length_remaining(tvb, offset),
                             val_to_str(p_mac_lte_info->rntiType,
                                              bch_transport_channel_vals,
                                              "Unknown"));

    /* Show which transport layer it came in on (inferred from RNTI type) */
    ti = proto_tree_add_uint(tree, hf_mac_lte_context_bch_transport_channel,
                             tvb, offset, 0, p_mac_lte_info->rntiType);
    PROTO_ITEM_SET_GENERATED(ti);

    /****************************************/
    /* Whole frame is BCH data              */

    /* Raw data */
    ti = proto_tree_add_item(tree, hf_mac_lte_bch_pdu,
                             tvb, offset, -1, FALSE);

    if (global_mac_lte_attempt_rrc_decode) {
        /* Attempt to decode payload using LTE RRC dissector */
        tvbuff_t *rrc_tvb = tvb_new_subset(tvb, offset, -1, tvb_length_remaining(tvb, offset));

        /* Get appropriate dissector handle */
        dissector_handle_t protocol_handle = 0;
        if (p_mac_lte_info->rntiType == SI_RNTI) {
            protocol_handle = find_dissector("lte-rrc.bcch.dl.sch");
        }
        else {
            protocol_handle = find_dissector("lte-rrc.bcch.bch");
        }

        /* Hide raw view of bytes */
        PROTO_ITEM_SET_HIDDEN(ti);

        call_with_catch_all(protocol_handle, rrc_tvb, pinfo, tree);
    }

    /* Check that this *is* downlink! */
    if (p_mac_lte_info->direction == DIRECTION_UPLINK) {
        expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                               "BCH data should not be received in Uplink!");
    }
}


/* Dissect PCH PDU */
static void dissect_pch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        proto_item *pdu_ti, int offset, guint8 direction)
{
    proto_item *ti;

    write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                             "PCH PDU (%u bytes)  ",
                             tvb_length_remaining(tvb, offset));

    /****************************************/
    /* Whole frame is PCH data              */

    /* Always show as raw data */
    ti = proto_tree_add_item(tree, hf_mac_lte_pch_pdu,
                             tvb, offset, -1, FALSE);

    if (global_mac_lte_attempt_rrc_decode) {

        /* Attempt to decode payload using LTE RRC dissector */
        tvbuff_t *rrc_tvb = tvb_new_subset(tvb, offset, -1, tvb_length_remaining(tvb, offset));

        /* Get appropriate dissector handle */
        dissector_handle_t protocol_handle = find_dissector("lte-rrc.pcch");

        /* Hide raw view of bytes */
        PROTO_ITEM_SET_HIDDEN(ti);

        /* Call it (catch exceptions so that stats will be updated) */
        TRY {
            call_dissector_only(protocol_handle, rrc_tvb, pinfo, tree);
        }
        CATCH_ALL {
        }
        ENDTRY
    }

    /* Check that this *is* downlink! */
    if (direction == DIRECTION_UPLINK) {
        expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                               "PCH data should not be received in Uplink!");
    }
}


/* Does this header entry correspond to a fixed-sized control element? */
static int is_fixed_sized_control_element(guint8 lcid, guint8 direction)
{
    if (direction == DIRECTION_UPLINK) {
        /* Uplink */
        switch (lcid) {
            case POWER_HEADROOM_REPORT_LCID:
            case CRNTI_LCID:
            case TRUNCATED_BSR_LCID:
            case SHORT_BSR_LCID:
            case LONG_BSR_LCID:
                return TRUE;

            default:
                return FALSE;
        }
    }
    else {
        /* Assume Downlink */
        switch (lcid) {
            case UE_CONTENTION_RESOLUTION_IDENTITY_LCID:
            case TIMING_ADVANCE_LCID:
            case DRX_COMMAND_LCID:
                return TRUE;

            default:
                return FALSE;
        }
    }
}


/* Is this a BSR report header? */
static int is_bsr_lcid(guint8 lcid)
{
    return ((lcid == TRUNCATED_BSR_LCID) ||
            (lcid == SHORT_BSR_LCID) ||
            (lcid == LONG_BSR_LCID));
}


/* Helper function to call RLC dissector for SDUs (where channel params are known) */
static void call_rlc_dissector(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                               proto_item *pdu_ti,
                               int offset, guint16 data_length,
                               guint8 mode, guint8 direction, guint16 ueid,
                               guint16 channelType, guint16 channelId,
                               guint8 UMSequenceNumberLength)
{
    tvbuff_t *srb_tvb = tvb_new_subset(tvb, offset, data_length, data_length);
    struct rlc_lte_info *p_rlc_lte_info;

    /* Get RLC dissector handle */
    volatile dissector_handle_t protocol_handle = find_dissector("rlc-lte-dan");

    /* Resuse or create RLC info */
    p_rlc_lte_info = p_get_proto_data(pinfo->fd, proto_rlc_lte_dan);
    if (p_rlc_lte_info == NULL) {
        p_rlc_lte_info = se_alloc0(sizeof(struct rlc_lte_info));
    }

    /* Fill in struct details for srb channels */
    p_rlc_lte_info->rlcMode = mode;
    p_rlc_lte_info->direction = direction;
    p_rlc_lte_info->priority = 0; /* ?? */
    p_rlc_lte_info->ueid = ueid;
    p_rlc_lte_info->channelType = channelType;
    p_rlc_lte_info->channelId = channelId;
    p_rlc_lte_info->pduLength = data_length;
    p_rlc_lte_info->UMSequenceNumberLength = UMSequenceNumberLength;

    /* Store info in packet */
    p_add_proto_data(pinfo->fd, proto_rlc_lte_dan, p_rlc_lte_info);

    if (global_mac_lte_layer_to_show != ShowRLCLayer) {
        /* Don't want these columns replaced */
        col_set_writable(pinfo->cinfo, FALSE);
    }
    else {
        /* Clear info column before first RLC PDU */
        if (s_number_of_rlc_pdus_shown == 0) {
            col_clear(pinfo->cinfo, COL_INFO);
        }
        else {
            /* Add a separator and protect column contents here */
            write_pdu_label_and_info(pdu_ti, NULL, pinfo, "   ||   ");
            col_set_fence(pinfo->cinfo, COL_INFO);
        }
    }
    s_number_of_rlc_pdus_shown++;

    /* Call it (catch exceptions so that stats will be updated) */
    TRY {
        call_dissector_only(protocol_handle, srb_tvb, pinfo, tree);
    }
    CATCH_ALL {
    }
    ENDTRY

    col_set_writable(pinfo->cinfo, TRUE);
}


/* Track DL frames, and look for likely cases of likely HARQ retx. Return TRUE if found */
static int DetectIfDLHARQResend(packet_info *pinfo, tvbuff_t *tvb, volatile int offset,
                                proto_tree *tree, mac_lte_info *p_mac_lte_info)
{
    DLHARQResult *result = NULL;
    proto_item *result_ti;

    /* TDD may not work... */

    if (!pinfo->fd->flags.visited) {
        /* First time, so set result and update DL harq table */
        LastFrameData *lastData = NULL;
        LastFrameData *thisData = NULL;

        /* Look up entry for this UE/RNTI */
        LastFrameDataAllSubframes *ueData =
            g_hash_table_lookup(mac_lte_dl_harq_hash, GUINT_TO_POINTER((guint)p_mac_lte_info->rnti));
        if (ueData != NULL) {

            /* Looking for a frame sent 8 or 9 subframes previously.
               TODO: have seen retx >=10 SFs later... */
            gboolean found_match = FALSE;
            gint     SFs_ago;

            for (SFs_ago=8; (SFs_ago <= 9) && !found_match; SFs_ago++) {
                /* Check 8 SFs ago */
                lastData = &(ueData->subframe[(p_mac_lte_info->subframeNumber+(10-SFs_ago)) % 10]);
                if (lastData->inUse) {
                    /* Compare time, sf, data to see if this looks like a retx */
                    if ((tvb_length_remaining(tvb, offset) == lastData->length) &&
                        (memcmp(lastData->data,
                                tvb_get_ptr(tvb, offset, lastData->length),
                                MIN(lastData->length, MAX_EXPECTED_PDU_LENGTH)) == 0)) {

                        /* Work out gap between frames */
                        gint seconds_between_packets = (gint)
                              (pinfo->fd->abs_ts.secs - lastData->received_time.secs);
                        gint nseconds_between_packets =
                              pinfo->fd->abs_ts.nsecs - lastData->received_time.nsecs;

                        /* Round difference to nearest millisecond */
                        gint total_gap = (seconds_between_packets*1000) +
                                         ((nseconds_between_packets+500000) / 1000000);

                        /* Should be equal to number of subframes - allow some leeway */
                        if ((total_gap >= (SFs_ago-1)) && (total_gap <= (SFs_ago+1))) {
                            found_match = TRUE;

                            /* Resend detected!!! Store result */
                            result = se_alloc(sizeof(DLHARQResult));
                            result->previousFrameNum = lastData->framenum;
                            g_hash_table_insert(mac_lte_dl_harq_result_hash, GUINT_TO_POINTER(pinfo->fd->num), result);
                        }
                    }
                }
            }

            /* Even if we didn't find a previous frame, if we know its a retx, setup result */
            if ((result == NULL) && (p_mac_lte_info->dl_retx == dl_retx_yes)) {
                result = se_alloc(sizeof(DLHARQResult));
                result->previousFrameNum = 0;
                g_hash_table_insert(mac_lte_dl_harq_result_hash, GUINT_TO_POINTER(pinfo->fd->num), result);
            }

        }
        else {
            /* Allocate entry in table for this UE/RNTI */
            ueData = se_alloc0(sizeof(LastFrameDataAllSubframes));
            g_hash_table_insert(mac_lte_dl_harq_hash, GUINT_TO_POINTER((guint)p_mac_lte_info->rnti), ueData);
        }

        /* Store this frame's details in table */
        thisData = &(ueData->subframe[p_mac_lte_info->subframeNumber]);
        thisData->inUse = TRUE;
        thisData->length = tvb_length_remaining(tvb, offset);
        memcpy(thisData->data,
               tvb_get_ptr(tvb, offset, MIN(thisData->length, MAX_EXPECTED_PDU_LENGTH)),
               MIN(thisData->length, MAX_EXPECTED_PDU_LENGTH));
        thisData->subframeNumber = p_mac_lte_info->subframeNumber;
        thisData->framenum = pinfo->fd->num;
        thisData->received_time = pinfo->fd->abs_ts;
    }
    else {
        /* Not first time, so just set whats already stored in result */
        result = g_hash_table_lookup(mac_lte_dl_harq_result_hash, GUINT_TO_POINTER(pinfo->fd->num));
    }


    /************************************************************/
    /* Show result, with link back to original frame (if known) */
    result_ti = proto_tree_add_boolean(tree, hf_mac_lte_context_phy_dl_retx,
                                       tvb, 0, 0, (result != NULL));
    if (result != NULL) {
        proto_item *original_ti;
        expert_add_info_format(pinfo, result_ti, PI_SEQUENCE, PI_WARN,
                               "%sDL HARQ resend (UE=%u)",
                               (p_mac_lte_info->dl_retx == dl_retx_unknown) ? "Suspected " : "",
                               p_mac_lte_info->ueid);
        if (result->previousFrameNum != 0) {
            original_ti = proto_tree_add_uint(tree, hf_mac_lte_suspected_dl_retx_original_frame,
                                             tvb, 0, 0, result->previousFrameNum);
            PROTO_ITEM_SET_GENERATED(original_ti);
        }
    }
    else {
        /* Don't show negatives */
        PROTO_ITEM_SET_HIDDEN(result_ti);
    }
    PROTO_ITEM_SET_GENERATED(result_ti);

    /* Return TRUE if resend was detected */
    return (result != NULL);
}


/* Return TRUE if the given packet is thought to be a retx */
int is_mac_lte_frame_retx(packet_info *pinfo, guint8 direction)
{
    if (direction == DIRECTION_UPLINK) {
        /* For UL, retx count is stored in per-packet struct */
        struct mac_lte_info *p_mac_lte_info = p_get_proto_data(pinfo->fd, proto_mac_lte_dan);
        return ((p_mac_lte_info != NULL) && (p_mac_lte_info->reTxCount > 0));
    }
    else {
        /* For DL, must consult result table */
        return (g_hash_table_lookup(mac_lte_dl_harq_result_hash, GUINT_TO_POINTER(pinfo->fd->num)) != NULL);
    }
}


/* Track UL frames, so that when a retx is indicated, we can search for
   the original tx.  We will either find it, and provide a link back to it,
   or flag that we couldn't find as an expert error */
static void TrackReportedULHARQResend(packet_info *pinfo, tvbuff_t *tvb, volatile int offset,
                                      proto_tree *tree, mac_lte_info *p_mac_lte_info,
                                      proto_item *retx_ti)
{
    ULHARQResult *result = NULL;

    /* FDD only for now! */
    if (p_mac_lte_info->radioType != FDD_RADIO) {
        return;
    }

    if (!pinfo->fd->flags.visited) {
        /* First time, so set result and update UL harq table */
        LastFrameData *lastData = NULL;
        LastFrameData *thisData = NULL;

        /* Look up entry for this UE/RNTI */
        LastFrameDataAllSubframes *ueData =
            g_hash_table_lookup(mac_lte_ul_harq_hash, GUINT_TO_POINTER((guint)p_mac_lte_info->rnti));
        if (ueData != NULL) {

            if (p_mac_lte_info->reTxCount >= 1) {
                /* Looking for a frame sent 8 subframes previously */
                lastData = &(ueData->subframe[(p_mac_lte_info->subframeNumber+2) % 10]);
                if (lastData->inUse) {
                    /* Compare time, sf, data to see if this looks like a retx */
                    if ((tvb_length_remaining(tvb, offset) == lastData->length) &&
                        (memcmp(lastData->data,
                                tvb_get_ptr(tvb, offset, lastData->length),
                                MIN(lastData->length, MAX_EXPECTED_PDU_LENGTH)) == 0)) {

                        /* Work out gap between frames */
                        gint seconds_between_packets = (gint)
                              (pinfo->fd->abs_ts.secs - lastData->received_time.secs);
                        gint nseconds_between_packets =
                              pinfo->fd->abs_ts.nsecs - lastData->received_time.nsecs;

                        /* Round to nearest ms */
                        gint total_gap = (seconds_between_packets*1000) +
                                         ((nseconds_between_packets+500000) / 1000000);

                        /* Should be 8 ms apart - allow some leeway */
                        if ((total_gap >= 7) && (total_gap <= 9)) {
                            /* Original detected!!! Store result */
                            result = se_alloc(sizeof(ULHARQResult));
                            result->previousFrameNum = lastData->framenum;
                            g_hash_table_insert(mac_lte_ul_harq_result_hash, GUINT_TO_POINTER(pinfo->fd->num), result);
                        }
                    }
                }
            }
        }
        else {
            /* Allocate entry in table for this UE/RNTI */
            ueData = se_alloc0(sizeof(LastFrameDataAllSubframes));
            g_hash_table_insert(mac_lte_ul_harq_hash, GUINT_TO_POINTER((guint)p_mac_lte_info->rnti), ueData);
        }

        /* Store this frame's details in table */
        thisData = &(ueData->subframe[p_mac_lte_info->subframeNumber]);
        thisData->inUse = TRUE;
        thisData->length = tvb_length_remaining(tvb, offset);
        memcpy(thisData->data,
               tvb_get_ptr(tvb, offset, MIN(thisData->length, MAX_EXPECTED_PDU_LENGTH)),
               MIN(thisData->length, MAX_EXPECTED_PDU_LENGTH));
        thisData->subframeNumber = p_mac_lte_info->subframeNumber;
        thisData->framenum = pinfo->fd->num;
        thisData->received_time = pinfo->fd->abs_ts;
    }
    else {
        /* Not first time, so just set whats already stored in result */
        result = g_hash_table_lookup(mac_lte_ul_harq_result_hash, GUINT_TO_POINTER(pinfo->fd->num));
    }

    if (retx_ti != NULL) {
        if (result != NULL) {
            proto_item *original_ti;

            original_ti = proto_tree_add_uint(tree, hf_mac_lte_ul_harq_resend_original_frame,
                                              tvb, 0, 0, result->previousFrameNum);
            PROTO_ITEM_SET_GENERATED(original_ti);
        }
        else {
            expert_add_info_format(pinfo, retx_ti, PI_SEQUENCE, PI_ERROR,
                                   "Original Tx of UL frame not found (UE %u) !!", p_mac_lte_info->ueid);
        }
    }
}


/* Look up SRResult associated with a given frame. Will create one if necessary
   if can_create is set */
static SRResult *GetSRResult(guint32 frameNum, gboolean can_create)
{
    SRResult *result;
    result = g_hash_table_lookup(mac_lte_sr_request_hash, GUINT_TO_POINTER(frameNum));

    if ((result == NULL) && can_create) {
        result = se_alloc0(sizeof(SRResult));
        g_hash_table_insert(mac_lte_sr_request_hash, GUINT_TO_POINTER((guint)frameNum), result);
    }
    return result;
}


/* Keep track of SR requests, failures and related grants, in order to show them
   as generated fields in these frames */
static void TrackSRInfo(SREvent event, packet_info *pinfo, proto_tree *tree _U_,
                        tvbuff_t *tvb _U_, guint16 rnti, proto_item *event_ti)
{
    SRResult *result = NULL;
    SRResult *resultForSRFrame = NULL;
    proto_item *ti;

    /* Create state for this RNTI if necessary */
    SRState *state = g_hash_table_lookup(mac_lte_ue_sr_state, GUINT_TO_POINTER((guint)rnti));
    if (state == NULL) {
        /* Allocate status for this RNTI */
        state = se_alloc(sizeof(SRState));
        state->status = None;
        g_hash_table_insert(mac_lte_ue_sr_state, GUINT_TO_POINTER((guint)rnti), state);
    }

    /* First time through - update state with new info */
    if (!pinfo->fd->flags.visited) {
        guint32 timeSinceRequest;

        /* Store time of request */
        if (event == SR_Request) {
            state->requestTime = pinfo->fd->abs_ts;
        }

        switch (state->status) {
            case None:
                switch (event) {
                    case SR_Grant:
                        /* Got another grant - fine */

                        /* update state */
                        state->lastGrantFramenum = pinfo->fd->num;
                        break;

                    case SR_Request:
                        /* Sent an SR - fine */

                        /* Update state */
                        state->status = SR_Outstanding;
                        state->lastSRFramenum = pinfo->fd->num;
                        break;

                    case SR_Failure:
                        /* This is an error, since we hadn't send an SR... */
                        result = GetSRResult(pinfo->fd->num, TRUE);
                        result->type = InvalidSREvent;
                        result->status = None;
                        result->event = SR_Failure;
                        break;
                }
                break;

            case SR_Outstanding:
                timeSinceRequest = (guint32)(((pinfo->fd->abs_ts.secs - state->requestTime.secs) * 1000) +
                                             ((pinfo->fd->abs_ts.nsecs - state->requestTime.nsecs) / 1000000));

                switch (event) {
                    case SR_Grant:
                        /* Got grant we were waiting for, so state goes to None */

                        /* Update state */
                        state->status = None;

                        /* Set result info */
                        result = GetSRResult(pinfo->fd->num, TRUE);
                        result->type = GrantAnsweringSR;
                        result->frameNum = state->lastSRFramenum;
                        result->timeDifference = timeSinceRequest;

                        /* Also set forward link for SR */
                        resultForSRFrame = GetSRResult(state->lastSRFramenum, TRUE);
                        resultForSRFrame->type = SRLeadingToGrant;
                        resultForSRFrame->frameNum = pinfo->fd->num;
                        resultForSRFrame->timeDifference = timeSinceRequest;
                        break;

                    case SR_Request:
                        /* Another request when already have one pending */
                        result = GetSRResult(pinfo->fd->num, TRUE);
                        result->type = InvalidSREvent;
                        result->status = SR_Outstanding;
                        result->event = SR_Grant;
                        break;

                    case SR_Failure:
                        /* We sent an SR but it failed */

                        /* Update state */
                        state->status = SR_Failed;

                        /* Set result info for failure frame */
                        result = GetSRResult(pinfo->fd->num, TRUE);
                        result->type = FailureAnsweringSR;
                        result->frameNum = state->lastSRFramenum;
                        result->timeDifference = timeSinceRequest;

                        /* Also set forward link for SR */
                        resultForSRFrame = GetSRResult(state->lastSRFramenum, TRUE);
                        resultForSRFrame->type = SRLeadingToFailure;
                        resultForSRFrame->frameNum = pinfo->fd->num;
                        resultForSRFrame->timeDifference = timeSinceRequest;
                        break;
                }
                break;

            case SR_Failed:
                switch (event) {
                    case SR_Grant:
                        /* Got a grant, presumably after a subsequent RACH - fine */

                        /* Update state */
                        state->status = None;
                        break;

                    case SR_Request:
                        /* Tried another SR after a failure, and presumbly no
                           successful subsequent RACH */
                        result = GetSRResult(pinfo->fd->num, TRUE);
                        result->type = InvalidSREvent;
                        result->status = SR_Failed;
                        result->event = SR_Request;
                        break;

                    case SR_Failure:
                        /* 2 failures in a row.... */
                        result = GetSRResult(pinfo->fd->num, TRUE);
                        result->type = InvalidSREvent;
                        result->status = SR_Failed;
                        result->event = SR_Failure;
                        break;
                }
                break;
        }
    }

    /* Get stored result for this frame */
    result = GetSRResult(pinfo->fd->num, FALSE);
    if (result == NULL) {
        /* For an SR frame, there should always be either a PDCCH grant or indication
           that the SR has failed */
        if (event == SR_Request) {
            expert_add_info_format(pinfo, event_ti, PI_SEQUENCE, PI_ERROR,
                                  "SR results in neither a grant or a failure indication");
        }
        return;
    }


    /* Show result info */
    switch (result->type) {
        case GrantAnsweringSR:
            ti = proto_tree_add_uint(tree, hf_mac_lte_grant_answering_sr,
                                     tvb, 0, 0, result->frameNum);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_uint(tree, hf_mac_lte_sr_time_since_request,
                                     tvb, 0, 0, result->timeDifference);
            PROTO_ITEM_SET_GENERATED(ti);
            break;

        case FailureAnsweringSR:
            ti = proto_tree_add_uint(tree, hf_mac_lte_failure_answering_sr,
                                     tvb, 0, 0, result->frameNum);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_uint(tree, hf_mac_lte_sr_time_since_request,
                                     tvb, 0, 0, result->timeDifference);
            PROTO_ITEM_SET_GENERATED(ti);
            break;

        case SRLeadingToGrant:
            ti = proto_tree_add_uint(tree, hf_mac_lte_sr_leading_to_grant,
                                     tvb, 0, 0, result->frameNum);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_uint(tree, hf_mac_lte_sr_time_until_answer,
                                     tvb, 0, 0, result->timeDifference);
            PROTO_ITEM_SET_GENERATED(ti);

            break;

        case SRLeadingToFailure:
            ti = proto_tree_add_uint(tree, hf_mac_lte_sr_leading_to_failure,
                                     tvb, 0, 0, result->frameNum);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_uint(tree, hf_mac_lte_sr_time_until_answer,
                                     tvb, 0, 0, result->timeDifference);
            PROTO_ITEM_SET_GENERATED(ti);
            break;

        case InvalidSREvent:
            ti = proto_tree_add_none_format(tree, hf_mac_lte_sr_invalid_event,
                                            tvb, 0, 0, "Invalid SR event - state=(%s), event=(%s)",
                                            val_to_str(result->status, sr_status_vals, "Unknown"),
                                            val_to_str(result->event,  sr_event_vals,  "Unknown"));
            PROTO_ITEM_SET_GENERATED(ti);
            expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_ERROR,
                                   "Invalid SR event - state=(%s), event=(%s)",
                                   val_to_str(result->status, sr_status_vals, "Unknown"),
                                   val_to_str(result->event,  sr_event_vals,  "Unknown"));

            break;
    }
}





#define MAX_HEADERS_IN_PDU 1024

/* UL-SCH and DL-SCH formats have much in common, so handle them in a common
   function */
static void dissect_ulsch_or_dlsch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                   proto_item *pdu_ti,
                                   volatile guint32 offset, guint8 direction,
                                   mac_lte_info *p_mac_lte_info, mac_lte_tap_info *tap_info,
                                   proto_item *retx_ti,
                                   proto_tree *context_tree)
{
    guint8          extension;
    volatile guint8 n;
    proto_item      *truncated_ti;
    proto_item      *padding_length_ti;
    proto_item      *hidden_root_ti;

    /* Keep track of LCIDs and lengths as we dissect the header */
    volatile guint8 number_of_headers = 0;
    guint8  lcids[MAX_HEADERS_IN_PDU];
    gint16  pdu_lengths[MAX_HEADERS_IN_PDU];

    proto_item *pdu_header_ti;
    proto_tree *pdu_header_tree;

    gboolean   have_seen_data_header = FALSE;
    gboolean   have_seen_bsr = FALSE;
    gboolean   expecting_body_data = FALSE;
    volatile   guint32    is_truncated = FALSE;

    write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                             "%s: (SF=%u) UEId=%u ",
                             (direction == DIRECTION_UPLINK) ? "UL-SCH" : "DL-SCH",
                             p_mac_lte_info->subframeNumber,
                             p_mac_lte_info->ueid);

    tap_info->raw_length = p_mac_lte_info->length;

    /* For downlink frames, can try to work out if this looks like a HARQ resend */
    if (direction == DIRECTION_DOWNLINK) {
        /* Result will be added to context tree */
        int detected = DetectIfDLHARQResend(pinfo, tvb, offset, context_tree, p_mac_lte_info);
        if (p_mac_lte_info->dl_retx == dl_retx_unknown) {
            tap_info->isPHYRetx = detected;
        }
        else {
            tap_info->isPHYRetx = p_mac_lte_info->dl_retx;
        }
    }


    /* For uplink frames, if this is logged as a resend, look for original tx */
    if ((direction == DIRECTION_UPLINK) && global_mac_lte_attempt_ul_harq_resend_track) {
        TrackReportedULHARQResend(pinfo, tvb, offset, tree, p_mac_lte_info, retx_ti);
    }

    /* For uplink grants, update SR status */
    if ((direction == DIRECTION_UPLINK) && global_mac_lte_track_sr) {
        TrackSRInfo(SR_Grant, pinfo, tree, tvb, p_mac_lte_info->rnti, NULL);
    }

    /* Add hidden item to filter on */
    hidden_root_ti = proto_tree_add_string_format(tree,
                                                 (direction == DIRECTION_UPLINK) ?
                                                    hf_mac_lte_ulsch :
                                                    hf_mac_lte_dlsch,
                                                 tvb, offset, 0,
                                                 "",
                                                 "Hidden header");
    PROTO_ITEM_SET_HIDDEN(hidden_root_ti);

    /* Add PDU block header subtree */
    pdu_header_ti = proto_tree_add_string_format(tree,
                                                 (direction == DIRECTION_UPLINK) ?
                                                    hf_mac_lte_ulsch_header :
                                                    hf_mac_lte_dlsch_header,
                                                 tvb, offset, 0,
                                                 "",
                                                 "MAC PDU Header");
    pdu_header_tree = proto_item_add_subtree(pdu_header_ti,
                                             (direction == DIRECTION_UPLINK) ?
                                                    ett_mac_lte_ulsch_header :
                                                    ett_mac_lte_dlsch_header);


    /************************************************************************/
    /* Dissect each sub-header.                                             */
    do {
        guint8 reserved;
        guint64 length = 0;
        proto_item *pdu_subheader_ti;
        proto_tree *pdu_subheader_tree;
        proto_item *lcid_ti;
        proto_item *ti;
        gint       offset_start_subheader = offset;
        guint8 first_byte = tvb_get_guint8(tvb, offset);

        /* Add PDU block header subtree */
        pdu_subheader_ti = proto_tree_add_string_format(pdu_header_tree,
                                                        hf_mac_lte_sch_subheader,
                                                        tvb, offset, 0,
                                                        "",
                                                        "Sub-header");
        pdu_subheader_tree = proto_item_add_subtree(pdu_subheader_ti,
                                                    ett_mac_lte_sch_subheader);

        /* Check 1st 2 reserved bits */
        reserved = (first_byte & 0xc0) >> 6;
        ti = proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_sch_reserved,
                                 tvb, offset, 1, FALSE);
        if (reserved != 0) {
            expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                                   "%cL-SCH header Reserved bits not zero",
                                   (p_mac_lte_info->direction == DIRECTION_UPLINK) ? 'U' : 'D');
        }

        /* Extended bit */
        extension = (first_byte & 0x20) >> 5;
        proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_sch_extended,
                            tvb, offset, 1, FALSE);

        /* LCID.  Has different meaning depending upon direction. */
        lcids[number_of_headers] = first_byte & 0x1f;
        if (direction == DIRECTION_UPLINK) {
            lcid_ti = proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_ulsch_lcid,
                                          tvb, offset, 1, FALSE);
            write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                                     "(%s",
                                     val_to_str(lcids[number_of_headers],
                                                      ulsch_lcid_vals, "(Unknown LCID)"));
        }
        else {
            lcid_ti = proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_dlsch_lcid,
                                          tvb, offset, 1, FALSE);
            write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                                     "(%s",
                                     val_to_str(lcids[number_of_headers],
                                                      dlsch_lcid_vals, "(Unknown LCID)"));
        }
        offset++;

        /* Remember if we've seen a data subheader */
        if (lcids[number_of_headers] <= 10) {
            have_seen_data_header = TRUE;
            expecting_body_data = TRUE;
        }

        /* Show an expert item if a contol subheader (except Padding) appears
           *after* a data PDU */
        if (have_seen_data_header &&
            (lcids[number_of_headers] > 10) && (lcids[number_of_headers] != PADDING_LCID)) {
            expert_add_info_format(pinfo, lcid_ti, PI_MALFORMED, PI_ERROR,
                                   "%cL-SCH Control subheaders should not appear after data subheaders",
                                   (p_mac_lte_info->direction == DIRECTION_UPLINK) ? 'U' : 'D');
            return;
        }

        /* Show an expert item if we're seeing more then one BSR in a frame */
        if ((direction == DIRECTION_UPLINK) && is_bsr_lcid(lcids[number_of_headers])) {
            if (have_seen_bsr) {
                expert_add_info_format(pinfo, lcid_ti, PI_MALFORMED, PI_ERROR,
                                      "There shouldn't be > 1 BSR in a frame");
                return;
            }
            have_seen_bsr = TRUE;
        }


        /********************************************************************/
        /* Length field follows if not the last header or for a fixed-sized
           control element */
        if (!extension) {
            if (is_fixed_sized_control_element(lcids[number_of_headers], direction)) {
                pdu_lengths[number_of_headers] = 0;
            }
            else {
                pdu_lengths[number_of_headers] = -1;
            }
        }
        else {
            if (!is_fixed_sized_control_element(lcids[number_of_headers], direction) &&
                (lcids[number_of_headers] != PADDING_LCID)) {

                guint8  format;

                /* F(ormat) bit tells us how long the length field is */
                format = (tvb_get_guint8(tvb, offset) & 0x80) >> 7;
                proto_tree_add_item(pdu_subheader_tree, hf_mac_lte_sch_format,
                                    tvb, offset, 1, FALSE);

                /* Now read length field itself */
                if (format) {
                    /* >= 128 - use 15 bits */
                    proto_tree_add_bits_ret_val(pdu_subheader_tree, hf_mac_lte_sch_length,
                                                tvb, offset*8 + 1, 15, &length, FALSE);

                    offset += 2;
                }
                else {
                    /* Less than 128 - only 7 bits */
                    proto_tree_add_bits_ret_val(pdu_subheader_tree, hf_mac_lte_sch_length,
                                                tvb, offset*8 + 1, 7, &length, FALSE);
                    offset++;
                }
                pdu_lengths[number_of_headers] = (gint16)length;
            }
            else {
                pdu_lengths[number_of_headers] = 0;
            }
        }


        /* Close off description in info column */
        switch (pdu_lengths[number_of_headers]) {
            case 0:
                write_pdu_label_and_info(pdu_ti, NULL, pinfo, ") ");
                break;
            case -1:
                write_pdu_label_and_info(pdu_ti, NULL, pinfo, ":remainder) ");
                break;
            default:
                write_pdu_label_and_info(pdu_ti, NULL, pinfo, ":%u bytes) ",
                                         pdu_lengths[number_of_headers]);
                break;
        }

        /* Append summary to subheader root */
        proto_item_append_text(pdu_subheader_ti, " (lcid=%s",
                               val_to_str(lcids[number_of_headers],
                                                (direction == DIRECTION_UPLINK) ?
                                                    ulsch_lcid_vals :
                                                        dlsch_lcid_vals,
                                                "Unknown"));

        switch (pdu_lengths[number_of_headers]) {
            case -1:
                proto_item_append_text(pdu_subheader_ti, ", length is remainder)");
                break;
            case 0:
                proto_item_append_text(pdu_subheader_ti, ")");
                break;
            default:
                proto_item_append_text(pdu_subheader_ti, ", length=%u)",
                                       pdu_lengths[number_of_headers]);
                break;
        }


        /* Flag unknown lcid values in expert info */
        if (match_strval(lcids[number_of_headers],
                         (direction == DIRECTION_UPLINK) ? ulsch_lcid_vals : dlsch_lcid_vals) == NULL) {
            expert_add_info_format(pinfo, pdu_subheader_ti, PI_MALFORMED, PI_ERROR,
                                   "%cL-SCH: Unexpected LCID received (%u)",
                                   (p_mac_lte_info->direction == DIRECTION_UPLINK) ? 'U' : 'D',
                                   lcids[number_of_headers]);
        }

        /* Set length of this subheader */
        proto_item_set_len(pdu_subheader_ti, offset- offset_start_subheader);

        number_of_headers++;
    } while (extension);

    /* Append summary to overall PDU header root */
    proto_item_append_text(pdu_header_ti, " (%u subheaders)",
                           number_of_headers);

    /* And set its length to offset */
    proto_item_set_len(pdu_header_ti, offset);




    /************************************************************************/
    /* Dissect SDUs / control elements / padding.                           */
    /************************************************************************/

    /* Dissect control element bodies first */

    for (n=0; n < number_of_headers; n++) {
        /* Get out of loop once see any data SDU subheaders */
        if (lcids[n] <= 10) {
            break;
        }

        /* Process what should be a valid control PDU type */
        if (direction == DIRECTION_DOWNLINK) {

            /****************************/
            /* DL-SCH Control PDUs      */
            switch (lcids[n]) {
                case UE_CONTENTION_RESOLUTION_IDENTITY_LCID:
                    {
                        proto_item *cr_ti;
                        proto_tree *cr_tree;
                        proto_item *ti;
                        ContentionResolutionResult *crResult;

                        /* Create CR root */
                        cr_ti = proto_tree_add_string_format(tree,
                                                             hf_mac_lte_control_ue_contention_resolution,
                                                             tvb, offset, 6,
                                                             "",
                                                             "Contention Resolution");
                        cr_tree = proto_item_add_subtree(cr_ti, ett_mac_lte_contention_resolution);


                        proto_tree_add_item(cr_tree, hf_mac_lte_control_ue_contention_resolution_identity,
                                            tvb, offset, 6, FALSE);

                        /* Get pointer to result struct for this frame */
                        crResult =  g_hash_table_lookup(mac_lte_cr_result_hash, GUINT_TO_POINTER(pinfo->fd->num));
                        if (crResult == NULL) {

                            /* Need to set result by looking for and comparing with Msg3 */
                            Msg3Data *msg3Data;
                            guint msg3Key = p_mac_lte_info->rnti;

                            /* Allocate result and add it to the table */
                            crResult = se_alloc(sizeof(ContentionResolutionResult));
                            g_hash_table_insert(mac_lte_cr_result_hash, GUINT_TO_POINTER(pinfo->fd->num), crResult);

                            /* Look for Msg3 */
                            msg3Data = g_hash_table_lookup(mac_lte_msg3_hash, GUINT_TO_POINTER(msg3Key));

                            /* Compare CCCH bytes */
                            if (msg3Data != NULL) {
                                crResult->msSinceMsg3 = (guint32)(((pinfo->fd->abs_ts.secs - msg3Data->msg3Time.secs) * 1000) +
                                                                  ((pinfo->fd->abs_ts.nsecs - msg3Data->msg3Time.nsecs) / 1000000));
                                crResult->msg3FrameNum = msg3Data->framenum;

                                /* Compare the 6 bytes */
                                if (memcmp(&msg3Data->data, tvb_get_ptr(tvb, offset, 6), 6) == 0) {
                                    crResult->status = Msg3Match;
                                }
                                else {
                                    crResult->status = Msg3NoMatch;
                                }
                            }
                            else {
                                crResult->status = NoMsg3;
                            }
                        }

                        /* Now show CR result in tree */
                        switch (crResult->status) {
                            case NoMsg3:
                                proto_item_append_text(cr_ti, " (no corresponding Msg3 found!)");
                                break;

                            case Msg3Match:
                                ti = proto_tree_add_uint(cr_tree, hf_mac_lte_control_ue_contention_resolution_msg3,
                                                         tvb, 0, 0, crResult->msg3FrameNum);
                                PROTO_ITEM_SET_GENERATED(ti);
                                ti = proto_tree_add_uint(cr_tree, hf_mac_lte_control_ue_contention_resolution_time_since_msg3,
                                                         tvb, 0, 0, crResult->msSinceMsg3);
                                PROTO_ITEM_SET_GENERATED(ti);

                                ti = proto_tree_add_boolean(cr_tree, hf_mac_lte_control_ue_contention_resolution_msg3_matched,
                                                            tvb, 0, 0, TRUE);
                                PROTO_ITEM_SET_GENERATED(ti);
                                proto_item_append_text(cr_ti, " (matches Msg3 from frame %u, %ums ago)",
                                                       crResult->msg3FrameNum, crResult->msSinceMsg3);
                                break;

                            case Msg3NoMatch:
                                ti = proto_tree_add_uint(cr_tree, hf_mac_lte_control_ue_contention_resolution_msg3,
                                                         tvb, 0, 0, crResult->msg3FrameNum);
                                PROTO_ITEM_SET_GENERATED(ti);
                                ti = proto_tree_add_uint(cr_tree, hf_mac_lte_control_ue_contention_resolution_time_since_msg3,
                                                         tvb, 0, 0, crResult->msSinceMsg3);
                                PROTO_ITEM_SET_GENERATED(ti);

                                ti = proto_tree_add_boolean(cr_tree, hf_mac_lte_control_ue_contention_resolution_msg3_matched,
                                                             tvb, 0, 0, FALSE);
                                expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_WARN,
                                                       "CR body in Msg4 doesn't match Msg3 CCCH in frame %u",
                                                       crResult->msg3FrameNum);
                                PROTO_ITEM_SET_GENERATED(ti);
                                proto_item_append_text(cr_ti, " (doesn't match Msg3 from frame %u, %u ago)",
                                                       crResult->msg3FrameNum, crResult->msSinceMsg3);
                                break;
                        };

                        offset += 6;
                    }
                    break;
                case TIMING_ADVANCE_LCID:
                    {
                        proto_item *ta_ti;
                        proto_item *reserved_ti;
                        guint8      reserved;
                        guint8      ta_value;

                        /* Check 2 reserved bits */
                        reserved = (tvb_get_guint8(tvb, offset) & 0xc0) >> 6;
                        reserved_ti = proto_tree_add_item(tree, hf_mac_lte_control_timing_advance_reserved, tvb, offset, 1, FALSE);
                        if (reserved != 0) {
                            expert_add_info_format(pinfo, reserved_ti, PI_MALFORMED, PI_ERROR,
                                                   "Timing Advance Reserved bits not zero (found 0x%x)", reserved);
                        }

                        /* TA value */
                        ta_value = tvb_get_guint8(tvb, offset) & 0x3f;
                        ta_ti = proto_tree_add_item(tree, hf_mac_lte_control_timing_advance,
                                                    tvb, offset, 1, FALSE);

                        if (ta_value == 31) {
                            expert_add_info_format(pinfo, ta_ti, PI_SEQUENCE,
                                                   PI_NOTE,
                                                   "Timing Advance control element received (no correction needed)");
                        }
                        else {
                            expert_add_info_format(pinfo, ta_ti, PI_SEQUENCE,
                                                   PI_WARN,
                                                   "Timing Advance control element received (%u) %s correction needed",
                                                   ta_value,
                                                   (ta_value < 31) ? "-ve" : "+ve");
                        }
                        offset++;
                    }
                    break;
                case DRX_COMMAND_LCID:
                    /* No payload */
                    break;
                case PADDING_LCID:
                    /* No payload (in this position) */
                    tap_info->padding_bytes++;
                    break;

                default:
                    break;
            }
        }
        else {

            /**********************************/
            /* UL-SCH Control PDUs            */
            switch (lcids[n]) {
                case POWER_HEADROOM_REPORT_LCID:
                    {
                        proto_item *phr_ti;
                        proto_tree *phr_tree;
                        proto_item *ti;
                        guint8 reserved;
                        guint8 level;

                        /* Create PHR root */
                        phr_ti = proto_tree_add_string_format(tree,
                                                              hf_mac_lte_control_power_headroom,
                                                              tvb, offset, 1,
                                                              "",
                                                              "Power Headroom");
                        phr_tree = proto_item_add_subtree(phr_ti, ett_mac_lte_power_headroom);

                        /* Check 2 Reserved bits */
                        reserved = (tvb_get_guint8(tvb, offset) & 0xc0) >> 6;
                        ti = proto_tree_add_item(phr_tree, hf_mac_lte_control_power_headroom_reserved,
                                                 tvb, offset, 1, FALSE);
                        if (reserved != 0) {
                            expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                                                   "Power Headroom Reserved bits not zero (found 0x%x)", reserved);
                        }

                        /* Level */
                        level = tvb_get_guint8(tvb, offset) & 0x3f;
                        proto_tree_add_item(phr_tree, hf_mac_lte_control_power_headroom_level,
                                            tvb, offset, 1, FALSE);

                        /* Show value in root label */
                        proto_item_append_text(phr_ti, " (%s)",
                                               val_to_str(level, power_headroom_size_vals, "Unknown"));
                        offset++;
                    }


                    break;
                case CRNTI_LCID:
                    proto_tree_add_item(tree, hf_mac_lte_control_crnti,
                                        tvb, offset, 2, FALSE);
                    offset += 2;
                    break;
                case TRUNCATED_BSR_LCID:
                case SHORT_BSR_LCID:
                    {
                        proto_tree *bsr_tree;
                        proto_item *bsr_ti;
                        proto_item *buffer_size_ti;
                        guint8 lcgid;
                        guint8 buffer_size;

                        bsr_ti = proto_tree_add_string_format(tree,
                                                              hf_mac_lte_control_bsr,
                                                              tvb, offset, 1,
                                                              "",
                                                              "Short BSR");
                        bsr_tree = proto_item_add_subtree(bsr_ti, ett_mac_lte_bsr);

                        /* LCG ID */
                        lcgid = (tvb_get_guint8(tvb, offset) & 0xc0) >> 6;
                        proto_tree_add_item(bsr_tree, hf_mac_lte_control_bsr_lcg_id,
                                                    tvb, offset, 1, FALSE);
                        /* Buffer Size */
                        buffer_size = tvb_get_guint8(tvb, offset) & 0x3f;
                        buffer_size_ti = proto_tree_add_item(bsr_tree, hf_mac_lte_control_short_bsr_buffer_size,
                                                             tvb, offset, 1, FALSE);
                        offset++;
                        if (buffer_size >= global_mac_lte_bsr_warn_threshold) {
                            expert_add_info_format(pinfo, buffer_size_ti, PI_SEQUENCE, PI_WARN,
                                                   "UE %u - BSR for LCG %u exceeds threshold: %u (%s)",
                                                   p_mac_lte_info->ueid,
                                                   lcgid,
                                                   buffer_size, val_to_str(buffer_size, buffer_size_vals, "Unknown"));
                        }


                        proto_item_append_text(bsr_ti, " (lcgid=%u  %s)",
                                               lcgid,
                                               val_to_str(buffer_size, buffer_size_vals, "Unknown"));
                    }
                    break;
                case LONG_BSR_LCID:
                    {
                        proto_tree *bsr_tree;
                        proto_item *bsr_ti;
                        proto_item *buffer_size_ti;
                        guint8     buffer_size[4];
                        bsr_ti = proto_tree_add_string_format(tree,
                                                              hf_mac_lte_control_bsr,
                                                              tvb, offset, 3,
                                                              "",
                                                              "Long BSR");
                        bsr_tree = proto_item_add_subtree(bsr_ti, ett_mac_lte_bsr);

                        /* LCID Group 0 */
                        buffer_size_ti = proto_tree_add_item(bsr_tree, hf_mac_lte_control_long_bsr_buffer_size_0,
                                                             tvb, offset, 1, FALSE);
                        buffer_size[0] = (tvb_get_guint8(tvb, offset) & 0xfc) >> 2;
                        if (buffer_size[0] >= global_mac_lte_bsr_warn_threshold) {
                            expert_add_info_format(pinfo, buffer_size_ti, PI_SEQUENCE, PI_WARN,
                                                   "UE %u - BSR for LCG 0 exceeds threshold: %u (%s)",
                                                   p_mac_lte_info->ueid,
                                                   buffer_size[0], val_to_str(buffer_size[0], buffer_size_vals, "Unknown"));
                        }

                        /* LCID Group 1 */
                        buffer_size_ti = proto_tree_add_item(bsr_tree, hf_mac_lte_control_long_bsr_buffer_size_1,
                                                             tvb, offset, 2, FALSE);
                        buffer_size[1] = ((tvb_get_guint8(tvb, offset) & 0x03) << 4) | ((tvb_get_guint8(tvb, offset+1) & 0xf0) >> 4);
                        offset++;
                        if (buffer_size[1] >= global_mac_lte_bsr_warn_threshold) {
                            expert_add_info_format(pinfo, buffer_size_ti, PI_SEQUENCE, PI_WARN,
                                                   "UE %u - BSR for LCG 1 exceeds threshold: %u (%s)",
                                                   p_mac_lte_info->ueid,
                                                   buffer_size[1], val_to_str(buffer_size[1], buffer_size_vals, "Unknown"));
                        }

                        /* LCID Group 2 */
                        buffer_size_ti = proto_tree_add_item(bsr_tree, hf_mac_lte_control_long_bsr_buffer_size_2,
                                                             tvb, offset, 2, FALSE);

                        buffer_size[2] = ((tvb_get_guint8(tvb, offset) & 0x0f) << 2) | ((tvb_get_guint8(tvb, offset+1) & 0xc0) >> 6);
                        offset++;
                        if (buffer_size[2] >= global_mac_lte_bsr_warn_threshold) {
                            expert_add_info_format(pinfo, buffer_size_ti, PI_SEQUENCE, PI_WARN,
                                                   "UE %u - BSR for LCG 2 exceeds threshold: %u (%s)",
                                                   p_mac_lte_info->ueid,
                                                   buffer_size[2], val_to_str(buffer_size[2], buffer_size_vals, "Unknown"));
                        }

                        /* LCID Group 3 */
                        buffer_size_ti = proto_tree_add_item(bsr_tree, hf_mac_lte_control_long_bsr_buffer_size_3,
                                                             tvb, offset, 1, FALSE);
                        buffer_size[3] = tvb_get_guint8(tvb, offset) & 0x3f;
                        offset++;
                        if (buffer_size[3] >= global_mac_lte_bsr_warn_threshold) {
                            expert_add_info_format(pinfo, buffer_size_ti, PI_SEQUENCE, PI_WARN,
                                                   "UE %u - BSR for LCG 3 exceeds threshold: %u (%s)",
                                                   p_mac_lte_info->ueid,
                                                   buffer_size[3], val_to_str(buffer_size[3], buffer_size_vals, "Unknown"));
                        }

                        /* Append summary to parent */
                        proto_item_append_text(bsr_ti, "   0:(%s)  1:(%s)  2:(%s)  3:(%s)",
                                               val_to_str(buffer_size[0], buffer_size_vals, "Unknown"),
                                               val_to_str(buffer_size[1], buffer_size_vals, "Unknown"),
                                               val_to_str(buffer_size[2], buffer_size_vals, "Unknown"),
                                               val_to_str(buffer_size[3], buffer_size_vals, "Unknown"));
                    }
                    break;
                case PADDING_LCID:
                    /* No payload, in this position */
                    tap_info->padding_bytes++;
                    break;

                default:
                    break;
            }
        }
    }


    /* There might not be any data, if only headers (plus control data) were logged */
    is_truncated = ((tvb_length_remaining(tvb, offset) == 0) && expecting_body_data);
    truncated_ti = proto_tree_add_uint(tree, hf_mac_lte_sch_header_only, tvb, 0, 0,
                                       is_truncated);
    if (is_truncated) {
        PROTO_ITEM_SET_GENERATED(truncated_ti);
        expert_add_info_format(pinfo, truncated_ti, PI_SEQUENCE, PI_NOTE,
                               "MAC PDU SDUs have been omitted");
        return;
    }
    else {
        PROTO_ITEM_SET_HIDDEN(truncated_ti);
    }


    /* Now process remaining bodies, which should all be data */
    for (; n < number_of_headers; n++) {

        /* Data SDUs treated identically for Uplink or downlink channels */
        proto_item *sdu_ti;
        const guint8 *pdu_data;
        volatile guint16 data_length;
        int i;
        char buff[64];

        /* Break out if meet padding */
        if (lcids[n] == PADDING_LCID) {
            break;
        }

        /* Work out length */
        data_length = (pdu_lengths[n] == -1) ?
                            tvb_length_remaining(tvb, offset) :
                            pdu_lengths[n];

        /* Dissect SDU as raw bytes */
        sdu_ti = proto_tree_add_bytes_format(tree, hf_mac_lte_sch_sdu, tvb, offset, pdu_lengths[n],
                                             tvb_get_ptr(tvb, offset, pdu_lengths[n]),
                                             "SDU (%s, length=%u bytes): ",
                                             val_to_str(lcids[n],
                                                              (direction == DIRECTION_UPLINK) ?
                                                                  ulsch_lcid_vals :
                                                                  dlsch_lcid_vals,
                                                             "Unknown"),
                                             data_length);
        /* Show bytes too.  There must be a nicer way of doing this! */
        pdu_data = tvb_get_ptr(tvb, offset, pdu_lengths[n]);
        for (i=0; i < data_length; i++) {
            g_snprintf(buff+(i*2), 3, "%02x",  pdu_data[i]);
            if (i >= 30) {
                g_snprintf(buff+(i*2), 4, "...");
                break;
            }
        }
        proto_item_append_text(sdu_ti, "%s", buff);


        /* Look for Msg3 data so that it may be compared with later
           Contention Resolution body */
        if ((lcids[n] == 0) && (direction == DIRECTION_UPLINK) && (data_length == 6)) {
            if (!pinfo->fd->flags.visited) {
                guint key = p_mac_lte_info->rnti;
                Msg3Data *data = g_hash_table_lookup(mac_lte_msg3_hash, GUINT_TO_POINTER(key));

                /* Look for previous entry for this UE */
                if (data == NULL) {
                    /* Allocate space for data and add to table */
                    data = se_alloc(sizeof(Msg3Data));
                    g_hash_table_insert(mac_lte_msg3_hash, GUINT_TO_POINTER(key), data);
                }

                /* Fill in data details */
                data->framenum = pinfo->fd->num;
                memcpy(&data->data, tvb_get_ptr(tvb, offset, data_length), data_length);
                data->msg3Time = pinfo->fd->abs_ts;
            }
        }

        /* CCCH frames can be dissected directly by LTE RRC... */
        if ((lcids[n] == 0) && global_mac_lte_attempt_rrc_decode) {
            tvbuff_t *rrc_tvb = tvb_new_subset(tvb, offset, data_length, data_length);

            /* Get appropriate dissector handle */
            volatile dissector_handle_t protocol_handle = 0;
            if (p_mac_lte_info->direction == DIRECTION_UPLINK) {
                protocol_handle = find_dissector("lte_rrc.ul_ccch");
            }
            else {
                protocol_handle = find_dissector("lte_rrc.dl_ccch");
            }

            /* Hide raw view of bytes */
            PROTO_ITEM_SET_HIDDEN(sdu_ti);

            call_with_catch_all(protocol_handle, rrc_tvb, pinfo, tree);
        }

        /* LCID 1 and 2 can be assumed to be srb1&2, so can dissect as RLC AM */
        else if ((lcids[n] == 1) || (lcids[n] == 2)) {
            if (global_mac_lte_attempt_srb_decode) {
                /* Call RLC dissector */
                call_rlc_dissector(tvb, pinfo, tree, pdu_ti, offset, data_length,
                                   RLC_AM_MODE, direction, p_mac_lte_info->ueid,
                                   CHANNEL_TYPE_SRB, lcids[n], 0);

                /* Hide raw view of bytes */
                PROTO_ITEM_SET_HIDDEN(sdu_ti);
            }
        }

        else if ((lcids[n] >= 2) && (lcids[n] <= 10)) {

            /* Look for mapping for this LCID to drb channel set by UAT table */
            rlc_channel_type_t rlc_channel_type = rlcRaw;
            guint8 UM_seqnum_length = 0;
            gint drb_id = 0;

            guint m;
            for (m=0; m < num_lcid_drb_mappings; m++) {
                if (lcids[n] == lcid_drb_mappings[m].lcid) {

                    rlc_channel_type = lcid_drb_mappings[m].channel_type;

                    /* Set UM_seqnum_length */
                    switch (lcid_drb_mappings[m].channel_type) {
                        case rlcUM5:
                            UM_seqnum_length = 5;
                            break;
                        case rlcUM10:
                            UM_seqnum_length = 10;
                            break;
                        default:
                            break;
                    }

                    /* Set drb_id */
                    drb_id = lcid_drb_mappings[m].drbid;
                    break;
                }
            }

            /* Dissect according to channel type */
            switch (rlc_channel_type) {
                case rlcUM5:
                    call_rlc_dissector(tvb, pinfo, tree, pdu_ti, offset, data_length,
                                       RLC_UM_MODE, direction, p_mac_lte_info->ueid,
                                       CHANNEL_TYPE_DRB, (guint16)drb_id, UM_seqnum_length);
                    break;
                case rlcUM10:
                    call_rlc_dissector(tvb, pinfo, tree, pdu_ti, offset, data_length,
                                       RLC_UM_MODE, direction, p_mac_lte_info->ueid,
                                       CHANNEL_TYPE_DRB, (guint16)drb_id, UM_seqnum_length);
                    break;
                case rlcAM:
                    call_rlc_dissector(tvb, pinfo, tree, pdu_ti, offset, data_length,
                                       RLC_AM_MODE, direction, p_mac_lte_info->ueid,
                                       CHANNEL_TYPE_DRB, (guint16)drb_id, 0);
                    break;
                case rlcTM:
                    call_rlc_dissector(tvb, pinfo, tree, pdu_ti, offset, data_length,
                                       RLC_TM_MODE, direction, p_mac_lte_info->ueid,
                                       CHANNEL_TYPE_DRB, (guint16)drb_id, 0);
                    break;
                case rlcRaw:
                    /* Nothing to do! */
                    break;
            }

            if (rlc_channel_type != rlcRaw) {
                /* Hide raw view of bytes */
                PROTO_ITEM_SET_HIDDEN(sdu_ti);
            }

        }

        offset += data_length;

        /* Update tap byte count for this channel */
        tap_info->bytes_for_lcid[lcids[n]] += data_length;
        tap_info->sdus_for_lcid[lcids[n]]++;
    }

    /* Now padding, if present, extends to the end of the PDU */
    if (lcids[number_of_headers-1] == PADDING_LCID) {
        if (tvb_length_remaining(tvb, offset) > 0) {
            proto_tree_add_item(tree, hf_mac_lte_padding_data,
                                tvb, offset, -1, FALSE);
        }
        padding_length_ti = proto_tree_add_int(tree, hf_mac_lte_padding_length,
                                               tvb, offset, 0,
                                               p_mac_lte_info->length - offset);
        PROTO_ITEM_SET_GENERATED(padding_length_ti);

        /* Update padding bytes in stats */
        tap_info->padding_bytes += (p_mac_lte_info->length - offset);

        /* Make sure the PDU isn't bigger than reported! */
        if (offset > p_mac_lte_info->length) {
            expert_add_info_format(pinfo, padding_length_ti, PI_MALFORMED, PI_ERROR,
                                   "MAC PDU is longer than reported length (reported=%u, actual=%u)",
                                   p_mac_lte_info->length, offset);
        }
    }
    else {
        /* There is no padding at the end of the frame */
        if (!is_truncated && (offset < p_mac_lte_info->length)) {
            /* There is a problem if we haven't used all of the PDU */
            expert_add_info_format(pinfo, pdu_ti, PI_MALFORMED, PI_ERROR,
                                   "PDU for UE %u is shorter than reported length (reported=%u, actual=%u)",
                                   p_mac_lte_info->ueid, p_mac_lte_info->length, offset);
        }

        if (!is_truncated && (offset > p_mac_lte_info->length)) {
            /* There is a problem if the PDU is longer than rpeported */
            expert_add_info_format(pinfo, pdu_ti, PI_MALFORMED, PI_ERROR,
                                   "PDU for UE %u is longer than reported length (reported=%u, actual=%u)",
                                   p_mac_lte_info->ueid, p_mac_lte_info->length, offset);
        }
    }
}



/*****************************/
/* Main dissection function. */
void dissect_mac_lte(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree             *mac_lte_tree;
    proto_item             *pdu_ti;
    proto_tree             *context_tree;
    proto_item             *context_ti;
    proto_item             *retx_ti = NULL;
    proto_item             *ti;
    gint                   offset = 0;
    struct mac_lte_info    *p_mac_lte_info = NULL;

    /* Allocate and zero tap struct */
    mac_lte_tap_info *tap_info = ep_alloc0(sizeof(mac_lte_tap_info));

    /* Set protocol name */
    //col_set_str(pinfo->cinfo, COL_PROTOCOL, "MAC-LTE-DAN");

    /* Create protocol tree. */
    pdu_ti = proto_tree_add_item(tree, proto_mac_lte_dan, tvb, offset, -1, FALSE);
    proto_item_append_text(pdu_ti, " ");
    mac_lte_tree = proto_item_add_subtree(pdu_ti, ett_mac_lte);


    /* Look for packet info! */
    p_mac_lte_info = p_get_proto_data(pinfo->fd, proto_mac_lte_dan);

    /* Can't dissect anything without it... */
    if (p_mac_lte_info == NULL) {
        proto_item *tii =
            proto_tree_add_text(mac_lte_tree, tvb, offset, -1,
                                "Can't dissect LTE MAC frame because no per-frame info was attached!");
        PROTO_ITEM_SET_GENERATED(tii);
        return;
    }

    /* Clear info column */
    col_clear(pinfo->cinfo, COL_INFO);


    /*****************************************/
    /* Show context information              */

    /* Create context root */
    context_ti = proto_tree_add_string_format(mac_lte_tree, hf_mac_lte_context,
                                              tvb, offset, 0, "", "Context");
    context_tree = proto_item_add_subtree(context_ti, ett_mac_lte_context);
    PROTO_ITEM_SET_GENERATED(context_ti);

    ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_radio_type,
                             tvb, 0, 0, p_mac_lte_info->radioType);
    PROTO_ITEM_SET_GENERATED(ti);

    ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_direction,
                             tvb, 0, 0, p_mac_lte_info->direction);
    PROTO_ITEM_SET_GENERATED(ti);

    if (p_mac_lte_info->ueid != 0) {
        ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_ueid,
                                 tvb, 0, 0, p_mac_lte_info->ueid);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    /* There are several out-of-band MAC events that may be indicated in the context info. */
    /* Handle them here */
    if (p_mac_lte_info->length == 0) {
        proto_item *preamble_ti;
        proto_tree *preamble_tree;

        switch (p_mac_lte_info->oob_event) {
            case ltemac_send_preamble:
                preamble_ti = proto_tree_add_item(mac_lte_tree, hf_mac_lte_oob_send_preamble,
                                                  tvb, 0, 0, FALSE);
                preamble_tree = proto_item_add_subtree(preamble_ti, ett_mac_lte_oob);
                PROTO_ITEM_SET_GENERATED(ti);

                ti = proto_tree_add_uint(preamble_tree, hf_mac_lte_context_rapid,
                                         tvb, 0, 0, p_mac_lte_info->rapid);
                PROTO_ITEM_SET_GENERATED(ti);

                ti = proto_tree_add_uint(preamble_tree, hf_mac_lte_context_rach_attempt_number,
                                         tvb, 0, 0, p_mac_lte_info->rach_attempt_number);
                PROTO_ITEM_SET_GENERATED(ti);

                /* Info column */
                write_pdu_label_and_info(pdu_ti, preamble_ti, pinfo,
                                         "RACH Preamble sent for UE %u (RAPID=%u, attempt=%u)",
                                         p_mac_lte_info->ueid, p_mac_lte_info->rapid, p_mac_lte_info->rach_attempt_number);

                /* Add expert info (a note, unless attempt > 1) */
                expert_add_info_format(pinfo, ti, PI_SEQUENCE,
                                       (p_mac_lte_info->rach_attempt_number > 1) ? PI_WARN : PI_NOTE,
                                       "RACH Preamble sent for UE %u (RAPID=%u, attempt=%u)",
                                       p_mac_lte_info->ueid, p_mac_lte_info->rapid,
                                       p_mac_lte_info->rach_attempt_number);
                break;
            case ltemac_send_sr:
                ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_rnti,
                                         tvb, 0, 0, p_mac_lte_info->rnti);
                PROTO_ITEM_SET_GENERATED(ti);

                ti = proto_tree_add_item(mac_lte_tree, hf_mac_lte_oob_send_sr,
                                         tvb, 0, 0, FALSE);
                PROTO_ITEM_SET_GENERATED(ti);

                /* Info column */
                write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                                         "Scheduling Request sent for UE %u (C-RNTI=%u)",
                                         p_mac_lte_info->ueid, p_mac_lte_info->rnti);

                /* Add expert info (an note) */
                expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_NOTE,
                                       "Scheduling Request send for UE %u (RNTI %u)",
                                       p_mac_lte_info->ueid, p_mac_lte_info->rnti);

                /* Update SR status */
                if (global_mac_lte_track_sr) {
                    TrackSRInfo(SR_Request, pinfo, mac_lte_tree, tvb, p_mac_lte_info->rnti, ti);
                }
                break;
            case ltemac_sr_failure:
                ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_rnti,
                                         tvb, 0, 0, p_mac_lte_info->rnti);
                PROTO_ITEM_SET_GENERATED(ti);

                ti = proto_tree_add_item(mac_lte_tree, hf_mac_lte_oob_sr_failure,
                                         tvb, 0, 0, FALSE);
                PROTO_ITEM_SET_GENERATED(ti);

                /* Info column */
                write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                                         "Scheduling Request FAILED for UE %u (C-RNTI=%u)",
                                         p_mac_lte_info->ueid,
                                         p_mac_lte_info->rnti);

                /* Add expert info (an error) */
                expert_add_info_format(pinfo, ti, PI_SEQUENCE, PI_ERROR,
                                       "Scheduling Request failed for UE %u (RNTI %u)",
                                       p_mac_lte_info->ueid,
                                       p_mac_lte_info->rnti);

                /* Update SR status */
                if (global_mac_lte_track_sr) {
                    TrackSRInfo(SR_Failure, pinfo, mac_lte_tree, tvb, p_mac_lte_info->rnti, ti);
                }

                break;
        }

        /* Our work here is done */
        return;
    }


    ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_subframe_number,
                             tvb, 0, 0, p_mac_lte_info->subframeNumber);
    PROTO_ITEM_SET_GENERATED(ti);
    if (p_mac_lte_info->subframeNumber > 9) {
        expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                               "Subframe number was out of range - using max (9) instead");
        p_mac_lte_info->subframeNumber = 9;
    }

    if (p_mac_lte_info->subframeNumberOfGrantPresent) {
        ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_grant_subframe_number,
                                 tvb, 0, 0, p_mac_lte_info->subframeNumberOfGrant);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    if (p_mac_lte_info->rntiType != NO_RNTI) {
        ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_rnti,
                                 tvb, 0, 0, p_mac_lte_info->rnti);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_rnti_type,
                             tvb, 0, 0, p_mac_lte_info->rntiType);
    PROTO_ITEM_SET_GENERATED(ti);

    ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_predefined_frame,
                             tvb, 0, 0, p_mac_lte_info->isPredefinedData);
    if (p_mac_lte_info->isPredefinedData) {
        PROTO_ITEM_SET_GENERATED(ti);
    }
    else {
        PROTO_ITEM_SET_HIDDEN(ti);
    }

    ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_length,
                             tvb, 0, 0, p_mac_lte_info->length);
    PROTO_ITEM_SET_GENERATED(ti);
    /* Infer uplink grant size */
    if (p_mac_lte_info->direction == DIRECTION_UPLINK) {
        ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_ul_grant_size,
                                 tvb, 0, 0, p_mac_lte_info->length);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    /* Retx count goes in top-level tree to make it more visible */
    if (p_mac_lte_info->reTxCount) {
        retx_ti = proto_tree_add_uint(mac_lte_tree, hf_mac_lte_context_retx_count,
                                 tvb, 0, 0, p_mac_lte_info->reTxCount);
        PROTO_ITEM_SET_GENERATED(retx_ti);

        if (p_mac_lte_info->reTxCount >= global_mac_lte_retx_counter_trigger) {
            expert_add_info_format(pinfo, retx_ti, PI_SEQUENCE, PI_ERROR,
                                   "UE %u: UL MAC frame ReTX no. %u",
                                   p_mac_lte_info->ueid, p_mac_lte_info->reTxCount);
        }
    }

    if (p_mac_lte_info->crcStatusValid) {
        ti = proto_tree_add_uint(context_tree, hf_mac_lte_context_crc_status,
                                 tvb, 0, 0, p_mac_lte_info->detailed_phy_info.dl_info.crc_status);
        PROTO_ITEM_SET_GENERATED(ti);
        if (p_mac_lte_info->detailed_phy_info.dl_info.crc_status != TRUE) {
            expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR,
                                   "%s Frame has CRC error",
                                   (p_mac_lte_info->direction == DIRECTION_UPLINK) ? "UL" : "DL");
            write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                                     "%s: <CRC FAILURE> UEId=%u %s=%u ",
                                     (p_mac_lte_info->direction == DIRECTION_UPLINK) ? "UL" : "DL",
                                     p_mac_lte_info->ueid,
                                     val_to_str(p_mac_lte_info->rntiType, rnti_type_vals,
                                                      "Unknown RNTI type"),
                                     p_mac_lte_info->rnti);
        }
    }

    /* May also have extra Physical layer attributes set for this frame */
    show_extra_phy_parameters(pinfo, tvb, mac_lte_tree, p_mac_lte_info);

    /* Set context-info parts of tap struct */
    tap_info->rnti = p_mac_lte_info->rnti;
    tap_info->ueid = p_mac_lte_info->ueid;
    tap_info->rntiType = p_mac_lte_info->rntiType;
    tap_info->isPredefinedData = p_mac_lte_info->isPredefinedData;
    tap_info->isPHYRetx = (p_mac_lte_info->reTxCount >= 1);
    tap_info->crcStatusValid = p_mac_lte_info->crcStatusValid;
    tap_info->crcStatus = p_mac_lte_info->detailed_phy_info.dl_info.crc_status;
    tap_info->direction = p_mac_lte_info->direction;

    tap_info->time = pinfo->fd->abs_ts;

    /* Also set total number of bytes (won't be used for UL/DL-SCH) */
    tap_info->single_number_of_bytes = tvb_length_remaining(tvb, offset);

    /* If we know its predefined data, don't try to decode any further */
    if (p_mac_lte_info->isPredefinedData) {
        proto_tree_add_item(mac_lte_tree, hf_mac_lte_predefined_pdu, tvb, offset, -1, FALSE);
        write_pdu_label_and_info(pdu_ti, NULL, pinfo,
                                 "Predefined data (%u bytes)",
                                 tvb_length_remaining(tvb, offset));

        /* Queue tap info */
        if (!pinfo->flags.in_error_pkt) {
            tap_queue_packet(mac_lte_tap, pinfo, tap_info);
        }

        return;
    }

    /* IF CRC status failed, just do decode as raw bytes */
    if (!global_mac_lte_dissect_crc_failures &&
        (p_mac_lte_info->crcStatusValid && !p_mac_lte_info->detailed_phy_info.dl_info.crc_status)) {

        proto_tree_add_item(mac_lte_tree, hf_mac_lte_raw_pdu, tvb, offset, -1, FALSE);
        write_pdu_label_and_info(pdu_ti, NULL, pinfo, "Raw data (%u bytes)", tvb_length_remaining(tvb, offset));

        /* Queue tap info.
           TODO: unfortunately DL retx detection won't get done if we return here... */
        if (!pinfo->flags.in_error_pkt) {
            tap_queue_packet(mac_lte_tap, pinfo, tap_info);
        }

        return;
    }

    /* Reset this counter */
    s_number_of_rlc_pdus_shown = 0;

    /* Dissect the MAC PDU itself. Format depends upon RNTI type. */
    switch (p_mac_lte_info->rntiType) {

        case P_RNTI:
            /* PCH PDU */
            dissect_pch(tvb, pinfo, mac_lte_tree, pdu_ti, offset, p_mac_lte_info->direction);
            break;

        case RA_RNTI:
            /* RAR PDU */
            dissect_rar(tvb, pinfo, mac_lte_tree, pdu_ti, offset, p_mac_lte_info, tap_info);
            break;

        case C_RNTI:
        case SPS_RNTI:
            /* Can be UL-SCH or DL-SCH */
            dissect_ulsch_or_dlsch(tvb, pinfo, mac_lte_tree, pdu_ti, offset,
                                   p_mac_lte_info->direction, p_mac_lte_info, tap_info,
                                   retx_ti, context_tree);
            break;

        case SI_RNTI:
            /* BCH over DL-SCH */
            dissect_bch(tvb, pinfo, mac_lte_tree, pdu_ti, offset, p_mac_lte_info);
            break;

        case NO_RNTI:
            /* Must be BCH over BCH... */
            dissect_bch(tvb, pinfo, mac_lte_tree, pdu_ti, offset, p_mac_lte_info);
            break;


        default:
            break;
    }

    /* Queue tap info */
    tap_queue_packet(mac_lte_tap, pinfo, tap_info);
}

/* Added by Yosi for use of attaching the mac_lte_info struct to the pinfo */
void attach_mac_info_to_dan(packet_info *pinfo, mac_lte_info *mac_info)
{
    p_add_proto_data(pinfo->fd, proto_mac_lte_dan, mac_info);
}


/* Initializes the hash table and the mem_chunk area each time a new
 * file is loaded or re-loaded in wireshark */
static void
mac_lte_init_protocol(void)
{
    /* Destroy any existing tables. */
    if (mac_lte_msg3_hash) {
        g_hash_table_destroy(mac_lte_msg3_hash);
    }
    if (mac_lte_cr_result_hash) {
        g_hash_table_destroy(mac_lte_cr_result_hash);
    }

    if (mac_lte_dl_harq_hash) {
        g_hash_table_destroy(mac_lte_dl_harq_hash);
    }
    if (mac_lte_dl_harq_result_hash) {
        g_hash_table_destroy(mac_lte_dl_harq_result_hash);
    }
    if (mac_lte_ul_harq_hash) {
        g_hash_table_destroy(mac_lte_ul_harq_hash);
    }
    if (mac_lte_ul_harq_result_hash) {
        g_hash_table_destroy(mac_lte_ul_harq_result_hash);
    }
    if (mac_lte_ue_sr_state) {
        g_hash_table_destroy(mac_lte_ue_sr_state);
    }
    if (mac_lte_sr_request_hash) {
        g_hash_table_destroy(mac_lte_sr_request_hash);
    }

    /* Now create them over */
    mac_lte_msg3_hash = g_hash_table_new(mac_lte_rnti_hash_func, mac_lte_rnti_hash_equal);
    mac_lte_cr_result_hash = g_hash_table_new(mac_lte_framenum_hash_func, mac_lte_framenum_hash_equal);

    mac_lte_dl_harq_hash = g_hash_table_new(mac_lte_rnti_hash_func, mac_lte_rnti_hash_equal);
    mac_lte_dl_harq_result_hash = g_hash_table_new(mac_lte_framenum_hash_func, mac_lte_framenum_hash_equal);

    mac_lte_ul_harq_hash = g_hash_table_new(mac_lte_rnti_hash_func, mac_lte_rnti_hash_equal);
    mac_lte_ul_harq_result_hash = g_hash_table_new(mac_lte_framenum_hash_func, mac_lte_framenum_hash_equal);

    mac_lte_ue_sr_state = g_hash_table_new(mac_lte_rnti_hash_func, mac_lte_rnti_hash_equal);
    mac_lte_sr_request_hash = g_hash_table_new(mac_lte_framenum_hash_func, mac_lte_framenum_hash_equal);
}


static void* lcid_drb_mapping_copy_cb(void* dest, const void* orig, unsigned len _U_)
{
    const lcid_drb_mapping_t *o = orig;
    lcid_drb_mapping_t *d = dest;

    /* Copy all items over */
    d->lcid = o->lcid;
    d->drbid = o->drbid;
    d->channel_type = o->channel_type;

    return d;
}



void proto_register_mac_lte(void)
{
    static hf_register_info hf[] =
    {
        /**********************************/
        /* Items for decoding context     */
        { &hf_mac_lte_context,
            { "Context",
              "mac-lte.context", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_radio_type,
            { "Radio Type",
              "mac-lte.radio-type", FT_UINT8, BASE_DEC, VALS(radio_type_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_direction,
            { "Direction",
              "mac-lte.direction", FT_UINT8, BASE_DEC, VALS(direction_vals), 0x0,
              "Direction of message", HFILL
            }
        },
        { &hf_mac_lte_context_rnti,
            { "RNTI",
              "mac-lte.rnti", FT_UINT16, BASE_DEC, 0, 0x0,
              "RNTI associated with message", HFILL
            }
        },
        { &hf_mac_lte_context_rnti_type,
            { "RNTI Type",
              "mac-lte.rnti-type", FT_UINT8, BASE_DEC, VALS(rnti_type_vals), 0x0,
              "Type of RNTI associated with message", HFILL
            }
        },
        { &hf_mac_lte_context_ueid,
            { "UEId",
              "mac-lte.ueid", FT_UINT16, BASE_DEC, 0, 0x0,
              "User Equipment Identifier associated with message", HFILL
            }
        },
        { &hf_mac_lte_context_subframe_number,
            { "Subframe",
              "mac-lte.subframe", FT_UINT16, BASE_DEC, 0, 0x0,
              "Subframe number associated with message", HFILL
            }
        },
        { &hf_mac_lte_context_grant_subframe_number,
            { "Grant Subframe",
              "mac-lte.grant-subframe", FT_UINT16, BASE_DEC, 0, 0x0,
              "Subframe grant for this PDU was received", HFILL
            }
        },
        { &hf_mac_lte_context_predefined_frame,
            { "Predefined frame",
              "mac-lte.is-predefined-frame", FT_UINT8, BASE_DEC, VALS(predefined_frame_vals), 0x0,
              "Predefined test frame (or real MAC PDU)", HFILL
            }
        },
        { &hf_mac_lte_context_length,
            { "Length of frame",
              "mac-lte.length", FT_UINT8, BASE_DEC, 0, 0x0,
              "Original length of frame (including SDUs and padding)", HFILL
            }
        },
        { &hf_mac_lte_context_ul_grant_size,
            { "Uplink grant size",
              "mac-lte.ul-grant-size", FT_UINT8, BASE_DEC, 0, 0x0,
              "Uplink grant size (in bytes)", HFILL
            }
        },
        { &hf_mac_lte_context_bch_transport_channel,
            { "Transport channel",
              "mac-lte.bch-transport-channel", FT_UINT8, BASE_DEC, VALS(bch_transport_channel_vals), 0x0,
              "Transport channel BCH data was carried on", HFILL
            }
        },
        { &hf_mac_lte_context_retx_count,
            { "ReTX count",
              "mac-lte.retx-count", FT_UINT8, BASE_DEC, 0, 0x0,
              "Number of times this PDU has been retransmitted", HFILL
            }
        },
        { &hf_mac_lte_context_crc_status,
            { "CRC Status",
              "mac-lte.crc-status", FT_UINT8, BASE_DEC, VALS(crc_status_vals), 0x0,
              "CRC Status as reported by PHY", HFILL
            }
        },
        { &hf_mac_lte_context_rapid,
            { "RAPID",
              "mac-lte.preamble-sent.rapid", FT_UINT8, BASE_DEC, 0, 0x0,
              "RAPID sent in RACH preamble", HFILL
            }
        },
        { &hf_mac_lte_context_rach_attempt_number,
            { "RACH Attempt Number",
              "mac-lte.preamble-sent.attempt", FT_UINT8, BASE_DEC, 0, 0x0,
              "RACH attempt number", HFILL
            }
        },

        /* Extra PHY context */
        { &hf_mac_lte_context_phy_ul,
            { "UL PHY attributes",
              "mac-lte.ul-phy", FT_STRING, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_ul_modulation_type,
            { "Modulation type",
              "mac-lte.ul-phy.modulation-type", FT_UINT8, BASE_DEC, VALS(modulation_type_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_ul_tbs_index,
            { "TBs Index",
              "mac-lte.ul-phy.tbs-index", FT_UINT8, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_ul_resource_block_length,
            { "Resource Block Length",
              "mac-lte.ul-phy.resource-block-length", FT_UINT8, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_ul_resource_block_start,
            { "Resource Block Start",
              "mac-lte.ul-phy.resource-block-start", FT_UINT8, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },


        { &hf_mac_lte_context_phy_dl,
            { "DL PHY attributes",
              "mac-lte.dl-phy", FT_STRING, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_dci_format,
            { "DCI format",
              "mac-lte.dl-phy.dci-format", FT_UINT8, BASE_DEC, VALS(dci_format_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_resource_allocation_type,
            { "Resource Allocation Type",
              "mac-lte.dl-phy.resource-allocation-type", FT_UINT8, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_aggregation_level,
            { "Aggregation Level",
              "mac-lte.dl-phy.aggregation-level", FT_UINT8, BASE_DEC, VALS(aggregation_level_vals), 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_mcs_index,
            { "MCS Index",
              "mac-lte.dl-phy.mcs-index", FT_UINT8, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_redundancy_version_index,
            { "RV Index",
              "mac-lte.dl-phy.rv-index", FT_UINT8, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_resource_block_length,
            { "RB Length",
              "mac-lte.dl-phy.rb-length", FT_UINT8, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_context_phy_dl_crc_status,
            { "CRC Status",
              "mac-lte.dl-phy.crc-status", FT_UINT8, BASE_DEC, VALS(crc_status_vals), 0x0,
              NULL, HFILL
            }
        },

        /* Out-of-band events */
        { &hf_mac_lte_oob_send_preamble,
            { "PRACH: ",
              "mac-lte.preamble-sent", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_oob_send_sr,
            { "Scheduling Request sent",
              "mac-lte.sr-req", FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_oob_sr_failure,
            { "Scheduling Request failure",
              "mac-lte.sr-failure", FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },

        /*******************************************/
        /* MAC shared channel header fields        */
        { &hf_mac_lte_ulsch,
            { "UL-SCH",
              "mac-lte.ulsch", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_ulsch_header,
            { "UL-SCH Header",
              "mac-lte.ulsch.header", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_dlsch_header,
            { "DL-SCH Header",
              "mac-lte.dlsch.header", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_dlsch,
            { "DL-SCH",
              "mac-lte.dlsch", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sch_subheader,
            { "SCH sub-header",
              "mac-lte.sch.subheader", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sch_reserved,
            { "SCH reserved bits",
              "mac-lte.sch.reserved", FT_UINT8, BASE_HEX, NULL, 0xc0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sch_extended,
            { "Extension",
              "mac-lte.sch.extended", FT_UINT8, BASE_HEX, 0, 0x20,
              "Extension - i.e. further headers after this one", HFILL
            }
        },
        { &hf_mac_lte_dlsch_lcid,
            { "LCID",
              "mac-lte.dlsch.lcid", FT_UINT8, BASE_HEX, VALS(dlsch_lcid_vals), 0x1f,
              "DL-SCH Logical Channel Identifier", HFILL
            }
        },
        { &hf_mac_lte_ulsch_lcid,
            { "LCID",
              "mac-lte.ulsch.lcid", FT_UINT8, BASE_HEX, VALS(ulsch_lcid_vals), 0x1f,
              "UL-SCH Logical Channel Identifier", HFILL
            }
        },
        { &hf_mac_lte_sch_format,
            { "Format",
              "mac-lte.sch.format", FT_UINT8, BASE_HEX, VALS(format_vals), 0x80,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sch_length,
            { "Length",
              "mac-lte.sch.length", FT_UINT16, BASE_DEC, 0, 0x0,
              "Length of MAC SDU or MAC control element", HFILL
            }
        },
        { &hf_mac_lte_sch_header_only,
            { "MAC PDU Header only",
              "mac-lte.sch.header-only", FT_UINT8, BASE_DEC, VALS(header_only_vals), 0x0,
              NULL, HFILL
            }
        },

        /********************************/
        /* Data                         */
        { &hf_mac_lte_sch_sdu,
            { "SDU",
              "mac-lte.sch.sdu", FT_BYTES, BASE_NONE, 0, 0x0,
              "Shared channel SDU", HFILL
            }
        },
        { &hf_mac_lte_bch_pdu,
            { "BCH PDU",
              "mac-lte.bch.pdu", FT_BYTES, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_pch_pdu,
            { "PCH PDU",
              "mac-lte.pch.pdu", FT_BYTES, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_predefined_pdu,
            { "Predefined data",
              "mac-lte.predefined-data", FT_BYTES, BASE_NONE, 0, 0x0,
              "Predefined test data", HFILL
            }
        },
        { &hf_mac_lte_raw_pdu,
            { "Raw data",
              "mac-lte.raw-data", FT_BYTES, BASE_NONE, 0, 0x0,
              "Raw bytes of PDU (e.g. if CRC failed)", HFILL
            }
        },
        { &hf_mac_lte_padding_data,
            { "Padding data",
              "mac-lte.padding-data", FT_BYTES, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_padding_length,
            { "Padding length",
              "mac-lte.padding-length", FT_INT32, BASE_DEC, 0, 0x0,
              "Length of padding data not included at end of frame", HFILL
            }
        },



        /*********************************/
        /* RAR fields                    */
        { &hf_mac_lte_rar,
            { "RAR",
              "mac-lte.rar", FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_headers,
            { "RAR Headers",
              "mac-lte.rar.headers", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_header,
            { "RAR Header",
              "mac-lte.rar.header", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_extension,
            { "Extension",
              "mac-lte.rar.e", FT_UINT8, BASE_HEX, 0, 0x80,
              "Extension - i.e. further RAR headers after this one", HFILL
            }
        },
        { &hf_mac_lte_rar_t,
            { "Type",
              "mac-lte.rar.t", FT_UINT8, BASE_HEX, VALS(rar_type_vals), 0x40,
              "Type field indicating whether the payload is RAPID or BI", HFILL
            }
        },
        { &hf_mac_lte_rar_bi,
            { "BI",
              "mac-lte.rar.bi", FT_UINT8, BASE_HEX, VALS(rar_bi_vals), 0x0f,
              "Backoff Indicator (ms)", HFILL
            }
        },
        { &hf_mac_lte_rar_rapid,
            { "RAPID",
              "mac-lte.rar.rapid", FT_UINT8, BASE_HEX_DEC, 0, 0x3f,
              "Random Access Preamble IDentifier", HFILL
            }
        },
        { &hf_mac_lte_rar_reserved,
            { "Reserved",
              "mac-lte.rar.reserved", FT_UINT8, BASE_HEX, 0, 0x30,
              "Reserved bits in RAR header - should be 0", HFILL
            }
        },

        { &hf_mac_lte_rar_body,
            { "RAR Body",
              "mac-lte.rar.body", FT_STRING, BASE_NONE, NULL, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_reserved2,
            { "Reserved",
              "mac-lte.rar.reserved2", FT_UINT8, BASE_HEX, 0, 0x80,
              "Reserved bit in RAR body - should be 0", HFILL
            }
        },
        { &hf_mac_lte_rar_ta,
            { "Timing Advance",
              "mac-lte.rar.ta", FT_UINT16, BASE_DEC, 0, 0x7ff0,
              "Required adjustment to uplink transmission timing", HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant,
            { "UL Grant",
              "mac-lte.rar.ul-grant", FT_UINT24, BASE_DEC, 0, 0x0fffff,
              "Size of UL Grant", HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_hopping,
            { "Hopping Flag",
              "mac-lte.rar.ul-grant.hopping", FT_UINT8, BASE_DEC, 0, 0x08,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_fsrba,
            { "Fixed sized resource block assignment",
              "mac-lte.rar.ul-grant.fsrba", FT_UINT16, BASE_DEC, 0, 0x07fe,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_tmcs,
            { "Truncated Modulation and coding scheme",
              "mac-lte.rar.ul-grant.tmcs", FT_UINT16, BASE_DEC, 0, 0x01e0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_tcsp,
            { "TPC command for scheduled PUSCH",
              "mac-lte.rar.ul-grant.tcsp", FT_UINT8, BASE_DEC, 0, 0x01c,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_ul_delay,
            { "UL Delay",
              "mac-lte.rar.ul-grant.ul-delay", FT_UINT8, BASE_DEC, 0, 0x02,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_ul_grant_cqi_request,
            { "CQI Request",
              "mac-lte.rar.ul-grant.cqi-request", FT_UINT8, BASE_DEC, 0, 0x01,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_rar_temporary_crnti,
            { "Temporary C-RNTI",
              "mac-lte.rar.temporary-crnti", FT_UINT16, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },

        /**********************/
        /* Control PDU fields */
        { &hf_mac_lte_control_bsr,
            { "BSR",
              "mac-lte.control.bsr", FT_STRING, BASE_NONE, 0, 0x0,
              "Buffer Status Report", HFILL
            }
        },
        { &hf_mac_lte_control_bsr_lcg_id,
            { "Logical Channel Group ID",
              "mac-lte.control.bsr.lcg-id", FT_UINT8, BASE_DEC, 0, 0xc0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_short_bsr_buffer_size,
            { "Buffer Size",
              "mac-lte.control.bsr.buffer-size", FT_UINT8, BASE_DEC, VALS(buffer_size_vals), 0x3f,
              "Buffer Size available in all channels in group", HFILL
            }
        },
        { &hf_mac_lte_control_long_bsr_buffer_size_0,
            { "Buffer Size 0",
              "mac-lte.control.bsr.buffer-size-0", FT_UINT8, BASE_DEC, VALS(buffer_size_vals), 0xfc,
              "Buffer Size available in logical channel group 0", HFILL
            }
        },
        { &hf_mac_lte_control_long_bsr_buffer_size_1,
            { "Buffer Size 1",
              "mac-lte.control.bsr.buffer-size-1", FT_UINT16, BASE_DEC, VALS(buffer_size_vals), 0x03f0,
              "Buffer Size available in logical channel group 1", HFILL
            }
        },
        { &hf_mac_lte_control_long_bsr_buffer_size_2,
            { "Buffer Size 2",
              "mac-lte.control.bsr.buffer-size-2", FT_UINT16, BASE_DEC, VALS(buffer_size_vals), 0x0fc0,
              "Buffer Size available in logical channel group 2", HFILL
            }
        },
        { &hf_mac_lte_control_long_bsr_buffer_size_3,
            { "Buffer Size 3",
              "mac-lte.control.bsr.buffer-size-3", FT_UINT8, BASE_DEC, VALS(buffer_size_vals), 0x3f,
              "Buffer Size available in logical channel group 3", HFILL
            }
        },
        { &hf_mac_lte_control_crnti,
            { "C-RNTI",
              "mac-lte.control.crnti", FT_UINT16, BASE_DEC, 0, 0x0,
              "C-RNTI for the UE", HFILL
            }
        },
        { &hf_mac_lte_control_timing_advance,
            { "Timing Advance",
              "mac-lte.control.timing-advance", FT_UINT8, BASE_DEC, 0, 0x3f,
              "Timing Advance (0-1282 - see 36.213, 4.2.3)", HFILL
            }
        },
        { &hf_mac_lte_control_timing_advance_reserved,
            { "Reserved",
              "mac-lte.control.timing-advance.reserved", FT_UINT8, BASE_DEC, 0, 0xc0,
              "Reserved bits", HFILL
            }
        },
        { &hf_mac_lte_control_ue_contention_resolution,
            { "UE Contention Resolution",
              "mac-lte.control.ue-contention-resolution", FT_STRING, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_ue_contention_resolution_identity,
            { "UE Contention Resolution Identity",
              "mac-lte.control.ue-contention-resolution.identity", FT_BYTES, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_ue_contention_resolution_msg3,
            { "Msg3",
              "mac-lte.control.ue-contention-resolution.msg3", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_ue_contention_resolution_msg3_matched,
            { "UE Contention Resolution Matches Msg3",
              "mac-lte.control.ue-contention-resolution.matches-msg3", FT_BOOLEAN, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_ue_contention_resolution_time_since_msg3,
            { "Time since Msg3",
              "mac-lte.control.ue-contention-resolution.time-since-msg3", FT_UINT32, BASE_DEC, 0, 0x0,
              "Time in ms since corresponding Msg3", HFILL
            }
        },

        { &hf_mac_lte_control_power_headroom,
            { "Power Headroom",
              "mac-lte.control.power-headroom", FT_STRING, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_control_power_headroom_reserved,
            { "Reserved",
              "mac-lte.control.power-headroom.reserved", FT_UINT8, BASE_DEC, 0, 0xc0,
              "Reserved bits, should be 0", HFILL
            }
        },
        { &hf_mac_lte_control_power_headroom_level,
            { "Power Headroom Level",
              "mac-lte.control.power-headroom.level", FT_UINT8, BASE_DEC,
               VALS(power_headroom_size_vals), 0x3f, "Power Headroom Level in dB", HFILL
            }
        },

        { &hf_mac_lte_control_padding,
            { "Padding",
              "mac-lte.control.padding", FT_NONE, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },

        /* Generated fields */
        { &hf_mac_lte_context_phy_dl_retx,
            { "DL Retx",
              "mac-lte.dlsch.retx", FT_BOOLEAN, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_suspected_dl_retx_original_frame,
            { "Frame with previous tx",
              "mac-lte.dlsch.retx.original-frame", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },

        { &hf_mac_lte_ul_harq_resend_original_frame,
            { "Frame with previous tx",
              "mac-lte.ulsch.retx.original-frame", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },

        { &hf_mac_lte_grant_answering_sr,
            { "First Grant Following SR from",
              "mac-lte.ulsch.grant-answering-sr", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_failure_answering_sr,
            { "SR which failed",
              "mac-lte.ulsch.failure-answering-sr", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sr_leading_to_failure,
            { "This SR fails",
              "mac-lte.ulsch.failure-answering-sr-frame", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sr_leading_to_grant,
            { "This SR results in a grant here",
              "mac-lte.ulsch.grant-answering-sr-frame", FT_FRAMENUM, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sr_invalid_event,
            { "Invalid event",
              "mac-lte.ulsch.sr-invalid-event", FT_NONE, BASE_NONE, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sr_time_since_request,
            { "Time since SR (ms)",
              "mac-lte.ulsch.time-since-sr", FT_UINT32, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },
        { &hf_mac_lte_sr_time_until_answer,
            { "Time until answer (ms)",
              "mac-lte.ulsch.time-until-sr-answer", FT_UINT32, BASE_DEC, 0, 0x0,
              NULL, HFILL
            }
        },

    };

    static gint *ett[] =
    {
        &ett_mac_lte,
        &ett_mac_lte_context,
        &ett_mac_lte_phy_context,
        &ett_mac_lte_rar_headers,
        &ett_mac_lte_rar_header,
        &ett_mac_lte_rar_body,
        &ett_mac_lte_rar_ul_grant,
        &ett_mac_lte_ulsch_header,
        &ett_mac_lte_dlsch_header,
        &ett_mac_lte_sch_subheader,
        &ett_mac_lte_bch,
        &ett_mac_lte_bsr,
        &ett_mac_lte_pch,
        &ett_mac_lte_contention_resolution,
        &ett_mac_lte_power_headroom,
        &ett_mac_lte_oob
    };

    static enum_val_t show_info_col_vals[] = {
        {"show-phy", "PHY Info", ShowPHYLayer},
        {"show-mac", "MAC Info", ShowMACLayer},
        {"show-rlc", "RLC Info", ShowRLCLayer},
        {NULL, NULL, -1}
    };

    module_t *mac_lte_module;

    static uat_field_t lcid_drb_mapping_flds[] = {
        UAT_FLD_VS(lcid_drb_mappings, lcid, "lcid", drb_lcid_vals, "The MAC LCID"),
        UAT_FLD_DEC(lcid_drb_mappings, drbid,"drb id (1-32)", "Identifier of logical data channel"),
        UAT_FLD_VS(lcid_drb_mappings, channel_type, "RLC Channel Type", rlc_channel_type_vals, "The MAC LCID"),
        UAT_END_FIELDS
    };

    /* Register protocol. */
    proto_mac_lte_dan = proto_register_protocol("MAC-LTE-DAN", "MAC-LTE-DAN", "mac-lte-dan");
    proto_register_field_array(proto_mac_lte_dan, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Allow other dissectors to find this one by name. */
    register_dissector("mac-lte-dan", dissect_mac_lte, proto_mac_lte_dan);

    /* Register the tap name */
    mac_lte_tap = register_tap("mac-lte-dan");

    /* Preferences */
    mac_lte_module = prefs_register_protocol(proto_mac_lte_dan, NULL);

    /* Obsolete preferences */
    prefs_register_obsolete_preference(mac_lte_module, "single_rar");
    prefs_register_obsolete_preference(mac_lte_module, "check_reserved_bits");
    prefs_register_obsolete_preference(mac_lte_module, "decode_rar_ul_grant");
    prefs_register_obsolete_preference(mac_lte_module, "show_rlc_info_column");
    prefs_register_obsolete_preference(mac_lte_module, "attempt_to_detect_dl_harq_resend");

    prefs_register_uint_preference(mac_lte_module, "retx_count_warn",
        "Number of Re-Transmits before expert warning triggered",
        "Number of Re-Transmits before expert warning triggered",
        10, &global_mac_lte_retx_counter_trigger);

    prefs_register_bool_preference(mac_lte_module, "attempt_rrc_decode",
        "Attempt to decode BCH, PCH and CCCH data using LTE RRC dissector",
        "Attempt to decode BCH, PCH and CCCH data using LTE RRC dissector",
        &global_mac_lte_attempt_rrc_decode);

    prefs_register_bool_preference(mac_lte_module, "attempt_to_dissect_crc_failures",
        "Dissect frames that have failed CRC check",
        "Attempt to dissect frames that have failed CRC check",
        &global_mac_lte_dissect_crc_failures);

    prefs_register_bool_preference(mac_lte_module, "heuristic_mac_lte_over_udp",
        "Try Heuristic LTE-MAC over UDP framing",
        "When enabled, use heuristic dissector to find MAC-LTE frames sent with "
        "UDP framing",
        &global_mac_lte_heur);

    prefs_register_bool_preference(mac_lte_module, "attempt_to_dissect_srb_sdus",
        "Attempt to dissect LCID 1&2 as srb1&2",
        "Will call LTE RLC dissector with standard settings as per RRC spec",
        &global_mac_lte_attempt_srb_decode);

    lcid_drb_mappings_uat = uat_new("LCID -> drb Table",
                               sizeof(lcid_drb_mapping_t),
                               "drb_logchans",
                               TRUE,
                               (void*) &lcid_drb_mappings,
                               &num_lcid_drb_mappings,
                               UAT_CAT_FFMT,
                               "",  /* TODO: is this ref to help manual? */
                               lcid_drb_mapping_copy_cb,
                               NULL,
                               NULL,
                               NULL,
                               lcid_drb_mapping_flds );

    prefs_register_uat_preference(mac_lte_module,
                                  "drb_table",
                                  "LCID -> DRB Mappings Table",
                                  "A table that maps from configurable lcids -> RLC logical channels",
                                  lcid_drb_mappings_uat);

    prefs_register_bool_preference(mac_lte_module, "attempt_to_track_ul_harq_resend",
        "Attempt to track UL HARQ resends",
        "When logging at UE side, will look for original transmission",
        &global_mac_lte_attempt_ul_harq_resend_track);

    prefs_register_uint_preference(mac_lte_module, "bsr_warn_threshold",
        "BSR size when warning should be issued (0 - 63)",
        "If any BSR report is >= this number, an expert warning will be added",
        10, &global_mac_lte_bsr_warn_threshold);

    prefs_register_bool_preference(mac_lte_module, "track_sr",
        "Track status of SRs within UEs",
        "Track status of SRs, providing links between requests, failure indications and grants",
        &global_mac_lte_track_sr);

    prefs_register_enum_preference(mac_lte_module, "layer_to_show",
        "Which layer info to show in Info column",
        "Can show PHY, MAC or RLC layer info in Info column",
        &global_mac_lte_layer_to_show, show_info_col_vals, FALSE);

    register_init_routine(&mac_lte_init_protocol);
}

void
proto_reg_handoff_mac_lte(void)
{
    static dissector_handle_t mac_lte_handle;
    if (!mac_lte_handle) {
        mac_lte_handle = find_dissector("mac-lte-dan");

        /* Add as a heuristic UDP dissector */
        heur_dissector_add("udp", dissect_mac_lte_heur, proto_mac_lte_dan);
    }
}

