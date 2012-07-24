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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/tvbuff-int.h>
#include <epan/reassemble.h>
#include <epan/value_string.h>
#include <epan/dissectors/packet-mac-lte.h>
#include "LI_types.h"
#include "LI_api.h"
#include "packetDanLteSdk.h"


// void __declspec(dllimport) attach_mac_info_to_dan(packet_info *pinfo, mac_lte_info *mac_info);
extern void attach_mac_info_to_dan(packet_info *pinfo, mac_lte_info *mac_info);

#include <string.h>

#define MAC_DISSECT
#define RLC_DISSECT

static void
dan_defragment_init(void)
{
  fragment_table_init(&dan_fragment_table);
  reassembled_table_init(&dan_reassembled_table);

}

static float api_val_to_lgcl_val (gint32 val, float start_val, float delt)
{
    float res = 0;

    res = (start_val + delt*val);

    return res;
}
void proto_reg_handoff_dan_lte_sdk(void)
{
	static gboolean initialized=FALSE;

	if (!initialized) {
		data_handle = find_dissector("dan_lte_sdk");
		dan_rlc_lte_handle = find_dissector("rlc-lte-dan");
		dan_mac_lte_handle = find_dissector("mac-lte-dan");
		dan_lte_sdk_handle = create_dissector_handle(dissect_dan_lte_sdk, proto_dan_lte_sdk);
		dissector_add("ethertype", PROTO_DAN_LTE_SDK_ETHERNET, dan_lte_sdk_handle);
	}

}

void proto_register_dan_lte_sdk (void)
{
	/* A header field is something you can search/filter on.
	*
	* We create a structure to register our fields. It consists of an
	* array of hf_register_info structures, each of which are of the format
	* {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
	*/
    static hf_register_info hf[] = {

        /* PI-E Header */
        {   &hf_dan_lte_sdk_pi_e_header_type,
        {   "Type", "dan_lte_sdk.pi_e_header.type",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_pi_e_header_seq,
        {   "Sequence", "dan_lte_sdk.pi_e_header.seq",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },


        {   &hf_dan_lte_sdk_pi_e_header_size,
        {   "Size", "dan_lte_sdk.pi_e_header.size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_pi_e_header_frag,
        {   "Fragment", "dan_lte_sdk.pi_e_header.frag",
            FT_UINT8, BASE_DEC, VALS(pie_e_header_fragment_string), 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_pi_e_header_nsf,
        {   "NSF", "dan_lte_sdk.pi_e_header.nsf",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },


        {   &hf_dan_lte_sdk_pi_e_header_nf,
        {   "NF", "dan_lte_sdk.pi_e_header.nf",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        /* DAN Message Header */
        {   &hf_dan_lte_sdk_msg_header_seq,
            {   "Sequence", "dan_lte_sdk.msg_header.seq",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_header_type,
            {   "Type", "dan_lte_sdk.msg_header.type",
                FT_UINT32, BASE_DEC, VALS(dan_msg_header_string), 0x0,
                NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_header_ack_req,
            {   "ACK", "dan_lte_sdk.msg_header.ack",
                FT_UINT32, BASE_DEC, VALS(onoff_string), 0x0,
                NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_header_size,
            {   "Size", "dan_lte_sdk.msg_header.size",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_header_nf,
            {   "NF", "dan_lte_sdk.msg_header.nf",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_header_nsf,
            {   "NSF", "dan_lte_sdk.msg_header.nsf",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_header_sector_id,
            {   "Sector ID", "dan_lte_sdk.msg_header.sector",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_header_rsrv,
            {   "Reserve", "dan_lte_sdk.msg_header.reserve",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }   },

        /* DAN DATA(AIRDL_PDSCH_REQ) Message */
        {   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_num_of_tbs,
        {   "Num of TBs", "dan_lte_sdk.msg_data_AIRDL_PDSCH_REQ.num_of_tbs",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_reserve0,
        {   "Reserve", "dan_lte_sdk.msg_data_AIRDL_PDSCH_REQ.reserve0",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_tb_idx,
        {   "TB idx", "dan_lte_sdk.msg_data_AIRDL_PDSCH_REQ.tb_idx",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_reserve1,
        {   "Reserve", "dan_lte_sdk.msg_data_AIRDL_PDSCH_REQ.reserve1",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_rnti,
        {   "RNTI", "dan_lte_sdk.msg_data_AIRDL_PDSCH_REQ.rnti",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_tb_size,
        {   "TB Size", "dan_lte_sdk.msg_data_AIRDL_PDSCH_REQ.tb_size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_n_rb,
        {   "N RB", "dan_lte_sdk.msg_data_AIRDL_PDSCH_REQ.n_rb",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_rb_bitmap,
        {   "RB Bitmap", "dan_lte_sdk.msg_data_AIRDL_PDSCH_REQ.rb_bitmap",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_ant_mode,
        {   "Ant Method", "dan_lte_sdk.msg_data_AIRDL_PDSCH_REQ.ant_method",
            FT_UINT32, BASE_DEC, VALS(dan_msg_data_ant_method_string), 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_pa,
        {   "PA", "dan_lte_sdk.msg_data_AIRDL_PDSCH_REQ.pa",
            FT_UINT32, BASE_DEC, VALS(dan_msg_data_pa_string), 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_mcs,
        {   "Mcs", "dan_lte_sdk.msg_data_AIRDL_PDSCH_REQ.mcs",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_pdsch_boost_index,
        {   "PDSCH Boost Index", "dan_lte_sdk.msg_data_AIRDL_PDSCH_REQ.pdsch_boost_index",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },


        {   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_rv_idx,
        {   "RV index", "dan_lte_sdk.msg_data_AIRDL_PDSCH_REQ.rv_index",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },


        {   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_pmi_codebook_idx,
        {   "PMI Codebook Index", "dan_lte_sdk.msg_data_AIRDL_PDSCH_REQ.pmi_codebook_idx",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_rank,
        {   "Rank", "dan_lte_sdk.msg_data_AIRDL_PDSCH_REQ.rank",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_n_codework,
        {   "N Codeword", "dan_lte_sdk.msg_data_AIRDL_PDSCH_REQ.n_codeword",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_codeword_id,
        {   "Codeword ID", "dan_lte_sdk.msg_data_AIRDL_PDSCH_REQ.codeword_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_k_mimo,
        {   "K Mimo", "dan_lte_sdk.msg_data_AIRDL_PDSCH_REQ.k_mimo",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_mimo_id,
        {   "Mimo ID", "dan_lte_sdk.msg_data_AIRDL_PDSCH_REQ.mimo_id",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_ue_category,
        {   "UE Category", "dan_lte_sdk.msg_data_AIRDL_PDSCH_REQ.ue_category",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_reserve2,
        {   "Reserve", "dan_lte_sdk.msg_data_AIRDL_PDSCH_REQ.ue_reserve2",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_p_data,
        {   "Payload", "dan_lte_sdk.msg_data_AIRDL_PDSCH_REQ.p_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }   },

		/* DAN DATA(DAN_E_AIRDL_PDSCH_DATA_ELMS_REQ) Message */
		{   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_num_of_tbs,
        {   "Num of TBs", "dan_lte_sdk.msg_data_AIRDL_PDSCH_DATA_ELMS_REQ.num_of_tbs",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_reserve0,
        {   "Reserve", "dan_lte_sdk.msg_data_AIRDL_PDSCH_DATA_ELMS_REQ.reserve0",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

		{   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_reserve1,
        {   "Reserve", "dan_lte_sdk.msg_data_AIRDL_PDSCH_DATA_ELMS_REQ.reserve1",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_tb_idx,
        {   "TB idx", "dan_lte_sdk.msg_data_AIRDL_PDSCH_DATA_ELMS_REQ.tb_idx",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

		{   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_num_of_data_chunks,
        {   "Num of Data Chunks", "dan_lte_sdk.msg_data_AIRDL_PDSCH_DATA_ELMS_REQ.num_of_data_chunks",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

		{   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_tb_size,
        {   "Chunk Size", "dan_lte_sdk.msg_data_AIRDL_PDSCH_DATA_ELMS_REQ.tb_size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

		{   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_reserve2,
        {   "Reserve", "dan_lte_sdk.msg_data_AIRDL_PDSCH_DATA_ELMS_REQ.reserve2",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

		{   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_chunk_data,
        {   "Chunk Data", "dan_lte_sdk.msg_data_AIRDL_PDSCH_DATA_ELMS_REQ.chunk_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_tb_data,
        {   "TB Data", "dan_lte_sdk.msg_data_AIRDL_PDSCH_DATA_ELMS_REQ.tb_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }   },

        /* DAN DATA(AIRDL_PDCCH_REQ) Message */
        {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_n_ue,
        {   "Number of UE", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.n_ue",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_reserve0,
        {   "Reserve", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.reserve0",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_rnti,
        {   "RNTI", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.rnti",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_cce_offset,
        {   "CCE Offset", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.cce_offset",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_reserve1,
        {   "Reserve", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.reserve1",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_pdcch_format,
        {   "PDCCH Format", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.pdcch_format",
            FT_UINT32, BASE_DEC, VALS(dan_msg_data_pdcch_format_string), 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_dci_format,
        {   "DCI Format", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.dci_format",
            FT_UINT32, BASE_DEC, VALS(dan_msg_data_dci_format_string), 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_antenna_selection,
        {   "Antenna Selection", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.antenna_selection",
            FT_UINT32, BASE_DEC, VALS(dan_msg_data_antenna_selection_string), 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_pdcch_boost,
        {   "PDCCH Boost", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.pdcch_boost",
            FT_FLOAT, BASE_NONE, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload_length,
        {   "Payload Length", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.payload_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_reserve2,
        {   "Reserve", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.reserve2",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload,
        {   "Payload", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.payload",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },
		/* payload for 20MHz Bandwidth */
		{   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload_64b,
        {   "Payload", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.payload",
            FT_UINT64, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },
/****************************************************************************/
		/* DAN DATA(AIRDL_PDCCH_REQ) PAYLOAD FORMAT 1/2/2A Message */
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_TB1,
       {   "TB Info", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_tb1",
           FT_UINT32, BASE_DEC, NULL, 0x0,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_TYPE,
       {   "Allocation Type", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_2_2a_type",
           FT_BOOLEAN, 32,VALS(dan_msg_data_param_payload_all_Type) , P1_2_2A_TYPE,
           NULL, HFILL }   },
		   

		/* DAN DATA(AIRDL_PDCCH_REQ) PAYLOAD FORMAT 1/2/2A Message (1.4MHZ) */   
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_1_4M,
       {   "RIV", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_2_2a_riv_1_4M",
           FT_UINT32, BASE_DEC, NULL, P1_2_2A_RIV_1_4M,
           NULL, HFILL }   },

		   /* Format 1 Fields */
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_MCS_1_4M,
       {   "MCS", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_mcs_1_4M",
           FT_UINT32, BASE_DEC, NULL, P1_MCS_1_4M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_HARQ_1_4M,
       {   "Counter", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_counter_1_4M",
           FT_UINT32, BASE_DEC, NULL, P1_HARQ_1_4M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_NDI_1_4M,
       {   "NDI", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_ndi_1_4M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P1_NDI_1_4M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_RV_1_4M,
       {   "RV", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_rv_1_4M",
           FT_UINT32, BASE_DEC, NULL, P1_RV_1_4M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_TPC_1_4M,
       {   "TPC", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_tpc_1_4M",
           FT_UINT32, BASE_DEC, NULL, P1_TPC_1_4M,
           NULL, HFILL }   },
		   
			/* Formats 2/2A Fields */
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_TPC_1_4M,
       {   "TPC", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_tpc_1_4M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_TPC_1_4M,
           NULL, HFILL }   },		   

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_HARQ_1_4M,
       {   "Counter", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_counter_1_4M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_HARQ_1_4M,
           NULL, HFILL }   },
		   
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_SWAP_1_4M,
       {   "Swap Flag", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_swap_1_4M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_SWAP_1_4M,
           NULL, HFILL }   },
		   
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS0_1_4M,
       {   "MCS 0", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_mcs0_1_4M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_MCS0_1_4M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI0_1_4M,
       {   "NDI 0", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_ndi0_1_4M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P2_2A_NDI0_1_4M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV0_1_4M,
       {   "RV 0", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_rv0_1_4M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_RV0_1_4M,
           NULL, HFILL }   },

	   {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_1_4M,
       {   "MCS 1", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_mcs1_1_4M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_MCS1_1_4M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI1_1_4M,
       {   "NDI 1", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_ndi1_1_4M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P2_2A_NDI1_1_4M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV1_1_4M,
       {   "RV 1", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_rv1_1_4M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_RV1_1_4M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_PRECODING_1_4M,
       {   "Precoding", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_precoding_1_4M",
           FT_UINT32, BASE_DEC, NULL, P2_PRECODING_1_4M,
           NULL, HFILL }   },		


		/* DAN DATA(AIRDL_PDCCH_REQ) PAYLOAD FORMAT 1/2/2A Message (3MHZ) */   
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_3M,
       {   "RIV", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_2_2a_riv_3M",
           FT_UINT32, BASE_DEC, NULL, P1_2_2A_RIV_3M,
           NULL, HFILL }   },

		   /* Format 1 Fields */
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_MCS_3M,
       {   "MCS", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_mcs_3M",
           FT_UINT32, BASE_DEC, NULL, P1_MCS_3M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_HARQ_3M,
       {   "Counter", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_counter_3M",
           FT_UINT32, BASE_DEC, NULL, P1_HARQ_3M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_NDI_3M,
       {   "NDI", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_ndi_3M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P1_NDI_3M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_RV_3M,
       {   "RV", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_rv_3M",
           FT_UINT32, BASE_DEC, NULL, P1_RV_3M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_TPC_3M,
       {   "TPC", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_tpc_3M",
           FT_UINT32, BASE_DEC, NULL, P1_TPC_3M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_REST_3M,
       {   "Reserved", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_resv",
           FT_UINT32, BASE_DEC, NULL, P1_REST_3M,
           NULL, HFILL }   },
		   
			/* Formats 2/2A Fields */
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_TPC_3M,
       {   "TPC", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_tpc_3M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_TPC_3M,
           NULL, HFILL }   },		   

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_HARQ_3M,
       {   "Counter", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_counter_3M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_HARQ_3M,
           NULL, HFILL }   },
		   
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_SWAP_3M,
       {   "Swap Flag", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_swap_3M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_SWAP_3M,
           NULL, HFILL }   },
		   
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS0_3M,
       {   "MCS 0", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_mcs0_3M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_MCS0_3M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI0_3M,
       {   "NDI 0", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_ndi0_3M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P2_2A_NDI0_3M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV0_3M,
       {   "RV 0", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_rv0_3M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_RV0_3M,
           NULL, HFILL }   },

	   {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_3M,
       {   "MCS 1", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_mcs1_3M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_MCS1_3M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI1_3M,
       {   "NDI 1", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_ndi1_3M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P2_2A_NDI1_3M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV1_3M,
       {   "RV 1", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_rv1_3M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_RV1_3M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_PRECODING1_3M,
       {   "Precoding (Part 1)", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_precoding1_3M",
           FT_UINT32, BASE_DEC, NULL, P2_PRECODING1_3M,
           NULL, HFILL }   },	

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_PRECODING2_3M,
       {   "Precoding (Part 2)", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_precoding2_3M",
           FT_UINT32, BASE_DEC, NULL, P2_PRECODING2_3M,
           NULL, HFILL }   },
		   
		/* DAN DATA(AIRDL_PDCCH_REQ) PAYLOAD FORMAT 1/2/2A Message (5MHZ) */   
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_5M,
       {   "RIV", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_2_2a_riv_5M",
           FT_UINT32, BASE_DEC, NULL, P1_2_2A_RIV_5M,
           NULL, HFILL }   },

		   /* Format 1 Fields */
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_MCS_5M,
       {   "MCS", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_mcs_5M",
           FT_UINT32, BASE_DEC, NULL, P1_MCS_5M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_HARQ_5M,
       {   "Counter", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_counter_5M",
           FT_UINT32, BASE_DEC, NULL, P1_HARQ_5M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_NDI_5M,
       {   "NDI", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_ndi_5M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P1_NDI_5M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_RV_5M,
       {   "RV", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_rv_5M",
           FT_UINT32, BASE_DEC, NULL, P1_RV_5M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_TPC_5M,
       {   "TPC", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_tpc_5M",
           FT_UINT32, BASE_DEC, NULL, P1_TPC_5M,
           NULL, HFILL }   },
		   
			/* Formats 2/2A Fields */
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_TPC_5M,
       {   "TPC", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_tpc_5M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_TPC_5M,
           NULL, HFILL }   },		   

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_HARQ_5M,
       {   "Counter", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_counter_5M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_HARQ_5M,
           NULL, HFILL }   },
		   
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_SWAP_5M,
       {   "Swap Flag", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_swap_5M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_SWAP_5M,
           NULL, HFILL }   },
		   
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS0_5M,
       {   "MCS 0", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_mcs0_5M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_MCS0_5M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI0_5M,
       {   "NDI 0", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_ndi0_5M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P2_2A_NDI0_5M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV0_5M,
       {   "RV 0", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_rv0_5M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_RV0_5M,
           NULL, HFILL }   },

	   {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_0_5M,
       {   "MCS 1 (Part 1)", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_mcs1_0_5M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_MCS1_0_5M,
           NULL, HFILL }   },

	   {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_1_5M,
       {   "MCS 1 (Part 2)", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_mcs1_1_5M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_MCS1_1_5M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI1_5M,
       {   "NDI 1", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_ndi1_5M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P2_2A_NDI1_5M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV1_5M,
       {   "RV 1", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_rv1_5M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_RV1_5M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_PRECODING_5M,
       {   "Precoding", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_precoding_5M",
           FT_UINT32, BASE_DEC, NULL, P2_PRECODING_5M,
           NULL, HFILL }   },		

		/* DAN DATA(AIRDL_PDCCH_REQ) PAYLOAD FORMAT 1/2/2A Message (10MHZ) */   
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_10M,
       {   "RIV", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_2_2a_riv_10M",
           FT_UINT32, BASE_DEC, NULL, P1_2_2A_RIV_10M,
           NULL, HFILL }   },

		   /* Format 1 Fields */
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_MCS_10M,
       {   "MCS", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_mcs_10M",
           FT_UINT32, BASE_DEC, NULL, P1_MCS_10M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_HARQ_10M,
       {   "Counter", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_counter_10M",
           FT_UINT32, BASE_DEC, NULL, P1_HARQ_10M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_NDI_10M,
       {   "NDI", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_ndi_10M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P1_NDI_10M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_RV_10M,
       {   "RV", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_rv_10M",
           FT_UINT32, BASE_DEC, NULL, P1_RV_10M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_TPC_10M,
       {   "TPC", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_tpc_10M",
           FT_UINT32, BASE_DEC, NULL, P1_TPC_10M,
           NULL, HFILL }   },
		   
			/* Formats 2/2A Fields */
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_TPC_10M,
       {   "TPC", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_tpc_10M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_TPC_10M,
           NULL, HFILL }   },		   

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_HARQ_10M,
       {   "Counter", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_counter_10M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_HARQ_10M,
           NULL, HFILL }   },
		   
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_SWAP_10M,
       {   "Swap Flag", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_swap_10M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_SWAP_10M,
           NULL, HFILL }   },
		   
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS0_10M,
       {   "MCS 0", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_mcs0_10M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_MCS0_10M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI0_10M,
       {   "NDI 0", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_ndi0_10M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P2_2A_NDI0_10M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV0_10M,
       {   "RV 0", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_rv0_10M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_RV0_10M,
           NULL, HFILL }   },

	   {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_10M,
       {   "MCS 1", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_mcs1_10M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_MCS1_10M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI1_10M,
       {   "NDI 1", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_ndi1_10M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P2_2A_NDI1_10M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV1_10M,
       {   "RV 1", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_rv1_10M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_RV1_10M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2A_REST_10M,
       {   "Reserved", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2a_resv_10M",
           FT_UINT32, BASE_DEC, NULL, P2A_REST_10M,
           NULL, HFILL }   },		

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_PRECODING_10M,
       {   "Precoding", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_precoding_10M",
           FT_UINT32, BASE_DEC, NULL, P2_PRECODING_10M,
           NULL, HFILL }   },		

		/* DAN DATA(AIRDL_PDCCH_REQ) PAYLOAD FORMAT 1/2/2A Message (15MHZ) */   
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_15M,
       {   "RIV", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_2_2a_riv_15M",
           FT_UINT32, BASE_DEC, NULL, P1_2_2A_RIV_15M,
           NULL, HFILL }   },

		   /* Format 1 Fields */
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_MCS_15M,
       {   "MCS", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_mcs_15M",
           FT_UINT32, BASE_DEC, NULL, P1_MCS_15M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_HARQ_15M,
       {   "Counter", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_counter_15M",
           FT_UINT32, BASE_DEC, NULL, P1_HARQ_15M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_NDI_15M,
       {   "NDI", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_ndi_15M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P1_NDI_15M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_RV_15M,
       {   "RV", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_rv_15M",
           FT_UINT32, BASE_DEC, NULL, P1_RV_15M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_TPC1_15M,
       {   "TPC (Part 1)", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_tpc1_15M",
           FT_UINT32, BASE_DEC, NULL, P1_TPC1_15M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_TPC2_15M,
       {   "TPC (Part 2)", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_tpc2_15M",
           FT_UINT32, BASE_DEC, NULL, P1_TPC2_15M,
           NULL, HFILL }   },
		   
			/* Formats 2/2A Fields */
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_TPC_15M,
       {   "TPC", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_tpc_15M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_TPC_15M,
           NULL, HFILL }   },		   

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_HARQ_15M,
       {   "Counter", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_counter_15M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_HARQ_15M,
           NULL, HFILL }   },
		   
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_SWAP_15M,
       {   "Swap Flag", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_swap_15M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_SWAP_15M,
           NULL, HFILL }   },
		   
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS0_15M,
       {   "MCS 0", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_mcs0_15M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_MCS0_15M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI0_15M,
       {   "NDI 0", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_ndi0_15M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P2_2A_NDI0_15M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV0_15M,
       {   "RV 0", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_rv0_15M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_RV0_15M,
           NULL, HFILL }   },

	   {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_15M,
       {   "MCS 1", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_mcs1_15M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_MCS1_15M,
           NULL, HFILL }   },

		   {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI1_15M,
       {   "NDI 1", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_ndi1_15M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P2_2A_NDI1_15M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV1_15M,
       {   "RV 1", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_rv1_15M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_RV1_15M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_PRECODING_15M,
       {   "Precoding", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_precoding_15M",
           FT_UINT32, BASE_DEC, NULL, P2_PRECODING_15M,
           NULL, HFILL }   },		

		/* DAN DATA(AIRDL_PDCCH_REQ) PAYLOAD FORMAT 1/2/2A Message (20MHZ) */   
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_20M,
       {   "RIV", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_2_2a_riv_20M",
           FT_UINT32, BASE_DEC, NULL, P1_2_2A_RIV_20M,
           NULL, HFILL }   },

		   /* Format 1 Fields */
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_MCS_20M,
       {   "MCS", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_mcs_20M",
           FT_UINT32, BASE_DEC, NULL, P1_MCS_20M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_HARQ1_20M,
       {   "Counter (Part 1)", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_counter1_20M",
           FT_UINT32, BASE_DEC, NULL, P1_HARQ1_20M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_HARQ2_20M,
       {   "Counter (Part 2)", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_counter2_20M",
           FT_UINT32, BASE_DEC, NULL, P1_HARQ2_20M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_NDI_20M,
       {   "NDI", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_ndi_20M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P1_NDI_20M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_RV_20M,
       {   "RV", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_rv_20M",
           FT_UINT32, BASE_DEC, NULL, P1_RV_20M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_TPC_20M,
       {   "TPC", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1_tpc_20M",
           FT_UINT32, BASE_DEC, NULL, P1_TPC_20M,
           NULL, HFILL }   },
		   
			/* Formats 2/2A Fields */
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_TPC_20M,
       {   "TPC", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_tpc_20M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_TPC_20M,
           NULL, HFILL }   },		   

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_HARQ_20M,
       {   "Counter", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_counter_20M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_HARQ_20M,
           NULL, HFILL }   },
		   
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_SWAP_20M,
       {   "Swap Flag", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_swap_20M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_SWAP_20M,
           NULL, HFILL }   },
		   
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS0_20M,
       {   "MCS 0", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_mcs0_20M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_MCS0_20M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI0_20M,
       {   "NDI 0", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_ndi0_20M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P2_2A_NDI0_20M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV0_20M,
       {   "RV 0", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_rv0_20M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_RV0_20M,
           NULL, HFILL }   },

	   {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_20M,
       {   "MCS 1", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_mcs1_20M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_MCS1_20M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI1_20M,
       {   "NDI 1", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_ndi1_20M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P2_2A_NDI1_20M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV1_20M,
       {   "RV 1", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_2a_rv1_20M",
           FT_UINT32, BASE_DEC, NULL, P2_2A_RV1_20M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_PRECODING_20M,
       {   "Precoding", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p2_precoding_20M",
           FT_UINT32, BASE_DEC, NULL, P2_PRECODING_20M,
           NULL, HFILL }   },		
			   
/******************************************************************************/

        /* DAN DATA(AIRDL_PDCCH_REQ) PAYLOAD FORMAT 0/1A Message */
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_TYPE,
       {   "DCI Format", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_1a_type",
           FT_BOOLEAN, 32,TFS(&tfs_payload_Type) , P0_1A_TYPE,
           NULL, HFILL }   },

	   {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_HOPPING,
       {   "Hopping", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_hopping",
           FT_BOOLEAN, 32, TFS(&tfs_payload_Hop), P0_HOPPING,
           NULL, HFILL }   },
	
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_ALLOCATION,
       {   "Allocation", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_allocation",
           FT_BOOLEAN, 32, TFS(&tfs_payload_Alloc), P1A_ALLOCATION,
           NULL, HFILL }   },

		/* DAN DATA(AIRDL_PDCCH_REQ) PAYLOAD FORMAT 0/1A Message (1.4MHZ) */   
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_RIV_1_4M,
       {   "RIV", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_1a_riv_1_4M",
           FT_UINT32, BASE_DEC, NULL, P0_1A_RIV_1_4M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_MCS_1_4M,
       {   "MCS", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_1a_mcs_1_4M",
           FT_UINT32, BASE_DEC, NULL, P0_1A_MCS_1_4M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_COUNTER_1_4M,
       {   "Counter", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_counter_1_4M",
           FT_UINT32, BASE_DEC, NULL, P1A_COUNTER_1_4M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_NDI_1_4M,
       {   "NDI", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_ndi_1_4M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P1A_NDI_1_4M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_RV_1_4M,
       {   "RV", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_rv_1_4M",
           FT_UINT32, BASE_DEC, NULL, P1A_RV_1_4M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_TPC_1_4M,
       {   "TPC", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_tpc_1_4M",
           FT_UINT32, BASE_DEC, NULL, P1A_TPC_1_4M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_REST_1_4M,
       {   "Rest of Data", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_rest_1_4M",
           FT_UINT32, BASE_HEX, NULL, P1A_REST_1_4M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_NDI_1_4M,
       {   "NDI", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_ndi_1_4M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P0_NDI_1_4M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_TPC_1_4M,
       {   "TPC", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_tpc_1_4M",
           FT_UINT32, BASE_DEC, NULL, P0_TPC_1_4M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CYCSHIFT_1_4M,
       {   "Cyclic Shift", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_cs_1_4M",
           FT_UINT32, BASE_DEC, NULL, P0_CYC_1_4M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CQI_1_4M,
       {   "CQI Request", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_cqi_1_4M",
           FT_UINT32, BASE_DEC, NULL, P0_CQI_1_4M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_REST_1_4M,
       {   "Rest of Data", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_rest_1_4M",
           FT_UINT32, BASE_HEX, NULL, P0_REST_1_4M,
           NULL, HFILL }   },
/******************************************************************************/

		/* DAN DATA(AIRDL_PDCCH_REQ) PAYLOAD FORMAT 0/1A Message (3MHZ) */   
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_RIV_3M,
       {   "RIV", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_1a_riv_3M",
           FT_UINT32, BASE_DEC, NULL, P0_1A_RIV_3M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_MCS_3M,
       {   "MCS", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_1a_mcs_3M",
           FT_UINT32, BASE_DEC, NULL, P0_1A_MCS_3M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_COUNTER_3M,
       {   "Counter", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_counter_3M",
           FT_UINT32, BASE_DEC, NULL, P1A_COUNTER_3M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_NDI_3M,
       {   "NDI", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_ndi_3M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P1A_NDI_3M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_RV_3M,
       {   "RV", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_rv_3M",
           FT_UINT32, BASE_DEC, NULL, P1A_RV_3M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_TPC_3M,
       {   "TPC", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_tpc_3M",
           FT_UINT32, BASE_DEC, NULL, P1A_TPC_3M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_NDI_3M,
       {   "NDI", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_ndi_3M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P0_NDI_3M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_TPC_3M,
       {   "TPC", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_tpc_3M",
           FT_UINT32, BASE_DEC, NULL, P0_TPC_3M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CYCSHIFT_3M,
       {   "Cyclic Shift", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_cs_3M",
           FT_UINT32, BASE_DEC, NULL, P0_CYC_3M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CQI_3M,
       {   "CQI Request", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_cqi_3M",
           FT_UINT32, BASE_DEC, NULL, P0_CQI_3M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_REST_3M,
       {   "Rest of Data", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_rest_3M",
           FT_UINT32, BASE_HEX, NULL, P0_REST_3M,
           NULL, HFILL }   },
/******************************************************************************/

		/* DAN DATA(AIRDL_PDCCH_REQ) PAYLOAD FORMAT 0/1A Message (5MHZ) */   
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_RIV_5M,
       {   "RIV", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_1a_riv_5M",
           FT_UINT32, BASE_DEC, NULL, P0_1A_RIV_5M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_MCS_5M,
       {   "MCS", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_1a_mcs_5M",
           FT_UINT32, BASE_DEC, NULL, P0_1A_MCS_5M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_COUNTER_5M,
       {   "Counter", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_counter_5M",
           FT_UINT32, BASE_DEC, NULL, P1A_COUNTER_5M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_NDI_5M,
       {   "NDI", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_ndi_5M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P1A_NDI_5M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_RV_5M,
       {   "RV", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_rv_5M",
           FT_UINT32, BASE_DEC, NULL, P1A_RV_5M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_TPC_5M,
       {   "TPC", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_tpc_5M",
           FT_UINT32, BASE_DEC, NULL, P1A_TPC_5M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_REST_5M,
       {   "Rest of Data", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_rest_5M",
           FT_UINT32, BASE_HEX, NULL, P1A_REST_5M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_NDI_5M,
       {   "NDI", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_ndi_5M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P0_NDI_5M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_TPC_5M,
       {   "TPC", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_tpc_5M",
           FT_UINT32, BASE_DEC, NULL, P0_TPC_5M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CYCSHIFT_5M,
       {   "Cyclic Shift", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_cs_5M",
           FT_UINT32, BASE_DEC, NULL, P0_CYC_5M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CQI_5M,
       {   "CQI Request", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_cqi_5M",
           FT_UINT32, BASE_DEC, NULL, P0_CQI_5M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_REST_5M,
       {   "Rest of Data", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_rest_5M",
           FT_UINT32, BASE_HEX, NULL, P0_REST_5M,
           NULL, HFILL }   },
/******************************************************************************/

		/* DAN DATA(AIRDL_PDCCH_REQ) PAYLOAD FORMAT 0/1A Message (10MHZ) */   
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_RIV_10M,
       {   "RIV", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_1a_riv_10M",
           FT_UINT32, BASE_DEC, NULL, P0_1A_RIV_10M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_MCS_10M,
       {   "MCS", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_1a_mcs_10M",
           FT_UINT32, BASE_DEC, NULL, P0_1A_MCS_10M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_COUNTER_10M,
       {   "Counter", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_counter_10M",
           FT_UINT32, BASE_DEC, NULL, P1A_COUNTER_10M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_NDI_10M,
       {   "NDI", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_ndi_10M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P1A_NDI_10M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_RV_10M,
       {   "RV", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_rv_10M",
           FT_UINT32, BASE_DEC, NULL, P1A_RV_10M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_TPC_10M,
       {   "TPC", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_tpc_10M",
           FT_UINT32, BASE_DEC, NULL, P1A_TPC_10M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_REST_10M,
       {   "Rest of Data", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_rest_10M",
           FT_UINT32, BASE_HEX, NULL, P1A_REST_10M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_NDI_10M,
       {   "NDI", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_ndi_10M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P0_NDI_10M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_TPC_10M,
       {   "TPC", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_tpc_10M",
           FT_UINT32, BASE_DEC, NULL, P0_TPC_10M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CYCSHIFT_10M,
       {   "Cyclic Shift", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_cs_10M",
           FT_UINT32, BASE_DEC, NULL, P0_CYC_10M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CQI_10M,
       {   "CQI Request", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_cqi_10M",
           FT_UINT32, BASE_DEC, NULL, P0_CQI_10M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_REST_10M,
       {   "Rest of Data", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_rest_10M",
           FT_UINT32, BASE_HEX, NULL, P0_REST_10M,
           NULL, HFILL }   },
/******************************************************************************/

		/* DAN DATA(AIRDL_PDCCH_REQ) PAYLOAD FORMAT 0/1A Message (15MHZ) */   
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_RIV_15M,
       {   "RIV", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_1a_riv_15M",
           FT_UINT32, BASE_DEC, NULL, P0_1A_RIV_15M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_MCS_15M,
       {   "MCS", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_1a_mcs_15M",
           FT_UINT32, BASE_DEC, NULL, P0_1A_MCS_15M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_COUNTER_15M,
       {   "Counter", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_counter_15M",
           FT_UINT32, BASE_DEC, NULL, P1A_COUNTER_15M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_NDI_15M,
       {   "NDI", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_ndi_15M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P1A_NDI_15M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_RV_15M,
       {   "RV", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_rv_15M",
           FT_UINT32, BASE_DEC, NULL, P1A_RV_15M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_TPC_15M,
       {   "TPC", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_tpc_15M",
           FT_UINT32, BASE_DEC, NULL, P1A_TPC_15M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_NDI_15M,
       {   "NDI", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_ndi_15M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P0_NDI_15M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_TPC_15M,
       {   "TPC", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_tpc_15M",
           FT_UINT32, BASE_DEC, NULL, P0_TPC_15M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CYCSHIFT_15M,
       {   "Cyclic Shift", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_cs_15M",
           FT_UINT32, BASE_DEC, NULL, P0_CYC_15M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CQI_15M,
       {   "CQI Request", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_cqi_15M",
           FT_UINT32, BASE_DEC, NULL, P0_CQI_15M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_REST_15M,
       {   "Rest of Data", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_rest_15M",
           FT_UINT32, BASE_HEX, NULL, P0_REST_15M,
           NULL, HFILL }   },
/******************************************************************************/

		/* DAN DATA(AIRDL_PDCCH_REQ) PAYLOAD FORMAT 0/1A Message (20MHZ) */   
       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_RIV_20M,
       {   "RIV", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_1a_riv_20M",
           FT_UINT32, BASE_DEC, NULL, P0_1A_RIV_20M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_MCS_20M,
       {   "MCS", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_1a_mcs_20M",
           FT_UINT32, BASE_DEC, NULL, P0_1A_MCS_20M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_COUNTER_20M,
       {   "Counter", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_counter_20M",
           FT_UINT32, BASE_DEC, NULL, P1A_COUNTER_20M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_NDI_20M,
       {   "NDI", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_ndi_20M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P1A_NDI_20M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_RV_20M,
       {   "RV", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_rv_20M",
           FT_UINT32, BASE_DEC, NULL, P1A_RV_20M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_TPC_20M,
       {   "TPC", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p1a_tpc_20M",
           FT_UINT32, BASE_DEC, NULL, P1A_TPC_20M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_NDI_20M,
       {   "NDI", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_ndi_20M",
           FT_BOOLEAN, 32, TFS(&tfs_payload_NDI), P0_NDI_20M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_TPC_20M,
       {   "TPC", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_tpc_20M",
           FT_UINT32, BASE_DEC, NULL, P0_TPC_20M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CYCSHIFT_20M,
       {   "Cyclic Shift", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_cs_20M",
           FT_UINT32, BASE_DEC, NULL, P0_CYC_20M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CQI_20M,
       {   "CQI Request", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_cqi_20M",
           FT_UINT32, BASE_DEC, NULL, P0_CQI_20M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_REST_20M,
       {   "Rest of Data", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p0_rest_20M",
           FT_UINT32, BASE_HEX, NULL, P0_REST_20M,
           NULL, HFILL }   },
/******************************************************************************/	
		/* DAN DATA(AIRDL_PDCCH_REQ) PAYLOAD FORMAT 3 Message (10MHZ) */   
	   {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P3_TPC_10M,
       {   "TPC", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p3_tpc_10M",
           FT_UINT32, BASE_DEC, NULL, P3_TPC_10M,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P3_REST_10M,
       {   "Rest of Data", "dan_lte_sdk.msg_data_AIRDL_PDCCH_REQ.p3_rest_10M",
           FT_UINT32, BASE_HEX, NULL, P3_REST_10M,
           NULL, HFILL }   },
				   

/******************************************************************************/
		   
        /* PHICH request (AIRDL_PHICH_REQ)*/
       {   &hf_dan_lte_sdk_msg_AIRDL_PHICH_REQ_n_ue,
       {   "Number of UEs", "dan_lte_sdk.msg_AIRDL_PHICH_REQ.n_ue",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PHICH_REQ_reserve1,
       {   "Reserved", "dan_lte_sdk.msg_data_AIRDL_PHICH_REQ.reserved1",
           FT_UINT24, BASE_HEX, NULL, 0x0,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PHICH_REQ_reserve2,
       {   "Reserved", "dan_lte_sdk.msg_data_AIRDL_PHICH_REQ.reserved2",
           FT_UINT16, BASE_HEX, NULL, 0x0,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PHICH_REQ_group_id,
       {   "Group ID", "dan_lte_sdk.msg_data_AIRDL_PHICH_REQ.group_id",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PHICH_REQ_ack_nack,
       {   "ACK/NACK", "dan_lte_sdk.msg_data_AIRDL_PHICH_REQ.ack_nack",
           FT_UINT8, BASE_DEC, VALS(dan_msg_data_ack_nack_gen_string), 0x0,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PHICH_REQ_seq_idx,
       {   "Payload", "dan_lte_sdk.msg_data_AIRDL_PHICH_REQ.seq_idx",
           FT_UINT8, BASE_DEC, NULL, 0x0,
           NULL, HFILL }   },

       {   &hf_dan_lte_sdk_msg_AIRDL_PHICH_REQ_reserve3,
       {   "Rreserved", "dan_lte_sdk.msg_data_AIRDL_PHICH_REQ.reserved3",
           FT_UINT8, BASE_HEX, NULL, 0x0,
           NULL, HFILL }   },

		/* DAN TTI (TTI_EVT) Message */
        {   &hf_dan_lte_sdk_msg_TTI_EVT_nf,
        {   "Number of frame", "dan_lte_sdk.msg_data_TTI_EVT.nf",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_TTI_EVT_nsf,
        {   "Number of sub-frame", "dan_lte_sdk.msg_data_TTI_EVT.nsf",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_TTI_EVT_reserve,
        {   "Reserve", "dan_lte_sdk.msg_data_TTI_EVT.reserve",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

		/* DAN EVT (SYS_START_RSP) Message */
        {   &hf_dan_lte_sdk_msg_SYS_START_RSP_err_code,
        {   "Error Code", "dan_lte_sdk.msg_data_SYS_START_RSP.err_code",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        /* DAN UL DATA(DAN_E_PUSCH_TB_DSC) Message */
        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_rnti,
        {   "RNTI", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.rnti",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_MCS,
        {   "MCS", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.MCS",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_rank,
        {   "Rank", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.rank",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_rb_start,
        {   "RB Start", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.rb_start",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_rb_num,
        {   "RB Num", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.rb_num",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_harq_rv,
        {   "HARQ RV", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.harq_rv",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_ul_harq_chan_id,
        {   "UL HARQ Channel ID", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.ul_harq_chan_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_dl_harq_chan_id,
        {   "DL HARQ Channel ID", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.dl_harq_chan_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_n2dmrs,
        {   "n2 DRS", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.n2dmrs",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_harq_re_tx,
        {   "HARQ Ret Tx", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.harq_re_tx",
            FT_UINT8, BASE_DEC,NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_cqi_nbits,
        {   "CQI Num of Bits", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.cqi_nbits",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_pucch_indication,
        {   "PUCCH Indication", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.pucch_indication",
            FT_UINT32, BASE_DEC, VALS(dan_msg_pucch_indication_string), 0x0,
            NULL, HFILL }   },


        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_ri_nbits,
        {   "RI Num of Bits", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.ri_nbits",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_acknack_nbits,
        {   "ACK/NACK Num of Bits", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.acknack_nbits",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_beta_offset_acknack,
        {   "Beta Offset ACK/NACK", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.beta_offset_acknack",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_beta_offset_cqi,
        {   "Beta Offset CQI", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.beta_offset_cqi",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_beta_offset_ri,
        {   "Beta Offset RI", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.beta_offset_ri",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_acknack_bo,
        {   "ACK/NACK Backoff", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.acknack_bo",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_cqi_bo,
        {   "CQI Backoff", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.cqi_bo",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_ri_bo,
        {   "RI Backoff", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.ri_bo",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_rb_num_init,
        {   "RB Num Init", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.rb_num_init",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_srs_init,
        {   "SRS Init", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.srs_init",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_MCS_init,
        {   "MCS Init", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.MCS_init",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_tb_size,
        {   "TB Size", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.tb_size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_uci_format,
        {   "UCI Format", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.uci_format",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

		{   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_crc_data,
        {   "CRC Data", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.crc_data",
            FT_UINT8, BASE_DEC, VALS(dan_msg_data_crc_data_string), 0x0,
            NULL, HFILL }   },

		{   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_srs_present,
        {   "SRS Present", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.srs_present",
            FT_UINT8, BASE_DEC, VALS(dan_msg_sr_presence_string), 0x0,
            NULL, HFILL }   },

		{   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_reserved1,
        {   "Reserved", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },
		

		{   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_reserved2,
        {   "Reserved", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.reserved",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },
		
		{   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_reserved,
        {   "Reserved", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.reserved",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_user_data,
        {   "User Data", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.user_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_PUSCH_TB_DSC_p_data,
        {   "Data Pointer", "dan_lte_sdk.msg_data_PUSCH_TB_DSC.p_data",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

         /* DAN UL DATA Descriptor(DAN_AIRUL_PUSCH_REQ) Message */
        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_REQ_n1dmrs,
        {   "n1 DRS", "dan_lte_sdk.msg_data_AIRUL_PUSCH_REQ.n1dmrs",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_REQ_n_ue,
        {   "Num of UE's", "dan_lte_sdk.msg_data_AIRUL_PUSCH_REQ.n_ue",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

		{   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_REQ_reserved,
        {   "Reserved", "dan_lte_sdk.msg_data_AIRUL_PUSCH_REQ.reserved",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

          /* DAN UL DATA Descriptor(DAN_AIRUL_PUCCH_REQ) Message */
        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_n_rb,
        {   "Num of RB's", "dan_lte_sdk.msg_data_AIRUL_PUCCH_REQ.n_rb",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_delta_pucch_shift,
        {   "Delta PUCCH Shift", "dan_lte_sdk.msg_data_AIRUL_PUCCH_REQ.delta_pucch_shift",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_n_rb_cqi,
        {   "n_rb_cqi", "dan_lte_sdk.msg_data_AIRUL_PUCCH_REQ.n_rb_cqi",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_n_cs_an,
        {   "No of Cyclic Shift", "dan_lte_sdk.msg_data_AIRUL_PUCCH_REQ.n_cs_an",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_n_pucch_req,
        {   "No of PUCCH REQ", "dan_lte_sdk.msg_data_AIRUL_PUCCH_REQ.n_pucch_req",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

		{   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_srs_present,
        {   "SRS Present", "dan_lte_sdk.msg_data_AIRUL_PUCCH_REQ.srs_present",
            FT_UINT8, BASE_DEC, VALS(dan_msg_sr_presence_string), 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_reserve,
        {   "Reserved", "dan_lte_sdk.msg_data_AIRUL_PUCCH_REQ.reserve",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_rnti,
        {   "RNTI", "dan_lte_sdk.msg_data_AIRUL_PUCCH_REQ.rnti",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_n_pucch_sr,
        {   "n_pucch_sr", "dan_lte_sdk.msg_data_AIRUL_PUCCH_REQ.n_pucch_sr",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_pucch_format,
        {   "PUCCH Format", "dan_lte_sdk.msg_data_AIRUL_PUCCH_REQ.pucch_format",
            FT_UINT32, BASE_DEC, VALS(dan_msg_data_pucch_format_string), 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_uci_format,
        {   "UCI Format", "dan_lte_sdk.msg_data_AIRUL_PUCCH_REQ.uci_format",
            FT_UINT32, BASE_DEC, VALS(dan_msg_data_uci_format_string), 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_thr,
        {   "Threshold", "dan_lte_sdk.msg_data_AIRUL_PUCCH_REQ.thr",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_dl_harq_chan_id,
        {   "DL HARQ Channel Id", "dan_lte_sdk.msg_data_AIRUL_PUCCH_REQ.dl_harq_chan_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_n_pucch_an_cqi,
        {   "n_pucch_an_cqi", "dan_lte_sdk.msg_data_AIRUL_PUCCH_REQ.n_pucch_an_cqi",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_cqi_n_bits,
        {   "Num of CQI bits", "dan_lte_sdk.msg_data_AIRUL_PUCCH_REQ.cqi_n_bits",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_reserve2,
        {   "Reserved", "dan_lte_sdk.msg_data_AIRUL_PUCCH_REQ.reserve2",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

          /* DAN UL DATA Descriptor(DAN_AIRUL_PUCCH_EVT) Message */
        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_n_ue,
        {   "Num of UE's", "dan_lte_sdk.msg_data_AIRUL_PUCCH_EVT.n_ue",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_error_indication,
        {   "Error Indication", "dan_lte_sdk.msg_data_AIRUL_PUCCH_EVT.error_indication",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_reserved,
        {   "Reserved", "dan_lte_sdk.msg_data_AIRUL_PUCCH_EVT.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_rnti,
        {   "RNTI", "dan_lte_sdk.msg_data_AIRUL_PUCCH_EVT.rnti",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_n_pucch_sr,
        {   "n_pucch_sr", "dan_lte_sdk.msg_data_AIRUL_PUCCH_EVT.n_pucch_sr",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_SR,
        {   "SR", "dan_lte_sdk.msg_data_AIRUL_PUCCH_EVT.SR",
            FT_UINT32, BASE_DEC, VALS(dan_msg_sr_presence_string), 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_ack_nack_presence,
        {   "ACK/NACK Presence", "dan_lte_sdk.msg_data_AIRUL_PUCCH_EVT.ack_nack_presence",
            FT_UINT8, BASE_DEC, VALS(dan_msg_data_ack_nack_presence_string), 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_ack_nack,
        {   "ACK/NACK", "dan_lte_sdk.msg_data_AIRUL_PUCCH_EVT.ack_nack",
            FT_UINT16, BASE_HEX, VALS(dan_msg_data_ack_nack_string), 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_dl_harq_chan_id,
        {   "DL HARQ Channel Id", "dan_lte_sdk.msg_data_AIRUL_PUCCH_EVT.dl_harq_chan_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_reserved2,
        {   "Reserved", "dan_lte_sdk.msg_data_AIRUL_PUCCH_EVT.reserved2",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_RSSI,
        {   "RSSI", "dan_lte_sdk.msg_data_AIRUL_PUCCH_EVT.RSSI",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_C2I,
        {   "C2I", "dan_lte_sdk.msg_data_AIRUL_PUCCH_EVT.C2I",
            FT_FLOAT, BASE_NONE, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_STO,
        {   "STO", "dan_lte_sdk.msg_data_AIRUL_PUCCH_EVT.STO",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_n_pucch_an_cqi,
        {   "n_pucch_an_cqi", "dan_lte_sdk.msg_data_AIRUL_PUCCH_EVT.n_pucch_an_cqi",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_pucch_format,
        {   "PUCCH Format", "dan_lte_sdk.msg_data_AIRUL_PUCCH_EVT.pucch_format",
            FT_UINT32, BASE_HEX, VALS(dan_msg_data_pucch_format_string), 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_cqi_presence,
        {   "CQI Presence", "dan_lte_sdk.msg_data_AIRUL_PUCCH_EVT.cqi_presence",
            FT_UINT32, BASE_DEC, VALS(dan_msg_data_cqi_presence_string), 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_uci_format,
        {   "UCI Format", "dan_lte_sdk.msg_data_AIRUL_PUCCH_EVT.uci_format",
            FT_UINT32, BASE_HEX, VALS(dan_msg_data_uci_format_string), 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_Payload,
        {   "Payload", "dan_lte_sdk.msg_data_AIRUL_PUCCH_EVT.Payload",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

         /* DAN UL DATA Descriptor(DAN_AIRUL_PUSCH_EVT) Message */
        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_n_ue,
        {   "Num of UE's", "dan_lte_sdk.msg_data_AIRUL_PUSCH_EVT.n_ue",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_reserved,
        {   "Reserved", "dan_lte_sdk.msg_data_AIRUL_PUSCH_EVT.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_rnti,
        {   "RNTI", "dan_lte_sdk.msg_data_AIRUL_PUSCH_EVT.rnti",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_n_rb,
        {   "Num of RB's", "dan_lte_sdk.msg_data_AIRUL_PUSCH_EVT.n_rb",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_rank,
        {   "Rank", "dan_lte_sdk.msg_data_AIRUL_PUSCH_EVT.rank",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_timing_offset,
        {   "Timing Offset", "dan_lte_sdk.msg_data_AIRUL_PUSCH_EVT.timing_offset",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_c2i,
        {   "C2I", "dan_lte_sdk.msg_data_AIRUL_PUSCH_EVT.c2i",
            FT_FLOAT, BASE_NONE, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_tb_size,
        {   "TB Size", "dan_lte_sdk.msg_data_AIRUL_PUSCH_EVT.tb_size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_RSSI,
        {   "RSSI", "dan_lte_sdk.msg_data_AIRUL_PUSCH_EVT.RSSI",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_data_present,
        {   "Data Present", "dan_lte_sdk.msg_data_AIRUL_PUSCH_EVT.data_present",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_crc_detect,
        {   "CRC Detect", "dan_lte_sdk.msg_data_AIRUL_PUSCH_EVT.crc_detect",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_sigma_kr,
        {   "Sigma KR", "dan_lte_sdk.msg_data_AIRUL_PUSCH_EVT.sigma_kr",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_ec2i,
        {   "EC2I", "dan_lte_sdk.msg_data_AIRUL_PUSCH_EVT.ec2i",
            FT_FLOAT, BASE_NONE, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_user_data,
        {   "User Data", "dan_lte_sdk.msg_data_AIRUL_PUSCH_EVT.user_data",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_p_data,
        {   "Payload", "dan_lte_sdk.msg_data_AIRUL_PUSCH_EVT.p_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }   },


         /* DAN UL Control Descriptor(DAN_AIRUL_PUSCH_CTRL_EVT) Message */
        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_n_ue,
        {   "Num of UE's", "dan_lte_sdk.msg_data_AIRUL_PUSCH_CTRL_EVT.n_ue",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_reserved,
        {   "Reserved", "dan_lte_sdk.msg_data_AIRUL_PUSCH_CTRL_EVT.reserved",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_rnti,
        {   "RNTI", "dan_lte_sdk.msg_data_AIRUL_PUSCH_CTRL_EVT.rnti",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_ack_nack_presence,
        {   "ACK/NACK Presence", "dan_lte_sdk.msg_data_AIRUL_PUSCH_CTRL_EVT.ack_nack_presence",
            FT_UINT8, BASE_DEC, VALS(dan_msg_data_ack_nack_presence_string), 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_ack_nack,
        {   "ACK/NACK", "dan_lte_sdk.msg_data_AIRUL_PUSCH_CTRL_EVT.ack_nack",
            FT_UINT8, BASE_DEC, VALS(dan_msg_data_ack_nack_string), 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_dl_harq_chan_id,
        {   "DL HARQ Channel ID", "dan_lte_sdk.msg_data_AIRUL_PUSCH_CTRL_EVT.dl_harq_chan_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_ri_presence,
        {   "RI Presence", "dan_lte_sdk.msg_data_AIRUL_PUSCH_CTRL_EVT.ri_presence",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_ri,
        {   "RI", "dan_lte_sdk.msg_data_AIRUL_PUSCH_CTRL_EVT.ri",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_reseved2,
        {   "Reserved", "dan_lte_sdk.msg_data_AIRUL_PUSCH_CTRL_EVT.reserved2",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_cqi_presence,
        {   "CQI Presence", "dan_lte_sdk.msg_data_AIRUL_PUSCH_CTRL_EVT.cqi_presence",
            FT_UINT32, BASE_DEC, VALS(dan_msg_data_cqi_presence_string), 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_uci_format,
        {   "UCI Format", "dan_lte_sdk.msg_data_AIRUL_PUSCH_CTRL_EVT.uci_format",
            FT_UINT32, BASE_DEC, VALS(dan_msg_data_uci_format_string), 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_uci_format_yosi,
        {   "UCI Format", "dan_lte_sdk.msg_data_AIRUL_PUSCH_CTRL_EVT.uci_format",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_Payload,
        {   "Payload[0]", "dan_lte_sdk.msg_data_AIRUL_PUSCH_CTRL_EVT.Payload",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_Payload_yosi,
        {   "Payload[1]", "dan_lte_sdk.msg_data_AIRUL_PUSCH_CTRL_EVT.Payload",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

         /* DAN UL measurement Descriptor(DAN_AIRUL_PUSCH_MEAS_EVT) Message */
        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_avg_rssi,
        {   "AVG RSSI", "dan_lte_sdk.msg_data_AIRUL_PUSCH_MEAS_EVT.avg_rssi",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_avg_ant1_rssi,
        {   "AVG RSSI ANT 1", "dan_lte_sdk.msg_data_AIRUL_PUSCH_MEAS_EVT.avg_ant1_rssi",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_avg_ant2_rssi,
        {   "AVG RSSI ANT 2", "dan_lte_sdk.msg_data_AIRUL_PUSCH_MEAS_EVT.avg_ant2_rssi",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_avg_ant3_rssi,
        {   "AVG RSSI ANT 3", "dan_lte_sdk.msg_data_AIRUL_PUSCH_MEAS_EVT.avg_ant3_rssi",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_avg_ant4_rssi,
        {   "AVG RSSI ANT 4", "dan_lte_sdk.msg_data_AIRUL_PUSCH_MEAS_EVT.avg_ant4_rssi",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_avg_c2i,
        {   "AVG C2I", "dan_lte_sdk.msg_data_AIRUL_PUSCH_MEAS_EVT.avg_c2i",
            FT_FLOAT, BASE_NONE, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_avg_ni,
        {   "AVG NI", "dan_lte_sdk.msg_data_AIRUL_PUSCH_MEAS_EVT.avg_ni",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_n_ue,
        {   "Num of UE's", "dan_lte_sdk.msg_data_AIRUL_PUSCH_MEAS_EVT.n_ue",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_n_tb,
        {   "Num of Alloc. TBs", "dan_lte_sdk.msg_data_AIRUL_PUSCH_MEAS_EVT.n_tb",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_n_tb_crc,
        {   "Num of CRC Failures", "dan_lte_sdk.msg_data_AIRUL_PUSCH_MEAS_EVT.n_tb_crc",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_reserved,
        {   "Reserved", "dan_lte_sdk.msg_data_AIRUL_PUSCH_MEAS_EVT.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_reserved2,
        {   "Reserved", "dan_lte_sdk.msg_data_AIRUL_PUSCH_MEAS_EVT.reserved",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

         /* DAN CFG Request(DAN_CFG_GET_REQ) Message */
        {   &hf_dan_lte_sdk_msg_CFG_GET_REQ_param_id,
        {   "Param ID", "dan_lte_sdk.msg_data_CFG_GET_REQ.param_id",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_CFG_GET_REQ_param_type,
        {   "Param Type", "dan_lte_sdk.msg_data_CFG_GET_REQ.param_type",
            FT_UINT32, BASE_DEC, VALS(dan_msg_data_param_type_string), 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_CFG_GET_REQ_index,
        {   "Index", "dan_lte_sdk.msg_data_CFG_GET_REQ.index",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_CFG_GET_REQ_reserved,
        {   "Reserved", "dan_lte_sdk.msg_data_CFG_GET_REQ.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

        /* DAN CFG Param Descriptor(DAN_CFG_PARAM_DSC) Message */
         {   &hf_dan_lte_sdk_msg_CFG_PARAM_DSC_param_type,
         {   "Param Type", "dan_lte_sdk.msg_data_CFG_PARAM_DSC.param_type",
            FT_UINT32, BASE_DEC, VALS(dan_msg_data_param_type_string), 0x0,
            NULL, HFILL }   },

        /* DAN CFG Param Data DSC (DAN_CFG_PARAM_DATA_DSC) Message */
        {   &hf_dan_lte_sdk_msg_CFG_PARAM_DATA_DSC_param_id,
        {   "Param ID", "dan_lte_sdk.msg_data_CFG_PARAM_DATA_DSC.param_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_CFG_PARAM_DATA_DSC_index,
        {   "Index", "dan_lte_sdk.msg_data_CFG_PARAM_DATA_DSC.index",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_CFG_PARAM_DATA_DSC_reserved,
        {   "Reserved", "dan_lte_sdk.msg_data_CFG_PARAM_DATA_DSC.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_DAN_BUF_size,
        {   "Size", "dan_lte_sdk.msg_data_CFG_PARAM_DATA_DSC.size",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_DAN_BUF_data,
        {   "Data", "dan_lte_sdk.msg_data_CFG_PARAM_DATA_DSC.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }   },

          /* DAN CFG Num Param DSC (DAN_CFG_PARAM_NUM_DSC) Message */
        {   &hf_dan_lte_sdk_msg_CFG_PARAM_NUM_DSC_param_id,
        {   "Param ID", "dan_lte_sdk.msg_data_CFG_PARAM_NUM_DSC.param_id",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_CFG_PARAM_NUM_DSC_value,
        {   "Value", "dan_lte_sdk.msg_data_CFG_PARAM_NUM_DSC.value",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_CFG_PARAM_NUM_DSC_index,
        {   "Index", "dan_lte_sdk.msg_data_CFG_PARAM_NUM_DSC.index",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_CFG_PARAM_NUM_DSC_reserved,
        {   "Reserved", "dan_lte_sdk.msg_data_CFG_PARAM_NUM_DSC.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

          /* DAN CFG Num Array Param DSC (DAN_CFG_PARAM_NUM_ARR_DSC) Message */
        {   &hf_dan_lte_sdk_msg_CFG_PARAM_NUM_ARR_DSC_param_id,
        {   "Param ID", "dan_lte_sdk.msg_data_CFG_PARAM_NUM_ARR_DSC.param_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_CFG_PARAM_NUM_ARR_DSC_start_index,
        {   "Start Index", "dan_lte_sdk.msg_data_CFG_PARAM_NUM_ARR_DSC.start_index",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_CFG_PARAM_NUM_ARR_DSC_num_of_params,
        {   "Num of Param", "dan_lte_sdk.msg_data_CFG_PARAM_NUM_ARR_DSC.num_of_params",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_CFG_PARAM_NUM_ARR_DSC_values,
        {   "Values", "dan_lte_sdk.msg_data_CFG_PARAM_NUM_ARR_DSC.values",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

          /* DAN Error Comm Code (DAN_COMMON_ERR_CODE) Message */
        {   &hf_dan_lte_sdk_msg_COMMON_ERR_CODE_type,
        {   "Type", "dan_lte_sdk.msg_data_COMMON_ERR_CODE.type",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_COMMON_ERR_CODE_msg_type,
        {   "MSG Type", "dan_lte_sdk.msg_data_COMMON_ERR_CODE.msg_type",
            FT_UINT32, BASE_DEC, VALS(dan_msg_header_string), 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_COMMON_ERR_CODE_msg_seq,
        {   "MSG Seq", "dan_lte_sdk.msg_data_COMMON_ERR_CODE.msg_seq",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_COMMON_ERR_CODE_user_data,
        {   "User Data", "dan_lte_sdk.msg_data_COMMON_ERR_CODE.user_data",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

          /* DAN PRACH request (DAN_AIRUL_PRACH_REQ) Message */
        {   &hf_dan_lte_sdk_msg_AIRUL_PRACH_REQ_logical_root_sn,
        {   "Logical Root SN", "dan_lte_sdk.msg_data_AIRUL_PRACH_REQ.logical_root_sn",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PRACH_REQ_prach_conf_index,
        {   "PRACH Conf Index", "dan_lte_sdk.msg_data_AIRUL_PRACH_REQ.prach_conf_index",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PRACH_REQ_Ncs,
        {   "Ncs", "dan_lte_sdk.msg_data_AIRUL_PRACH_REQ.Ncs",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PRACH_REQ_prach_req_offset,
        {   "PRACH Freq Offset", "dan_lte_sdk.msg_data_AIRUL_PRACH_REQ.prach_req_offset",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PRACH_REQ_highSpeedFlag,
        {   "High Speed Flag", "dan_lte_sdk.msg_data_AIRUL_PRACH_REQ.highSpeedFlag",
            FT_UINT8, BASE_DEC, VALS(dan_msg_data_highspeedflag), 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PRACH_REQ_prach_format,
        {   "PRACH Format", "dan_lte_sdk.msg_data_AIRUL_PRACH_REQ.prach_format",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PRACH_REQ_thr,
        {   "Threshold", "dan_lte_sdk.msg_data_AIRUL_PRACH_REQ.thr",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

          /* DAN PRACH request (DAN_AIRUL_PRACH_RSP) Message */
        {   &hf_dan_lte_sdk_msg_AIRUL_PRACH_RSP_num_preambles,
        {   "Number of Preambles", "dan_lte_sdk.msg_data_AIRUL_PRACH_RSP.num_preambles",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PRACH_RSP_error_indication,
        {   "Error Indication", "dan_lte_sdk.msg_data_AIRUL_PRACH_RSP.error_indication",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PRACH_RSP_reserve,
        {   "Reserved", "dan_lte_sdk.msg_data_AIRUL_PRACH_RSP.reserve",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PRACH_RSP_preambles,
        {   "Preambles", "dan_lte_sdk.msg_data_AIRUL_PRACH_RSP.preambles",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PRACH_RSP_preamble_id,
        {   "Preamble ID", "dan_lte_sdk.msg_data_AIRUL_PRACH_RSP.preamble_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PRACH_RSP_detection_metric,
        {   "Detection Metric", "dan_lte_sdk.msg_data_AIRUL_PRACH_RSP.detection_metric",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PRACH_RSP_timing_offset,
        {   "Timing Offset", "dan_lte_sdk.msg_data_AIRUL_PRACH_RSP.timing_offset",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PRACH_RSP_RTWP,
        {   "RTWP", "dan_lte_sdk.msg_data_AIRUL_PRACH_RSP.RTWP",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_PRACH_RSP_reserve2,
        {   "Reserved", "dan_lte_sdk.msg_data_AIRUL_PRACH_RSP.reserve2",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }   },

			/* DAN SRS request (DAN_AIRUL_SRS_REQ) Message */
        {   &hf_dan_lte_sdk_msg_AIRUL_SRS_REQ_n_srs,
        {   "Number of SRS", "dan_lte_sdk.msg_data_AIRUL_SRS_REQ.n_srs",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_SRS_REQ_reserved,
        {   "Reserved", "dan_lte_sdk.msg_data_AIRUL_SRS_REQ.reserved",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

			/* DAN SRS request (DAN_SRS_DSC) Message */
        {   &hf_dan_lte_sdk_msg_SRS_DSC_rnti,
        {   "RNTI", "dan_lte_sdk.msg_data_SRS_DSC.rnti",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_SRS_DSC_cs_srs,
        {   "Cyclic SHift", "dan_lte_sdk.msg_data_SRS_DSC.cs_srs",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_SRS_DSC_nap,
        {   "Num. of Antenna Ports", "dan_lte_sdk.msg_data_SRS_DSC.nap",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_SRS_DSC_boosting,
        {   "Boosting", "dan_lte_sdk.msg_data_SRS_DSC.boosting",
            FT_FLOAT, BASE_NONE, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_SRS_DSC_rb_start,
        {   "RB Start", "dan_lte_sdk.msg_data_SRS_DSC.rb_start",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_SRS_DSC_b_srs,
        {   "SRS Bandwidth", "dan_lte_sdk.msg_data_SRS_DSC.b_srs",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_SRS_DSC_trans_comb,
        {   "Transmission Comb", "dan_lte_sdk.msg_data_SRS_DSC.trans_comb",
            FT_UINT8, BASE_DEC, VALS(dan_msg_data_trans_comb_string), 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_SRS_DSC_reserved,
        {   "Reserved", "dan_lte_sdk.msg_data_SRS_DSC.reserved",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

			/* DAN SRS Event (DAN_AIRUL_SRS_EVT) Message */
        {   &hf_dan_lte_sdk_msg_AIRUL_SRS_EVT_n_srs,
        {   "Number of SRS", "dan_lte_sdk.msg_data_AIRUL_SRS_EVT.n_srs",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_AIRUL_SRS_EVT_reserved,
        {   "Reserved", "dan_lte_sdk.msg_data_AIRUL_SRS_EVT.reserved",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        	/* DAN SRS Event (DAN_SRS_DECODED_DSC) Message */
        {   &hf_dan_lte_sdk_msg_SRS_DECODED_DSC_rnti,
        {   "RNTI", "dan_lte_sdk.msg_data_SRS_DECODED_DSC.rnti",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_SRS_DECODED_DSC_rbg_indx,
        {   "RBG Index", "dan_lte_sdk.msg_data_SRS_DECODED_DSC.rbg_indx",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_SRS_DECODED_DSC_reserved,
        {   "Reserved", "dan_lte_sdk.msg_data_SRS_DECODED_DSC.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_SRS_DECODED_DSC_ch_state_mag[0],
        {   "Magnitude Ant. 0", "dan_lte_sdk.msg_data_SRS_DECODED_DSC.ch_state_mag",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_SRS_DECODED_DSC_ch_state_phase[0],
        {   "Phase Ant. 0", "dan_lte_sdk.msg_data_AIRUL_SRS_EVT.ch_state_phase",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

		{   &hf_dan_lte_sdk_msg_SRS_DECODED_DSC_ch_state_mag[1],
        {   "Magnitude Ant. 1", "dan_lte_sdk.msg_data_SRS_DECODED_DSC.ch_state_mag",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_SRS_DECODED_DSC_ch_state_phase[1],
        {   "Phase Ant. 1", "dan_lte_sdk.msg_data_AIRUL_SRS_EVT.ch_state_phase",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

		{   &hf_dan_lte_sdk_msg_SRS_DECODED_DSC_ch_state_mag[2],
        {   "Magnitude Ant. 2", "dan_lte_sdk.msg_data_SRS_DECODED_DSC.ch_state_mag",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_SRS_DECODED_DSC_ch_state_phase[2],
        {   "Phase Ant. 2", "dan_lte_sdk.msg_data_AIRUL_SRS_EVT.ch_state_phase",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

		{   &hf_dan_lte_sdk_msg_SRS_DECODED_DSC_ch_state_mag[3],
        {   "Magnitude Ant. 3", "dan_lte_sdk.msg_data_SRS_DECODED_DSC.ch_state_mag",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

        {   &hf_dan_lte_sdk_msg_SRS_DECODED_DSC_ch_state_phase[3],
        {   "Phase Ant. 3", "dan_lte_sdk.msg_data_AIRUL_SRS_EVT.ch_state_phase",
            FT_INT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }   },

         /* MAC Header (MAC) 4 Bytes */
       {   &hf_dan_lte_msg_MAC_MAC_HEADER_4byte,
       {   "MAC Header", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.header",
           FT_UINT32, BASE_HEX ,NULL , 0x0,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_R1_4byte,
       {   "R", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.R1",
           FT_UINT32, BASE_DEC ,NULL , MAC_4Byte_R1,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_R2_4byte,
       {   "R", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.R2",
           FT_UINT32, BASE_DEC ,NULL , MAC_4Byte_R2,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_E_4byte,
       {   "E", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.E",
           FT_BOOLEAN, 32 ,TFS(&tfs_MAC_E), MAC_4Byte_E,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_LCID_4byte,
       {   "LCID", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.lcid",
           FT_UINT32, BASE_DEC ,NULL , MAC_4Byte_LCID,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_7bitMAC_Length_4byte,
       {   "Length (7Bit)", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.length7",
           FT_UINT32, BASE_DEC , NULL, MAC_4Byte_LENGTH_7,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_F_4byte,
       {   "F", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.F",
           FT_BOOLEAN, 32, TFS(&tfs_MAC_F) , MAC_4Byte_F,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_15bitMAC_Length_4byte,
       {   "Length (15Bit)", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.length15",
           FT_UINT32, BASE_DEC ,NULL , MAC_4Byte_LENGTH_15,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_R1_7_4byte,
       {   "R", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.R1_7",
           FT_UINT32, BASE_DEC ,NULL , MAC_4Byte_R1_7,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_R2_7_4byte,
       {   "R", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.R2_7",
           FT_UINT32, BASE_DEC ,NULL , MAC_4Byte_R2_7,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_E_7_4byte,
       {   "E", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.E_7",
           FT_BOOLEAN, 32, TFS(&tfs_MAC_E) , MAC_4Byte_E_7,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_LCID_7_4byte,
       {   "LCID", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.lcid_7",
           FT_UINT32, BASE_DEC ,NULL , MAC_4Byte_LCID_7,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_R1_15_4byte,
       {   "R", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.R1_15",
           FT_UINT32, BASE_DEC ,NULL , MAC_4Byte_R1_15,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_R2_15_4byte,
       {   "R", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.R2_15",
           FT_UINT32, BASE_DEC ,NULL , MAC_4Byte_R2_15,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_E_15_4byte,
       {   "E", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.E_15",
           FT_BOOLEAN, 32, TFS(&tfs_MAC_E) , MAC_4Byte_E_15,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_LCID_15_4byte,
       {   "LCID", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.lcid_15",
           FT_UINT32, BASE_DEC ,NULL , MAC_4Byte_LCID_15,
           NULL, HFILL }   },

           /* MAC Header (MAC) 3 Bytes */
       {   &hf_dan_lte_msg_MAC_MAC_HEADER_3byte,
       {   "MAC Header", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.header",
           FT_UINT24, BASE_HEX ,NULL , 0x0,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_R1_3byte,
       {   "R", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.R1",
           FT_UINT24, BASE_DEC ,NULL , MAC_3Byte_R1,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_R2_3byte,
       {   "R", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.R2",
           FT_UINT24, BASE_DEC ,NULL , MAC_3Byte_R2,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_E_3byte,
       {   "E", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.E",
           FT_BOOLEAN, 24, TFS(&tfs_MAC_E) , MAC_3Byte_E,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_LCID_3byte,
       {   "LCID", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.lcid",
           FT_UINT24, BASE_DEC ,NULL , MAC_3Byte_LCID,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_7bitMAC_Length_3byte,
       {   "Length (7Bit)", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.length7",
           FT_UINT24, BASE_DEC , NULL, MAC_3Byte_LENGTH_7,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_F_3byte,
       {   "F", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.F",
           FT_BOOLEAN, 24, TFS(&tfs_MAC_F) , MAC_3Byte_F,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_15bitMAC_Length_3byte,
       {   "Length (15Bit)", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.length15",
           FT_UINT24, BASE_DEC ,NULL , MAC_3Byte_LENGTH_15,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_R1_7_3byte,
       {   "R", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.R1_7",
           FT_UINT24, BASE_DEC ,NULL , MAC_3Byte_R1_7,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_R2_7_3byte,
       {   "R", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.R2_7",
           FT_UINT24, BASE_DEC ,NULL , MAC_3Byte_R2_7,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_E_7_3byte,
       {   "E", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.E_7",
           FT_BOOLEAN, 24, TFS(&tfs_MAC_E) , MAC_3Byte_E_7,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_LCID_7_3byte,
       {   "LCID", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.lcid_7",
           FT_UINT24, BASE_DEC ,NULL , MAC_3Byte_LCID_7,
           NULL, HFILL }   },

            /* MAC Header (MAC) 2 Bytes */
       {   &hf_dan_lte_msg_MAC_MAC_HEADER_2byte,
       {   "MAC Header", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.header",
           FT_UINT16, BASE_HEX ,NULL , 0x0,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_R1_2byte,
       {   "R", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.R1",
           FT_UINT16, BASE_DEC ,NULL , MAC_2Byte_R1,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_R2_2byte,
       {   "R", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.R2",
           FT_UINT16, BASE_DEC ,NULL , MAC_2Byte_R2,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_E_2byte,
       {   "E", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.E",
           FT_BOOLEAN, 16, TFS(&tfs_MAC_E) , MAC_2Byte_E,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_LCID_2byte,
       {   "LCID", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.lcid",
           FT_UINT16, BASE_DEC ,NULL , MAC_2Byte_LCID,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_F_2byte,
       {   "F", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.F",
           FT_BOOLEAN, 16, TFS(&tfs_MAC_F) , MAC_2Byte_F,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_7bitMAC_Length_2byte,
       {   "Length (7Bit)", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.length7",
           FT_UINT16, BASE_DEC , NULL, MAC_2Byte_LENGTH_7,
           NULL, HFILL }   },

           /* MAC Header (MAC) 1 Bytes (Padding) */
       {   &hf_dan_lte_msg_MAC_MAC_HEADER_1byte,
       {   "MAC Header", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.header",
           FT_UINT8, BASE_HEX ,NULL , 0x0,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_R1_1byte,
       {   "R", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.R1",
           FT_UINT8, BASE_DEC ,NULL , MAC_1Byte_R1,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_R2_1byte,
       {   "R", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.R2",
           FT_UINT8, BASE_DEC ,NULL , MAC_1Byte_R2,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_E_1byte,
       {   "E", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.E",
           FT_BOOLEAN, 8, TFS(&tfs_MAC_E) , MAC_1Byte_E,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_MAC_LCID_1byte,
       {   "LCID", "dan_lte_sdk.hf_dan_lte_msg_MAC_MAC.lcid",
           FT_UINT8, BASE_DEC ,NULL , MAC_1Byte_LCID,
           NULL, HFILL }   },

           /* RLC Header (MAC) 4 Byte  */
       {   &hf_dan_lte_msg_MAC_10bitRLC_HEADER_4byte,
       {   "RLC Header", "dan_lte_sdk.hf_dan_lte_msg_MAC_RLC.4header",
           FT_UINT32, BASE_HEX ,NULL , 0x0,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_10bitRLC_R1_4byte,
       {   "R", "dan_lte_sdk.hf_dan_lte_msg_MAC_RLC.R1",
           FT_UINT32, BASE_DEC ,NULL , RLC_4Byte_R1,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_10bitRLC_R2_4byte,
       {   "R", "dan_lte_sdk.hf_dan_lte_msg_MAC_RLC.R2",
           FT_UINT32, BASE_DEC ,NULL , RLC_4Byte_R2,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_10bitRLC_R3_4byte,
       {   "R", "dan_lte_sdk.hf_dan_lte_msg_MAC_RLC.R3",
           FT_UINT32, BASE_DEC ,NULL , RLC_4Byte_R3,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_10bitRLC_FI_4byte,
       {   "FI", "dan_lte_sdk.hf_dan_lte_msg_MAC_RLC.FI",
           FT_UINT32, BASE_DEC ,NULL , RLC_4Byte_FI,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_10bitRLC_E1_4byte,
       {   "E", "dan_lte_sdk.hf_dan_lte_msg_MAC_RLC.E1",
           FT_UINT32, BASE_DEC , NULL, RLC_4Byte_E1,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_10bitRLC_SN_4byte,
       {   "SN", "dan_lte_sdk.hf_dan_lte_msg_MAC_RLC.SN",
           FT_UINT32, BASE_DEC ,NULL , RLC_4Byte_SN10,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_10bitRLC_E2_4byte,
       {   "E", "dan_lte_sdk.hf_dan_lte_msg_MAC_RLC.E2",
           FT_UINT32, BASE_DEC , NULL, RLC_4Byte_E2,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_10bitRLC_LI1_4byte,
       {   "LI", "dan_lte_sdk.hf_dan_lte_msg_MAC_RLC.LI1",
           FT_UINT32, BASE_DEC ,NULL , RLC_4Byte_LI1,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_10bitRLC_PADD_4byte,
       {   "Padding", "dan_lte_sdk.hf_dan_lte_msg_MAC_RLC.padding",
           FT_UINT32, BASE_DEC ,NULL , RLC_4Byte_PADD,
           NULL, HFILL }   },


            /* RLC Sub Header 12 Bit */
       {   &hf_dan_lte_msg_MAC_10bitRLC_Sub_Header,
       {   "E", "dan_lte_sdk.hf_dan_lte_msg_MAC_RLC.sub_header",
           FT_UINT16, BASE_DEC , NULL, 0x0,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_10bitRLC_E_12bit,
       {   "E", "dan_lte_sdk.hf_dan_lte_msg_MAC_RLC.E2",
           FT_UINT16, BASE_DEC , NULL, RLC_12bit_E,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_10bitRLC_LI_12bit,
       {   "LI", "dan_lte_sdk.hf_dan_lte_msg_MAC_RLC.LI1",
           FT_UINT16, BASE_DEC ,NULL , RLC_12bit_LI,
           NULL, HFILL }   },

            /* RLC Sub Header 16 Bit */
       {   &hf_dan_lte_msg_MAC_10bitRLC_E_16bit,
       {   "E", "dan_lte_sdk.hf_dan_lte_msg_MAC_RLC.E2",
           FT_UINT16, BASE_DEC , NULL, RLC_16bit_E,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_10bitRLC_LI_16bit,
       {   "LI", "dan_lte_sdk.hf_dan_lte_msg_MAC_RLC.LI1",
           FT_UINT16, BASE_DEC ,NULL , RLC_16bit_LI,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_10bitRLC_PADD_16bit,
       {   "Padding", "dan_lte_sdk.hf_dan_lte_msg_MAC_RLC.padding",
           FT_UINT16, BASE_DEC ,NULL , RLC_16bit_PADD,
           NULL, HFILL }   },

            /* RLC Header (MAC) 2 Byte */
       {   &hf_dan_lte_msg_MAC_10bitRLC_HEADER_2byte,
       {   "RLC Header", "dan_lte_sdk.hf_dan_lte_msg_MAC_RLC.header",
           FT_UINT16, BASE_HEX ,NULL , 0x0,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_10bitRLC_R1_2byte,
       {   "R", "dan_lte_sdk.hf_dan_lte_msg_MAC_RLC.R1",
           FT_UINT16, BASE_DEC ,NULL , RLC_2Byte_R1,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_10bitRLC_R2_2byte,
       {   "R", "dan_lte_sdk.hf_dan_lte_msg_MAC_RLC.R2",
           FT_UINT16, BASE_DEC ,NULL , RLC_2Byte_R2,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_10bitRLC_R3_2byte,
       {   "R", "dan_lte_sdk.hf_dan_lte_msg_MAC_RLC.R3",
           FT_UINT16, BASE_DEC ,NULL , RLC_2Byte_R3,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_10bitRLC_FI_2byte,
       {   "FI", "dan_lte_sdk.hf_dan_lte_msg_MAC_RLC.FI",
           FT_UINT16, BASE_DEC ,NULL , RLC_2Byte_FI,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_10bitRLC_E1_2byte,
       {   "E", "dan_lte_sdk.hf_dan_lte_msg_MAC_RLC.E1",
           FT_UINT16, BASE_DEC , NULL, RLC_2Byte_E1,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_10bitRLC_SN_2byte,
       {   "SN", "dan_lte_sdk.hf_dan_lte_msg_MAC_RLC.SN",
           FT_UINT16, BASE_DEC ,NULL , RLC_2Byte_SN10,
           NULL, HFILL }   },

       {   &hf_dan_lte_msg_MAC_10bitRLC_data,
       {   "Rest of Data", "dan_lte_sdk.hf_dan_lte_msg_MAC_RLC.data",
           FT_BYTES, BASE_NONE,NULL , 0x0,
           NULL, HFILL }   },

        /* Fragmentation data */

        {&hf_msg_fragments,
            {"Message fragments", "msg.fragments",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_msg_fragment,
            {"Message fragment", "msg.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_msg_fragment_overlap,
            {"Message fragment overlap", "msg.fragment.overlap",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_msg_fragment_overlap_conflicts,
            {"Message fragment overlapping with conflicting data",
            "msg.fragment.overlap.conflicts",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_msg_fragment_multiple_tails,
            {"Message has multiple tail fragments",
            "msg.fragment.multiple_tails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_msg_fragment_too_long_fragment,
            {"Message fragment too long", "msg.fragment.too_long_fragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_msg_fragment_error,
            {"Message defragmentation error", "msg.fragment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_msg_fragment_count,
			{"Message fragment count", "msg.fragment.count", 
			FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
		{&hf_msg_reassembled_in,
            {"Reassembled in", "msg.reassembled.in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_msg_reassembled_length,
            {"Reassembled length", "msg.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } }
    };


    static gint *ett[] = {
        &ett_dan_lte_sdk_pi_e_header,
		&ett_dan_lte_sdk_msg_header,
		&ett_dan_lte_sdk_msg_data,
		&ett_dan_lte_sdk_msg_data_subtree1,
		&ett_dan_lte_sdk_msg_data_subtree2,
		&ett_dan_lte_sdk_msg_data_subtree3,
        &ett_dan_lte_sdk_msg_data_subtree4,
        &ett_msg_fragment,
        &ett_msg_fragments
	};

	module_t *dan_lte_sdk_module;

    proto_dan_lte_sdk = proto_register_protocol ("DAN LTE SDK Protocol", "* Dan LTE SDK *", "dan_lte_sdk");

    register_init_routine(dan_defragment_init);

	proto_register_field_array (proto_dan_lte_sdk, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
	register_dissector("dan_lte_sdk", dissect_dan_lte_sdk, proto_dan_lte_sdk);


	dan_lte_sdk_module = prefs_register_protocol(proto_dan_lte_sdk, NULL);


	prefs_register_bool_preference(dan_lte_sdk_module, "dissect_mac_dl",
	                               "Dissect DL MAC Layers from Data Payload",
	                               "In Downlink data packets, dissect MAC header layer "
	                               "Disabling MAC dissection will disable RLC dissection automaticly",
	                               &global_dan_lte_sdk_dissect_MAC_DL);

    prefs_register_bool_preference(dan_lte_sdk_module, "dissect_mac_ul",
	                               "Dissect UL MAC Layers from Data Payload",
	                               "In Uplink data packets, dissect MAC header layer "
	                               "Disabling MAC dissection will disable RLC dissection automaticly",
	                               &global_dan_lte_sdk_dissect_MAC_UL);

    prefs_register_bool_preference(dan_lte_sdk_module, "big_endian",
                                   "Use Big Endian",
                                   "Choose between dissecting in Big Endian or Little Endian ",
                                   &global_dan_lte_sdk_BIG_ENDIAN);

    prefs_register_bool_preference(dan_lte_sdk_module, "no_elm_arr_ul_data",
                                   "Dissect element array in UL data",
                                   "Choose between dissecting element array in ul data or not "
                                   "This option is used when dissecting NSN mirroring ",
                                   &global_dan_lte_sdk_IPC_NO_ELM_ARR_UL);

    prefs_register_bool_preference(dan_lte_sdk_module, "data_dl_req",
                                   "IPC - Dissect DL data in request",
                                   "When using IPC the DL data wil appear in the PUSCH REQ "
                                   "This option is used when dissecting NSN mirroring ",
                                   &global_dan_lte_sdk_IPC_NO_ELM_ARR_DL);

    prefs_register_bool_preference(dan_lte_sdk_module, "ul_parse_p_data",
                                   "Dissect data pointer in UL PUSCH_REQ",
                                   "Choose between dissecting data pointer in ul request or not "
                                   "This option is used when dissecting NSN mirroring ",
                                   &global_dan_lte_sdk_UL_parse_p_data);

    prefs_register_bool_preference(dan_lte_sdk_module, "pucch_parse_cqi_nbits",
                                   "Dissect CQI number of bits in PUCCH descriptor",
                                   "Choose between dissecting cqi_n_bits in PUCCH or not "
                                   "This option is used when dissecting Latests API versions ",
                                   &global_dan_lte_sdk_PUCCH_parse_cqi_nbits);

	prefs_register_bool_preference(dan_lte_sdk_module, "parse_sounding",
                                   "Dissect Sounding (SRS)",
                                   "Choose whether or not to dissect sounding in PUCCH_REQ and PUSCH_REQ "
                                   "This option is used when dissecting Latests API versions ", // version 1.15
								   &global_dan_lte_sdk_parse_sounding);

	prefs_register_bool_preference(dan_lte_sdk_module, "parse_crc_data",
                                   "Dissect CRC Failures",
                                   "Choose whether or not to display CRC failure flags and counters "
                                   "This option is used when dissecting Latests API versions ", // version 1.14
								   &global_dan_lte_sdk_parse_crc_data);

	prefs_register_bool_preference(dan_lte_sdk_module, "new_ctrl_evt_dissection",
                                   "Dissect CTRL_EVT according to new API",
                                   "Choose whether to dissect the CTRL_EVT according to the new "
								   "or old API. ", // version 1.14
								   &global_dan_lte_sdk_ctrl_evt_yosi);

	prefs_register_enum_preference(dan_lte_sdk_module, "pdcch_bw",
                                   "PDCCH Channel Bandwidth",
                                   "What bandwidth are you working with?",
                                   &global_dan_lte_sdk_PDCCH_bw_val,
								   global_dan_lte_sdk_PDCCH_bw_enum,FALSE);

}


static void
dan_tvb_init(tvbuff_t *tvb, const tvbuff_type type)
{
	tvb_backing_t	*backing;
	tvb_comp_t	*composite;

	tvb->type		= type;
	tvb->initialized	= FALSE;
	tvb->usage_count	= 1;
	tvb->length		= 0;
	tvb->reported_length	= 0;
	tvb->free_cb		= NULL;
	tvb->real_data		= NULL;
	tvb->raw_offset		= -1;
	tvb->used_in		= NULL;
	tvb->ds_tvb		= NULL;

	switch(type) {
		case TVBUFF_REAL_DATA:
			/* Nothing */
			break;

		case TVBUFF_SUBSET:
			backing = &tvb->tvbuffs.subset;
			backing->tvb	= NULL;
			backing->offset	= 0;
			backing->length	= 0;
			break;

		case TVBUFF_COMPOSITE:
			composite = &tvb->tvbuffs.composite;
			composite->tvbs			= NULL;
			composite->start_offsets	= NULL;
			composite->end_offsets		= NULL;
			break;

		default:
			DISSECTOR_ASSERT_NOT_REACHED();
			break;
	}
}


tvbuff_t*
dan_tvb_new(const tvbuff_type type)
{
	tvbuff_t	*tvb;

#if GLIB_CHECK_VERSION(2,10,0)
	tvb = g_slice_new(tvbuff_t);
#else
	tvb = g_chunk_new(tvbuff_t, tvbuff_mem_chunk);
#endif

	dan_tvb_init(tvb, type);

	return tvb;
}

//#ifdef LEN_NSN
static guint16
dan_tvb_get_ntohs(tvbuff_t *tvb, const gint offset)
{
    if(global_dan_lte_sdk_BIG_ENDIAN)
        return tvb_get_ntohs(tvb, offset);
    else
	    return tvb_get_letohs(tvb, offset);
}

static guint32
dan_tvb_get_ntoh24(tvbuff_t *tvb, const gint offset)
{
    if(global_dan_lte_sdk_BIG_ENDIAN)
        return tvb_get_ntoh24(tvb, offset);
    else
    	return tvb_get_letoh24(tvb, offset);
}

static guint32
dan_tvb_get_ntohl(tvbuff_t *tvb, const gint offset)
{
    if(global_dan_lte_sdk_BIG_ENDIAN)
        return tvb_get_ntohl(tvb, offset);
    else
    	return tvb_get_letohl(tvb, offset);
}

static guint64
dan_tvb_get_ntoh64(tvbuff_t *tvb, const gint offset)
{
    if(global_dan_lte_sdk_BIG_ENDIAN)
        return tvb_get_ntoh64(tvb, offset);
    else
    	return tvb_get_letoh64(tvb, offset);
}

//#endif //LEN_NSN

guint
dan_tvb_increment_usage_count(tvbuff_t* tvb, const guint count)
{
	tvb->usage_count += count;

	return tvb->usage_count;
}

tvbuff_t*
dan_tvb_new_composite(void)
{
	return dan_tvb_new(TVBUFF_COMPOSITE);
}

static void
dan_add_to_used_in_list_prepend(tvbuff_t *tvb, tvbuff_t *used_in)
{
	tvb->used_in = g_slist_prepend(tvb->used_in, used_in);
	dan_tvb_increment_usage_count(tvb, 1);
}


static void
dan_add_to_used_in_list_append(tvbuff_t *tvb, tvbuff_t *used_in)
{
	tvb->used_in = g_slist_append(tvb->used_in, used_in);
	dan_tvb_increment_usage_count(tvb, 1);
}

void
dan_tvb_composite_append(tvbuff_t* tvb, tvbuff_t* member)
{
	tvb_comp_t	*composite;

	DISSECTOR_ASSERT(tvb && !tvb->initialized);
	DISSECTOR_ASSERT(tvb->type == TVBUFF_COMPOSITE);
	composite = &tvb->tvbuffs.composite;
	composite->tvbs = g_slist_append( composite->tvbs, member );
	dan_add_to_used_in_list_append(tvb, member);
}

void
dan_tvb_composite_prepend(tvbuff_t* tvb, tvbuff_t* member)
{
	tvb_comp_t	*composite;

	DISSECTOR_ASSERT(tvb && !tvb->initialized);
	DISSECTOR_ASSERT(tvb->type == TVBUFF_COMPOSITE);
	composite = &tvb->tvbuffs.composite;
	composite->tvbs = g_slist_prepend( composite->tvbs, member );
	dan_add_to_used_in_list_prepend(tvb, member);
}

void
dan_tvb_composite_finalize(tvbuff_t* tvb)
{
	GSList		*slist;
	guint		num_members;
	tvbuff_t	*member_tvb;
	tvb_comp_t	*composite;
	int		i = 0;

	DISSECTOR_ASSERT(tvb && !tvb->initialized);
	DISSECTOR_ASSERT(tvb->type == TVBUFF_COMPOSITE);
	DISSECTOR_ASSERT(tvb->length == 0);

	composite = &tvb->tvbuffs.composite;
	num_members = g_slist_length(composite->tvbs);

	composite->start_offsets = g_new(guint, num_members);
	composite->end_offsets = g_new(guint, num_members);

	for (slist = composite->tvbs; slist != NULL; slist = slist->next) {
		DISSECTOR_ASSERT((guint) i < num_members);
		member_tvb = slist->data;
		composite->start_offsets[i] = tvb->length;
		tvb->length += member_tvb->length;
		composite->end_offsets[i] = tvb->length - 1;
		i++;
	}

	tvb->initialized = TRUE;
}

static void
dissect_dan_lte_dan_msg_RLC_PAYLOAD(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32* plen, guint32 TB_size, guint32 ue_num, guint32 num_of_mac_head_byte)
{
    proto_tree		*RLC_payload = NULL;
    proto_tree		*RLC_Header = NULL;
	proto_item	    *rlc_ti;
    guint32         num_of_rlc_head_byte = 2;
    guint32         val;
    tvbuff_t        *rlc_tvb = NULL;
    const guint8	*val_ptr;
    int             rlc_tvb_length = 0;
    guint8          extended = 1;
    int             sh_offset = 0;
    guint16         length = 0;
    guint8          padding = 0;

    mac_subh_count = 0;

    val = dan_tvb_get_ntohs(tvb, *plen);
    rlc_ti= proto_tree_add_protocol_format(tree, proto_dan_lte_sdk, tvb, *plen, 2,"RLC PAYLOAD");
    RLC_payload = proto_item_add_subtree(rlc_ti, ett_dan_lte_sdk_msg_data_subtree1);

    if (global_dan_lte_sdk_dissect_RLC)
    {
        RLC_payload = proto_tree_add_uint_format(rlc_ti, hf_dan_lte_msg_MAC_10bitRLC_HEADER_2byte, tvb, *plen, 2, val,"Fixed-Header [0x%04X]", val);
        RLC_Header = proto_item_add_subtree(RLC_payload, ett_dan_lte_sdk_msg_data_subtree2);

        /* Fixed section of RLC Header (appears only once in whole header)*/
        num_of_rlc_head_byte = 2;
        proto_tree_add_item(RLC_Header, hf_dan_lte_msg_MAC_10bitRLC_R1_2byte,tvb, *plen, num_of_rlc_head_byte, FALSE);
        proto_tree_add_item(RLC_Header, hf_dan_lte_msg_MAC_10bitRLC_R2_2byte,tvb, *plen, num_of_rlc_head_byte, FALSE);
        proto_tree_add_item(RLC_Header, hf_dan_lte_msg_MAC_10bitRLC_R3_2byte,tvb, *plen, num_of_rlc_head_byte, FALSE);
        proto_tree_add_item(RLC_Header, hf_dan_lte_msg_MAC_10bitRLC_FI_2byte,tvb, *plen, num_of_rlc_head_byte, FALSE);
        proto_tree_add_item(RLC_Header, hf_dan_lte_msg_MAC_10bitRLC_E1_2byte,tvb, *plen, num_of_rlc_head_byte, FALSE);
        proto_tree_add_item(RLC_Header, hf_dan_lte_msg_MAC_10bitRLC_SN_2byte,tvb, *plen, num_of_rlc_head_byte, FALSE);

        //Checking if there is more subheaders
        extended = tvb_get_bits8(tvb, (*plen*8)+ 5, 1);

        *plen+=num_of_rlc_head_byte;

        sh_offset = (*plen*8);

        while (extended)
        {
            RLC_payload = proto_tree_add_uint_format(rlc_ti, hf_dan_lte_msg_MAC_10bitRLC_Sub_Header, tvb, *plen, 2, val,"Sub-Header %d", Num_of_LI);
            RLC_Header = proto_item_add_subtree(RLC_payload, ett_dan_lte_sdk_msg_data_subtree2);
            Num_of_LI++;
            extended = tvb_get_bits8(tvb, sh_offset, 1);
            proto_tree_add_text(RLC_Header, tvb, 0, 0, "E: %d", extended);
            length = tvb_get_bits16(tvb, sh_offset+1, 11, FALSE);
            proto_tree_add_text(RLC_Header, tvb, 0, 0, "L: %d", length);
            sh_offset+=12;
         }

         if ((Num_of_LI%2) != 0 )
         {
            padding = tvb_get_bits8(tvb, sh_offset, 4);
            proto_tree_add_text(RLC_Header, tvb, 0, 0, "Padding: %d", padding);
            *plen+=((Num_of_LI*12)/8);
         }
         else
            *plen+=(((Num_of_LI*12)+4)/8);

    }
    else
    {
        rlc_tvb = tvb_new_subset(tvb, *plen, -1, tvb_reported_length(tvb)-(*plen));
        rlc_tvb_length = tvb_reported_length(rlc_tvb);
        val_ptr = tvb_get_ptr(tvb, *plen, rlc_tvb_length);
        proto_item_append_text(rlc_ti, " Dissecting RLC has been disabled");
        proto_tree_add_bytes(RLC_Header, hf_dan_lte_msg_MAC_10bitRLC_data, tvb, *plen, rlc_tvb_length, val_ptr);
        *plen += rlc_tvb_length;

    }
}

static void
dissect_dan_lte_dan_msg_MAC_PAYLOAD(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32* plen, guint32 TB_size, guint32 ue_num)
{
    proto_tree		*MAC_payload = NULL;
	proto_tree		*MAC_header = NULL;
	proto_item	    *tf;
	guint32         num_of_mac_head_byte = 4;
    const guint8	*val_ptr;
	guint32 		val;
	guint32         mac_f_header;
	guint8          mac_e_h1;
    guint32         mac_e_header;
    guint32         mac_lcid_header;
    guint8          mac_lcid_h1;
    gboolean        parce_RLC = TRUE;

if(global_dan_lte_sdk_dissect_MAC_DL)
 {

    if (mac_subh_count == 0)
    {
        tf = proto_tree_add_protocol_format(tree, proto_dan_lte_sdk, tvb, (*plen), num_of_mac_head_byte,"MAC PAYLOAD");

    	MAC_payload = proto_item_add_subtree(tf, ett_dan_lte_sdk_msg_data_subtree1);
        MAC_header = proto_item_add_subtree(MAC_payload, ett_dan_lte_sdk_msg_data_subtree2);
        msg_head = tree;
    }
    else
        tf = tree;



    val = tvb_get_guint8(tvb, *plen);

    //Checking for Padding
    mac_e_h1 = (val & 0x20); //checking for more subheaders
    mac_lcid_h1 = (val & 0x1F); // checking if this is a padding header

    if(mac_e_h1 == 0x20)
    {

        if((1 < mac_lcid_h1)&&(mac_lcid_h1 < 10)) //Legal Logical Channels
        {
            val = dan_tvb_get_ntohl(tvb, *plen);

            //inserting the F & E bit into the correct variables
            mac_f_header = (val & 0x00800000);
            mac_e_header = (val & 0x20000000);
            mac_lcid_header = (val & 0x1F000000);

            if (mac_f_header == 0)
            {
                val = dan_tvb_get_ntohs(tvb, *plen);

                num_of_mac_head_byte = 2;
                MAC_payload = proto_tree_add_uint_format(tf, hf_dan_lte_msg_MAC_MAC_HEADER_2byte, tvb, *plen, 2, val,"Sub-Header %d [0x%04X]",mac_subh_count, val);
                MAC_header = proto_item_add_subtree(MAC_payload, ett_dan_lte_sdk_msg_data_subtree2);
                proto_tree_add_item(MAC_header, hf_dan_lte_msg_MAC_MAC_R1_2byte,tvb, *plen, num_of_mac_head_byte, FALSE);
                proto_tree_add_item(MAC_header, hf_dan_lte_msg_MAC_MAC_R2_2byte,tvb, *plen, num_of_mac_head_byte, FALSE);
                proto_tree_add_item(MAC_header, hf_dan_lte_msg_MAC_MAC_E_2byte,tvb, *plen, num_of_mac_head_byte, FALSE);
                proto_tree_add_item(MAC_header, hf_dan_lte_msg_MAC_MAC_LCID_2byte,tvb, *plen, num_of_mac_head_byte, FALSE);
                proto_tree_add_item(MAC_header, hf_dan_lte_msg_MAC_MAC_F_2byte,tvb, *plen, num_of_mac_head_byte, FALSE);
                proto_tree_add_item(MAC_header, hf_dan_lte_msg_MAC_7bitMAC_Length_2byte,tvb, *plen, num_of_mac_head_byte, FALSE);

                *plen += num_of_mac_head_byte;

                mac_subh_count++;
                dissect_dan_lte_dan_msg_MAC_PAYLOAD(tvb, pinfo, tf, plen, TB_size, ue_num);
            }
            else
            {

                val = dan_tvb_get_ntoh24(tvb, *plen);

                num_of_mac_head_byte = 3;
                MAC_payload = proto_tree_add_uint_format(tf, hf_dan_lte_msg_MAC_MAC_HEADER_3byte, tvb, *plen, 3, val,"Sub-Header %d [0x%04X]",mac_subh_count, val);
                MAC_header = proto_item_add_subtree(MAC_payload, ett_dan_lte_sdk_msg_data_subtree2);
                proto_tree_add_item(MAC_header, hf_dan_lte_msg_MAC_MAC_R1_3byte,tvb, *plen, num_of_mac_head_byte, FALSE);
                proto_tree_add_item(MAC_header, hf_dan_lte_msg_MAC_MAC_R2_3byte,tvb, *plen, num_of_mac_head_byte, FALSE);
                proto_tree_add_item(MAC_header, hf_dan_lte_msg_MAC_MAC_E_3byte,tvb, *plen, num_of_mac_head_byte, FALSE);
                proto_tree_add_item(MAC_header, hf_dan_lte_msg_MAC_MAC_LCID_3byte,tvb, *plen, num_of_mac_head_byte, FALSE);
                proto_tree_add_item(MAC_header, hf_dan_lte_msg_MAC_MAC_F_3byte,tvb, *plen, num_of_mac_head_byte, FALSE);
                proto_tree_add_item(MAC_header, hf_dan_lte_msg_MAC_15bitMAC_Length_3byte,tvb, *plen, num_of_mac_head_byte, FALSE);

                *plen += num_of_mac_head_byte;

                mac_subh_count++;
                dissect_dan_lte_dan_msg_MAC_PAYLOAD(tvb, pinfo, tf, plen, TB_size, ue_num);
            }

        }
        else if (mac_lcid_h1 == 0x1F)   //Padding Header (LCID = 31)
        {
            num_of_mac_head_byte = 1;
            MAC_payload = proto_tree_add_uint_format(tf, hf_dan_lte_msg_MAC_MAC_HEADER_1byte, tvb, *plen, 1, val, "Sub-Header %d [0x%02X]",mac_subh_count, val);
            MAC_header = proto_item_add_subtree(MAC_payload, ett_dan_lte_sdk_msg_data_subtree2);
            proto_tree_add_item(MAC_header, hf_dan_lte_msg_MAC_MAC_R1_1byte,tvb, *plen, num_of_mac_head_byte, FALSE);
            proto_tree_add_item(MAC_header, hf_dan_lte_msg_MAC_MAC_R2_1byte,tvb, *plen, num_of_mac_head_byte, FALSE);
            proto_tree_add_item(MAC_header, hf_dan_lte_msg_MAC_MAC_E_1byte,tvb, *plen, num_of_mac_head_byte, FALSE);
            proto_tree_add_item(MAC_header, hf_dan_lte_msg_MAC_MAC_LCID_1byte,tvb, *plen, num_of_mac_head_byte, FALSE);

            *plen += num_of_mac_head_byte;

            mac_subh_count++;
            dissect_dan_lte_dan_msg_MAC_PAYLOAD(tvb, pinfo, tf, plen, TB_size, ue_num);
        }
        else        //Not supported
        {
            val_ptr = tvb_get_ptr(tvb, *plen, (TB_size));
            proto_item_append_text(MAC_payload, " Dissecting LCID Value is not supported");
    		proto_tree_add_bytes(MAC_payload, hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_p_data, tvb, *plen, (TB_size), val_ptr);
    		*plen += (TB_size);
    		mac_e_h1 = 0;
    		parce_RLC = FALSE;
        }

    }
    else
    {
        if((1 < mac_lcid_h1)&&(mac_lcid_h1 < 10)) //Legal Logical Channels
        {
            num_of_mac_head_byte = 1;
            MAC_payload = proto_tree_add_uint_format(tf, hf_dan_lte_msg_MAC_MAC_HEADER_1byte, tvb, *plen, 1, val,"Sub-Header %d [0x%02X]",mac_subh_count, val);
            MAC_header = proto_item_add_subtree(MAC_payload, ett_dan_lte_sdk_msg_data_subtree2);
            proto_tree_add_item(MAC_header, hf_dan_lte_msg_MAC_MAC_R1_1byte,tvb, *plen, num_of_mac_head_byte, FALSE);
            proto_tree_add_item(MAC_header, hf_dan_lte_msg_MAC_MAC_R2_1byte,tvb, *plen, num_of_mac_head_byte, FALSE);
            proto_tree_add_item(MAC_header, hf_dan_lte_msg_MAC_MAC_E_1byte,tvb, *plen, num_of_mac_head_byte, FALSE);
            proto_tree_add_item(MAC_header, hf_dan_lte_msg_MAC_MAC_LCID_1byte,tvb, *plen, num_of_mac_head_byte, FALSE);

            *plen += num_of_mac_head_byte;

        }
        else if (mac_lcid_h1 == 0x1F)   //Padding Header (LCID = 31)
        {
            num_of_mac_head_byte = 1;
            MAC_payload = proto_tree_add_uint_format(tf, hf_dan_lte_msg_MAC_MAC_HEADER_1byte, tvb, *plen, 1, val, "Sub-Header %d [0x%02X]",mac_subh_count, val);
            MAC_header = proto_item_add_subtree(MAC_payload, ett_dan_lte_sdk_msg_data_subtree2);
            proto_tree_add_item(MAC_header, hf_dan_lte_msg_MAC_MAC_R1_1byte,tvb, *plen, num_of_mac_head_byte, FALSE);
            proto_tree_add_item(MAC_header, hf_dan_lte_msg_MAC_MAC_R2_1byte,tvb, *plen, num_of_mac_head_byte, FALSE);
            proto_tree_add_item(MAC_header, hf_dan_lte_msg_MAC_MAC_E_1byte,tvb, *plen, num_of_mac_head_byte, FALSE);
            proto_tree_add_item(MAC_header, hf_dan_lte_msg_MAC_MAC_LCID_1byte,tvb, *plen, num_of_mac_head_byte, FALSE);

            *plen += num_of_mac_head_byte;
        }
        else        //Not supported
        {
            val_ptr = tvb_get_ptr(tvb, *plen, (TB_size));
            proto_item_append_text(MAC_payload, " Dissecting LCID Value is not supported");
    		proto_tree_add_bytes(MAC_payload, hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_p_data, tvb, *plen, (TB_size), val_ptr);
    		*plen += (TB_size);
    		parce_RLC = FALSE;
        }

        if (parce_RLC)
            dissect_dan_lte_dan_msg_RLC_PAYLOAD(tvb, pinfo, msg_head, plen,TB_size, ue_num, num_of_mac_head_byte);
    }

    Num_of_LI = 0;
  }
  else
  {

    tf = proto_tree_add_protocol_format(tree, proto_dan_lte_sdk, tvb, (*plen), (tvb_reported_length(tvb)-(*plen)),"MAC PAYLOAD");
    MAC_payload = proto_item_add_subtree(tf, ett_dan_lte_sdk_msg_data_subtree1);

    val_ptr = tvb_get_ptr(tvb, *plen, (tvb_reported_length(tvb)-(*plen)));
    proto_item_append_text(MAC_payload, " Dissecting MAC has been disabled");
    proto_tree_add_bytes(MAC_payload, hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_p_data, tvb, *plen, (tvb_reported_length(tvb)-(*plen)), val_ptr);
  }
}

static void
dissect_dan_lte_dan_msg_AIRDL_PDSCH_DATA_ELMS_HANDLE(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32* plen)
{
    proto_item      *ti;
	proto_item      *ei;
    proto_tree      *dan_lte_sdk_msg_tb_dsc = NULL;
	proto_tree      *dan_lte_sdk_msg_chunk_dsc = NULL;
    guint32         j;
    guint32         val;
	guint32         data_size = 0;
	guint32			num_of_data_chunks;
	guint32         tb_idx;
    const guint8    *val_ptr;
    tvbuff_t        *total_payload = NULL;
    tvbuff_t        *tvb_temp = NULL;
    tvbuff_t        *mac_tvb;
    gint            data_length;
    mac_lte_info    *mac_info = NULL;
    //guint32         sfn;


    ti = proto_tree_add_protocol_format(tree, proto_dan_lte_sdk, tvb, *plen, 4,
                                      "PDSCH_TB_DATA_ELM_ARR");
    dan_lte_sdk_msg_tb_dsc = proto_item_add_subtree(ti, ett_dan_lte_sdk_msg_data_subtree1);


    val = tvb_get_guint8(tvb, *plen);
    proto_tree_add_uint(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_reserve1, tvb, *plen, 1, val);
    *plen += 1;

    val = tvb_get_guint8(tvb, *plen);
    tb_idx = val;
    proto_tree_add_uint(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_tb_idx, tvb, *plen, 1, val);
    *plen += 1;


	num_of_data_chunks = dan_tvb_get_ntohs(tvb, *plen);
    proto_tree_add_uint(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_num_of_data_chunks, tvb, *plen, 2, num_of_data_chunks);
	*plen += 2;

    /* Initializing the composed buffer and the temp buffer to be of type TVBUFF_COMPOSITE */
    total_payload = dan_tvb_new_composite();
    tvb_temp = dan_tvb_new_composite();

	/* Loop over data elements */
    for (j = 0; j < num_of_data_chunks; j++)
	{
    	ei = proto_tree_add_protocol_format(dan_lte_sdk_msg_tb_dsc, proto_dan_lte_sdk, tvb, *plen, 4,
        	                              "PDSCH_TB_DATA_CHUNKS[%d]", j);
        dan_lte_sdk_msg_chunk_dsc = proto_item_add_subtree(ei, ett_dan_lte_sdk_msg_data_subtree2);

		data_size = dan_tvb_get_ntohs(tvb, *plen);
    	proto_tree_add_uint(dan_lte_sdk_msg_chunk_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_tb_size, tvb, *plen, 2, data_size);
    	*plen += 2;

    	val = dan_tvb_get_ntohs(tvb, *plen);
    	proto_tree_add_uint(dan_lte_sdk_msg_chunk_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_reserve2, tvb, *plen, 2, val);
    	*plen += 2;

        data_length = tvb_length_remaining(tvb, *plen);
        mac_tvb = tvb_new_subset(tvb, *plen, data_length, data_length);

        /* make the temp buffer to be only the data out of the #j chunk */
        tvb_temp = tvb_new_subset(tvb, *plen, data_size, data_size);

       	val_ptr = tvb_get_ptr(tvb, *plen, data_size);
    	proto_tree_add_bytes(dan_lte_sdk_msg_chunk_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_chunk_data, tvb, *plen, data_size, val_ptr);
    	*plen += data_size;

        /* Compose the final buffer with the temp buffer (add the curent data chunk to the total data buffer) */
        dan_tvb_composite_append(total_payload, tvb_temp);

    }

    /* Dissect the MAC layers only if the user has enabled it in  in the preferences menu */
    if (global_dan_lte_sdk_dissect_MAC_DL)
    {
        /* Finalize the composed buffer */
        dan_tvb_composite_finalize(total_payload);

        if (mac_info == NULL)
        {
            /* Allocate & zero struct */
            mac_info = se_alloc0(sizeof(struct mac_lte_info));
        }
        call_dissector_only(dan_mac_lte_handle, (tvbuff_t*)total_payload->used_in->data, pinfo, tree);
   }

}


static void
dissect_dan_lte_dan_msg_AIRDL_PDSCH_REQ(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32* plen)
{
    proto_item  *ti;
    proto_tree      *dan_lte_sdk_msg_data = NULL;
    proto_tree      *dan_lte_sdk_msg_tb_dsc = NULL;
    guint32         num_of_tbs;
    guint32         i;
    guint32         val;
    guint32         TB_size;
    const guint8    *val_ptr;
	float		    off_val;
	float			boost_start_val = -20;
	float		    boost_del = (float)(1);

    /* Wireshark MAC dissecting */
    tvbuff_t        *total_payload = NULL;
    tvbuff_t        *tvb_temp = NULL;
	tvbuff_t        *mac_tvb = NULL;
    gint            data_length;
    mac_lte_info    *mac_info = NULL;
    guint32         sfn;

    col_set_str (pinfo->cinfo, COL_INFO, "DAN_AIRDL_PDSCH_REQ");
    dan_lte_sdk_msg_data = proto_item_add_subtree(tree, ett_dan_lte_sdk_msg_data);

    /* Number of TBs */
    num_of_tbs = tvb_get_guint8(tvb, *plen);
    proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_num_of_tbs, tvb, *plen, 1, num_of_tbs);
    *plen += 1;
    val         = dan_tvb_get_ntoh24(tvb, *plen);
    proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_reserve0, tvb, *plen, 3, val);
    *plen += 3;

    /* Loop over TBs */
    for (i = 0; i < num_of_tbs; i++)
    {
        ti = proto_tree_add_protocol_format(dan_lte_sdk_msg_data, proto_dan_lte_sdk, tvb, (36+i*44), 44,
                                          "PDSCH_TB_DSC[%d]", i);
        dan_lte_sdk_msg_tb_dsc = proto_item_add_subtree(ti, ett_dan_lte_sdk_msg_data_subtree1);


        val = tvb_get_guint8(tvb, *plen);
        proto_tree_add_uint(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_tb_idx, tvb, *plen, 1, val);
        *plen += 1;

        val = tvb_get_guint8(tvb, *plen);
        proto_tree_add_uint(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_reserve1, tvb, *plen, 1, val);
        *plen += 1;

        val = dan_tvb_get_ntohs(tvb, *plen);
        rnti = val;
        proto_tree_add_uint(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_rnti, tvb, *plen, 2, val);
        *plen += 2;

        TB_size = dan_tvb_get_ntohs(tvb, *plen);
        proto_tree_add_uint(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_tb_size, tvb, *plen, 2, TB_size);
        *plen += 2;

        val = dan_tvb_get_ntohs(tvb, *plen);
        proto_tree_add_uint(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_n_rb, tvb, *plen, 2, val);
        *plen += 2;

        val_ptr = tvb_get_ptr(tvb, *plen, sizeof(guint32)*4);
        proto_tree_add_bytes(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_rb_bitmap, tvb, *plen, 4*sizeof(guint32), val_ptr);
        *plen += (4*sizeof(guint32));

        val = dan_tvb_get_ntohl(tvb, *plen);
        proto_tree_add_uint(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_ant_mode, tvb, *plen, 4, val);
        *plen += 4;

        val = dan_tvb_get_ntohl(tvb, *plen);
        proto_tree_add_uint(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_pa, tvb, *plen, 4, val);
        *plen += 4;

        val = tvb_get_guint8(tvb, *plen);
        proto_tree_add_uint(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_mcs, tvb, *plen, 1, val);
        *plen += 1;

        val = tvb_get_guint8(tvb, *plen);
		off_val = api_val_to_lgcl_val(val,boost_start_val,boost_del);
        proto_tree_add_int(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_pdsch_boost_index, tvb, *plen, 1, (gint32)off_val);
        *plen += 1;

        val = tvb_get_guint8(tvb, *plen);
        proto_tree_add_uint(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_rv_idx, tvb, *plen, 1, val);
        *plen += 1;

        val = tvb_get_guint8(tvb, *plen);
        proto_tree_add_uint(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_pmi_codebook_idx, tvb, *plen, 1, val);
        *plen += 1;

        val = tvb_get_guint8(tvb, *plen);
        proto_tree_add_uint(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_rank, tvb, *plen, 1, val);
        *plen += 1;

        val = tvb_get_guint8(tvb, *plen);
        proto_tree_add_uint(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_n_codework, tvb, *plen, 1, val);
        *plen += 1;

        val = tvb_get_guint8(tvb, *plen);
        proto_tree_add_uint(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_codeword_id, tvb, *plen, 1, val);
        *plen += 1;

        val = tvb_get_guint8(tvb, *plen);
        proto_tree_add_uint(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_k_mimo, tvb, *plen, 1, val);
        *plen += 1;

        val = dan_tvb_get_ntohs(tvb, *plen);
        proto_tree_add_uint(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_mimo_id, tvb, *plen, 2, val);
        *plen += 2;

        val = tvb_get_guint8(tvb, *plen);
        proto_tree_add_uint(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_ue_category, tvb, *plen, 1, val);
        *plen += 1;

        val = tvb_get_guint8(tvb, *plen);
        proto_tree_add_uint(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_reserve2, tvb, *plen, 1, val);
        *plen += 1;

        if(global_dan_lte_sdk_IPC_NO_ELM_ARR_DL)
        {

            data_length = tvb_length_remaining(tvb, *plen);
            if(global_dan_lte_sdk_dissect_MAC_DL)
            {
                mac_tvb = tvb_new_subset(tvb, *plen, data_length, data_length);

                if (mac_info == NULL)
                {
                    /* Allocate & zero struct */
                    mac_info = se_alloc0(sizeof(struct mac_lte_info));
                }

                /* Attach mandatory info to the pinfo of the buffer sent to the MAC dissector */
                sfn = tvb_get_guint8(tvb, 28);
                mac_info->subframeNumber = sfn;
                mac_info->rnti = rnti;
                mac_info->radioType = FDD_RADIO;
                mac_info->direction = DIRECTION_DOWNLINK;
                mac_info->rntiType = C_RNTI;
                mac_info->length = tvb_length(mac_tvb) - 8;
                mac_info->ueid = i;

                attach_mac_info_to_dan(pinfo, mac_info);
    //            if(global_dan_lte_sdk_dissect_MAC_DL)
                    call_dissector_only(dan_mac_lte_handle, mac_tvb, pinfo, tree);
                dissect_dan_lte_dan_msg_AIRDL_PDSCH_DATA_ELMS_HANDLE(tvb, pinfo, dan_lte_sdk_msg_tb_dsc, plen);
            }
            else
            {
                dissect_dan_lte_dan_msg_AIRDL_PDSCH_DATA_ELMS_HANDLE(tvb, pinfo, dan_lte_sdk_msg_tb_dsc, plen);
                //val_ptr = tvb_get_ptr(tvb, *plen, (TB_size));
               // proto_tree_add_bytes(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_REQ_p_data, tvb, *plen, (TB_size), val_ptr);
               // *plen += TB_size;
            }
        }
    }
}



static void
dissect_dan_lte_dan_msg_AIRDL_PDSCH_DATA_ELMS_REQ(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32* plen)
{
    proto_item      *ti;
	proto_item      *ei;
    proto_tree      *dan_lte_sdk_msg_data = NULL;
    proto_tree      *dan_lte_sdk_msg_tb_dsc = NULL;
	proto_tree      *dan_lte_sdk_msg_chunk_dsc = NULL;
    guint32         num_of_data_arrs;
    guint32         i,j;
    guint32         val;
	guint32         data_size = 0;
	guint32			num_of_data_chunks;
	guint32         tb_idx;
    const guint8    *val_ptr;
    tvbuff_t        *total_payload = NULL;
    tvbuff_t        *tvb_temp = NULL;
    tvbuff_t        *mac_tvb;
    gint            data_length;
    mac_lte_info    *mac_info = NULL;
    guint32         sfn;

    col_set_str (pinfo->cinfo, COL_INFO, "DAN_AIRDL_PDSCH_DATA_REQ");

    dan_lte_sdk_msg_data = proto_item_add_subtree(tree, ett_dan_lte_sdk_msg_data);

    /* Number of data arrays */
    num_of_data_arrs = tvb_get_guint8(tvb, *plen);
    proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_num_of_tbs, tvb, *plen, 1, num_of_data_arrs);
    *plen += 1;
    val = dan_tvb_get_ntoh24(tvb, *plen);
    proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_reserve0, tvb, *plen, 3, val);
    *plen += 3;

    /* Loop over data arrays */
    for (i = 0; i < num_of_data_arrs; i++)
    {
        ti = proto_tree_add_protocol_format(dan_lte_sdk_msg_data, proto_dan_lte_sdk, tvb, *plen, 4,
                                          "PDSCH_TB_DATA_ELM_ARR[%d]", i);
        dan_lte_sdk_msg_tb_dsc = proto_item_add_subtree(ti, ett_dan_lte_sdk_msg_data_subtree1);


        val = tvb_get_guint8(tvb, *plen);
        proto_tree_add_uint(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_reserve1, tvb, *plen, 1, val);
        *plen += 1;

        val = tvb_get_guint8(tvb, *plen);
        tb_idx = val;
        proto_tree_add_uint(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_tb_idx, tvb, *plen, 1, val);
        *plen += 1;


		num_of_data_chunks = dan_tvb_get_ntohs(tvb, *plen);
        proto_tree_add_uint(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_num_of_data_chunks, tvb, *plen, 2, num_of_data_chunks);
		*plen += 2;

        /* Initializing the composed buffer and the temp buffer to be of type TVBUFF_COMPOSITE */
        total_payload = dan_tvb_new_composite();
        tvb_temp = dan_tvb_new_composite();

		/* Loop over data elements */
	    for (j = 0; j < num_of_data_chunks; j++)
    	{
        	ei = proto_tree_add_protocol_format(dan_lte_sdk_msg_tb_dsc, proto_dan_lte_sdk, tvb, *plen, 4,
            	                              "PDSCH_TB_DATA_CHUNKS[%d]", j);
	        dan_lte_sdk_msg_chunk_dsc = proto_item_add_subtree(ei, ett_dan_lte_sdk_msg_data_subtree2);

			data_size = dan_tvb_get_ntohs(tvb, *plen);
        	proto_tree_add_uint(dan_lte_sdk_msg_chunk_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_tb_size, tvb, *plen, 2, data_size);
        	*plen += 2;

        	val = dan_tvb_get_ntohs(tvb, *plen);
        	proto_tree_add_uint(dan_lte_sdk_msg_chunk_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_reserve2, tvb, *plen, 2, val);
        	*plen += 2;

            data_length = tvb_length_remaining(tvb, *plen);
            mac_tvb = tvb_new_subset(tvb, *plen, data_length, data_length);

            /* make the temp buffer to be only the data out of the #j chunk */
            tvb_temp = tvb_new_subset(tvb, *plen, data_size, data_size);

           	val_ptr = tvb_get_ptr(tvb, *plen, data_size);
        	proto_tree_add_bytes(dan_lte_sdk_msg_chunk_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_chunk_data, tvb, *plen, data_size, val_ptr);
        	*plen += data_size;

            /* Compose the final buffer with the temp buffer (add the curent data chunk to the total data buffer) */
            dan_tvb_composite_append(total_payload, tvb_temp);

	    }

        /* Dissect the MAC layers only if the user has enabled it in  in the preferences menu */
	    if (global_dan_lte_sdk_dissect_MAC_DL)
        {
            /* Finalize the composed buffer */
            dan_tvb_composite_finalize(total_payload);

            if (mac_info == NULL)
            {
                /* Allocate & zero struct */
                mac_info = se_alloc0(sizeof(struct mac_lte_info));
            }

            /* Attach mandatory info to the pinfo of the buffer sent to the MAC dissector */
            sfn = tvb_get_guint8(tvb, 9);
            mac_info->subframeNumber = sfn;
            mac_info->rnti = rnti;
            mac_info->radioType = FDD_RADIO;
            mac_info->direction = DIRECTION_DOWNLINK;
            mac_info->rntiType = C_RNTI;
            mac_info->length = tvb_length(total_payload);
            mac_info->ueid = i;

            attach_mac_info_to_dan(pinfo, mac_info);
            //val_ptr = tvb_get_ptr(total_payload, 0, tvb_length(total_payload));
            //proto_tree_add_text(dan_lte_sdk_msg_tb_dsc, total_payload, 0,0, "tvb_length: %u", tvb_length(total_payload));
            //proto_tree_add_bytes(dan_lte_sdk_msg_tb_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_tb_data, total_payload, 0, tvb_length(total_payload), val_ptr);
            call_dissector_only(dan_mac_lte_handle, (tvbuff_t*)total_payload->used_in->data, pinfo, tree);
       }

    }
}

static void
dissect_dan_lte_dan_msg_AIRDL_PDCCH_REQ(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32* plen)
{
	proto_item	    *ti;
	proto_item      *tf;
	proto_tree	    *dan_lte_sdk_msg_data = NULL;
	proto_tree	    *dan_lte_sdk_msg_ue_dsc = NULL;
	proto_tree      *dan_lte_sdk_msg_ue_payload = NULL;
	proto_tree      *dan_lte_sdk_msg_ue_payload_tb1 = NULL;
	proto_tree      *dan_lte_sdk_msg_ue_payload_tb1_tree = NULL;
	guint32 		num_of_ue;
	guint32 		i;
	guint32 		val,tmp_val32;//, alloc_type;
	guint32         dci_format,f_val2;
    guint64         f2_val;
	float			off_val;
	float			boost_start_val  = -20;
	float			boost_del = (float)(0.5);
	
	if(global_dan_lte_sdk_parse_crc_data)
		boost_del = (float)(1);

    col_set_str (pinfo->cinfo, COL_INFO, "DAN_AIRDL_PDCCH_REQ");

	dan_lte_sdk_msg_data = proto_item_add_subtree(tree, ett_dan_lte_sdk_msg_data);

	/* Number of UEs */
	num_of_ue = dan_tvb_get_ntohs(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_n_ue, tvb, *plen, 2, num_of_ue);
	*plen += 2;
	val = dan_tvb_get_ntohs(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_reserve0, tvb, *plen, 2, val);
	*plen += 2;

	/* Loop over UEs */
	for (i = 0; i < num_of_ue; i++)
	{
		ti = proto_tree_add_protocol_format(dan_lte_sdk_msg_data, proto_dan_lte_sdk, tvb, (36+i*56), 56,
										  "PDCCH_UE_DSC[%d]", i);
		dan_lte_sdk_msg_ue_dsc = proto_item_add_subtree(ti, ett_dan_lte_sdk_msg_data_subtree1);


		val = dan_tvb_get_ntohs(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_rnti, tvb, *plen, 2, val);
		*plen += 2;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_cce_offset, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_reserve1, tvb, *plen, 1, val);
		*plen += 1;

		val = dan_tvb_get_ntohl(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_pdcch_format, tvb, *plen, 4, val);
		*plen += 4;

		dci_format = dan_tvb_get_ntohl(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_dci_format, tvb, *plen, 4, dci_format);
		*plen += 4;

		val = dan_tvb_get_ntohl(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_antenna_selection, tvb, *plen, 4, val);
		*plen += 4;

		val = dan_tvb_get_ntohl(tvb, *plen);
		off_val = api_val_to_lgcl_val(val,boost_start_val,boost_del);
		proto_tree_add_float(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_pdcch_boost, tvb, *plen, 4, off_val);
		*plen += 4;

		val = dan_tvb_get_ntohs(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload_length, tvb, *plen, 2, val);
		*plen += 2;

		val = dan_tvb_get_ntohs(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_reserve2, tvb, *plen, 2, val);
		*plen += 2;

      // Payload DCI parsing
        tf = proto_tree_add_protocol_format(dan_lte_sdk_msg_ue_dsc, proto_dan_lte_sdk, tvb, *plen, 4,
										  "PDCCH_DSC_PAYLOAD");
		dan_lte_sdk_msg_ue_payload = proto_item_add_subtree(tf, ett_dan_lte_sdk_msg_data_subtree2);
        val = dan_tvb_get_ntohl(tvb, *plen);
		
        switch (dci_format)
        {

            case 0:

                if (val != 0)
                {
                    val = tvb_get_letohl(tvb, *plen);
                    proto_tree_add_uint(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload, tvb, *plen, 4, val);
					proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_TYPE,tvb, *plen, 4, TRUE);
					proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_HOPPING,tvb, *plen, 4, TRUE);
					switch(global_dan_lte_sdk_PDCCH_bw_val)
					{	
					case 1:
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_RIV_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_MCS_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_NDI_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_TPC_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CYCSHIFT_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CQI_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_REST_1_4M,tvb, *plen, 4, TRUE);
	
					break;
					case 3:
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_RIV_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_MCS_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_NDI_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_TPC_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CYCSHIFT_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CQI_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_REST_3M,tvb, *plen, 4, TRUE);
	
					break;
					case 5:
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_RIV_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_MCS_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_NDI_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_TPC_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CYCSHIFT_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CQI_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_REST_5M,tvb, *plen, 4, TRUE);
			
					break;
					case 10:
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_RIV_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_MCS_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_NDI_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_TPC_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CYCSHIFT_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CQI_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_REST_10M,tvb, *plen, 4, TRUE);
					break;
					case 15:
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_RIV_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_MCS_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_NDI_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_TPC_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CYCSHIFT_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CQI_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_REST_15M,tvb, *plen, 4, TRUE);
	
					break;
					case 20:
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_RIV_20M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_MCS_20M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_NDI_20M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_TPC_20M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CYCSHIFT_20M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_CQI_20M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_REST_20M,tvb, *plen, 4, TRUE);
					
					break;
					
					}// end of switch-case (BANDWIDTH)
                } // end of if (val != 0)
                *plen += 4*8;
                break;
            case 1:

                if (val != 0)
                {
					val 	= tvb_get_letohl(tvb, *plen);
                    f_val2 	= tvb_get_letohl(tvb, (*plen+4));
                    f2_val 	= val;
					f2_val<<= 32;
					f2_val |= f_val2;

					switch(global_dan_lte_sdk_PDCCH_bw_val)
					{	
					case 1:
						proto_tree_add_uint(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload, tvb, *plen, 4, val);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_MCS_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_HARQ_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_NDI_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_RV_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_TPC_1_4M,tvb, *plen, 4, TRUE);
						break;
					case 3:
						proto_tree_add_uint(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload, tvb, *plen, 4, val);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_TYPE,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_MCS_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_HARQ_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_NDI_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_RV_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_TPC_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_REST_3M,tvb, *plen, 4, TRUE);
						break;
					case 5:
						proto_tree_add_uint(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload, tvb, *plen, 4, val);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_TYPE,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_MCS_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_HARQ_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_NDI_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_RV_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_TPC_5M,tvb, *plen, 4, TRUE);
						break;
					case 10:
						proto_tree_add_uint(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload, tvb, *plen, 4, val);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_TYPE,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_MCS_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_HARQ_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_NDI_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_RV_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_TPC_10M,tvb, *plen, 4, TRUE);
						break;
					case 15:
						proto_tree_add_uint64(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload_64b, tvb, *plen, 8, f2_val);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_TYPE,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_MCS_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_HARQ_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_NDI_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_RV_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_TPC1_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_TPC2_15M,tvb, *plen+4, 4, TRUE);
						break;
					case 20:
						proto_tree_add_uint64(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload_64b, tvb, *plen, 8, f2_val);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_TYPE,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_20M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_MCS_20M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_HARQ1_20M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_HARQ2_20M,tvb, *plen+4, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_NDI_20M,tvb, *plen+4, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_RV_20M,tvb, *plen+4, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_TPC_20M,tvb, *plen+4, 4, TRUE);
						break;
					}// end of switch-case (BANDWIDTH)
                }
                *plen += 4*8;
                break;
            case 2:
                if (val != 0)
                {
					val = tvb_get_letohl(tvb, *plen);
					proto_tree_add_uint(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload, tvb, *plen, 4, val);
					proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_TYPE,tvb, *plen, 4, TRUE);
					proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_ALLOCATION,tvb, *plen, 4, TRUE);
					switch(global_dan_lte_sdk_PDCCH_bw_val)
					{	
					case 1:
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_RIV_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_MCS_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_COUNTER_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_NDI_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_RV_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_TPC_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_REST_1_4M,tvb, *plen, 4, TRUE);
	
					break;
					case 3:
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_RIV_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_MCS_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_COUNTER_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_NDI_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_RV_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_TPC_3M,tvb, *plen, 4, TRUE);	
					break;
					case 5:
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_RIV_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_MCS_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_COUNTER_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_NDI_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_RV_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_TPC_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_REST_5M,tvb, *plen, 4, TRUE);
			
					break;
					case 10:
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_RIV_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_MCS_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_COUNTER_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_NDI_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_RV_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_TPC_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_REST_10M,tvb, *plen, 4, TRUE);
					break;
					case 15:
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_RIV_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_MCS_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_COUNTER_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_NDI_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_RV_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_TPC_15M,tvb, *plen, 4, TRUE);	
					break;
					case 20:
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_RIV_20M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P0_1A_MCS_20M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_COUNTER_20M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_NDI_20M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_RV_20M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1A_TPC_20M,tvb, *plen, 4, TRUE);					
					break;
					
					}// end of switch-case (BANDWIDTH)
                } // end of if (val != 0)

                *plen += 4*8;
                break;
            case 3:
            case 4:
            case 5:
            case 6:

                if (val != 0)
                {

					val 	= tvb_get_letohl(tvb, *plen);
                    f_val2 	= tvb_get_letohl(tvb, (*plen+4));
                    f2_val 	= val;
					f2_val<<= 32;
					f2_val |= f_val2;

					switch(global_dan_lte_sdk_PDCCH_bw_val)
					{	
					case 1:
						proto_tree_add_uint(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload, tvb, *plen, 4, val);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_TPC_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_HARQ_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_SWAP_1_4M,tvb, *plen, 4, TRUE);
						
						tmp_val32 = 1;
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload, ett_dan_lte_sdk_msg_data_subtree3);
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_tree_add_uint_format(dan_lte_sdk_msg_ue_payload,hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_TB1, tvb, *plen, 8, tmp_val32, "TB %d",tmp_val32);
						dan_lte_sdk_msg_ue_payload_tb1 = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload_tb1_tree, ett_dan_lte_sdk_msg_data_subtree4);
						
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS0_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI0_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV0_1_4M,tvb, *plen, 4, TRUE);
						
						tmp_val32 = 2;
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload, ett_dan_lte_sdk_msg_data_subtree3);
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_tree_add_uint_format(dan_lte_sdk_msg_ue_payload,hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_TB1, tvb, *plen, 8, tmp_val32, "TB %d",tmp_val32);
						dan_lte_sdk_msg_ue_payload_tb1 = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload_tb1_tree, ett_dan_lte_sdk_msg_data_subtree4);

						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI1_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV1_1_4M,tvb, *plen, 4, TRUE);
						
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_PRECODING_1_4M,tvb, *plen, 4, TRUE);
						break;
					case 3:
						proto_tree_add_uint64(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload_64b, tvb, *plen, 8, f2_val);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_TYPE,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_TPC_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_HARQ_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_SWAP_3M,tvb, *plen, 4, TRUE);
						
						tmp_val32 = 1;
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload, ett_dan_lte_sdk_msg_data_subtree3);
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_tree_add_uint_format(dan_lte_sdk_msg_ue_payload,hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_TB1, tvb, *plen, 8, tmp_val32, "TB %d",tmp_val32);
						dan_lte_sdk_msg_ue_payload_tb1 = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload_tb1_tree, ett_dan_lte_sdk_msg_data_subtree4);
						
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS0_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI0_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV0_3M,tvb, *plen, 4, TRUE);
						
						tmp_val32 = 2;
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload, ett_dan_lte_sdk_msg_data_subtree3);
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_tree_add_uint_format(dan_lte_sdk_msg_ue_payload,hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_TB1, tvb, *plen, 8, tmp_val32, "TB %d",tmp_val32);
						dan_lte_sdk_msg_ue_payload_tb1 = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload_tb1_tree, ett_dan_lte_sdk_msg_data_subtree4);

						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI1_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV1_3M,tvb, *plen, 4, TRUE);
						
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_PRECODING1_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_PRECODING2_3M,tvb, *plen+4, 4, TRUE);
						break;
					case 5:
						proto_tree_add_uint64(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload_64b, tvb, *plen, 8, f2_val);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_TYPE,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_TPC_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_HARQ_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_SWAP_5M,tvb, *plen, 4, TRUE);
						
						tmp_val32 = 1;
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload, ett_dan_lte_sdk_msg_data_subtree3);
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_tree_add_uint_format(dan_lte_sdk_msg_ue_payload,hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_TB1, tvb, *plen, 8, tmp_val32, "TB %d",tmp_val32);
						dan_lte_sdk_msg_ue_payload_tb1 = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload_tb1_tree, ett_dan_lte_sdk_msg_data_subtree4);
						
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS0_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI0_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV0_5M,tvb, *plen, 4, TRUE);
						
						tmp_val32 = 2;
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload, ett_dan_lte_sdk_msg_data_subtree3);
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_tree_add_uint_format(dan_lte_sdk_msg_ue_payload,hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_TB1, tvb, *plen, 8, tmp_val32, "TB %d",tmp_val32);
						dan_lte_sdk_msg_ue_payload_tb1 = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload_tb1_tree, ett_dan_lte_sdk_msg_data_subtree4);

						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_0_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_1_5M,tvb, *plen+4, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI1_5M,tvb, *plen+4, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV1_5M,tvb, *plen+4, 4, TRUE);
						
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_PRECODING_5M,tvb, *plen+4, 4, TRUE);
						break;
					case 10:
						proto_tree_add_uint64(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload_64b, tvb, *plen, 8, f2_val);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_TYPE,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_TPC_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_HARQ_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_SWAP_10M,tvb, *plen, 4, TRUE);
						
						tmp_val32 = 1;
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload, ett_dan_lte_sdk_msg_data_subtree3);
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_tree_add_uint_format(dan_lte_sdk_msg_ue_payload,hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_TB1, tvb, *plen, 8, tmp_val32, "TB %d",tmp_val32);
						dan_lte_sdk_msg_ue_payload_tb1 = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload_tb1_tree, ett_dan_lte_sdk_msg_data_subtree4);
						
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS0_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI0_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV0_10M,tvb, *plen, 4, TRUE);
						
						tmp_val32 = 2;
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload, ett_dan_lte_sdk_msg_data_subtree3);
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_tree_add_uint_format(dan_lte_sdk_msg_ue_payload,hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_TB1, tvb, *plen, 8, tmp_val32, "TB %d",tmp_val32);
						dan_lte_sdk_msg_ue_payload_tb1 = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload_tb1_tree, ett_dan_lte_sdk_msg_data_subtree4);

						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_10M,tvb, *plen+4, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI1_10M,tvb, *plen+4, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV1_10M,tvb, *plen+4, 4, TRUE);
						
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_PRECODING_10M,tvb, *plen+4, 4, TRUE);
						break;
					case 15:
						proto_tree_add_uint64(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload_64b, tvb, *plen, 8, f2_val);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_TYPE,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_TPC_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_HARQ_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_SWAP_15M,tvb, *plen, 4, TRUE);
						
						tmp_val32 = 1;
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload, ett_dan_lte_sdk_msg_data_subtree3);
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_tree_add_uint_format(dan_lte_sdk_msg_ue_payload,hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_TB1, tvb, *plen, 8, tmp_val32, "TB %d",tmp_val32);
						dan_lte_sdk_msg_ue_payload_tb1 = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload_tb1_tree, ett_dan_lte_sdk_msg_data_subtree4);
						
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS0_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI0_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV0_15M,tvb, *plen+4, 4, TRUE);
						
						tmp_val32 = 2;
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload, ett_dan_lte_sdk_msg_data_subtree3);
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_tree_add_uint_format(dan_lte_sdk_msg_ue_payload,hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_TB1, tvb, *plen, 8, tmp_val32, "TB %d",tmp_val32);
						dan_lte_sdk_msg_ue_payload_tb1 = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload_tb1_tree, ett_dan_lte_sdk_msg_data_subtree4);

						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_15M,tvb, *plen+4, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI1_15M,tvb, *plen+4, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV1_15M,tvb, *plen+4, 4, TRUE);
						
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_PRECODING_15M,tvb, *plen+4, 4, TRUE);
						break;
					case 20:
						proto_tree_add_uint64(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload_64b, tvb, *plen, 8, f2_val);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_TYPE,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_20M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_TPC_20M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_HARQ_20M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_SWAP_20M,tvb, *plen, 4, TRUE);
						
						tmp_val32 = 1;
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload, ett_dan_lte_sdk_msg_data_subtree3);
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_tree_add_uint_format(dan_lte_sdk_msg_ue_payload,hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_TB1, tvb, *plen, 8, tmp_val32, "TB %d",tmp_val32);
						dan_lte_sdk_msg_ue_payload_tb1 = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload_tb1_tree, ett_dan_lte_sdk_msg_data_subtree4);
						
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS0_20M,tvb, *plen+4, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI0_20M,tvb, *plen+4, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV0_20M,tvb, *plen+4, 4, TRUE);
						
						tmp_val32 = 2;
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload, ett_dan_lte_sdk_msg_data_subtree3);
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_tree_add_uint_format(dan_lte_sdk_msg_ue_payload,hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_TB1, tvb, *plen, 8, tmp_val32, "TB %d",tmp_val32);
						dan_lte_sdk_msg_ue_payload_tb1 = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload_tb1_tree, ett_dan_lte_sdk_msg_data_subtree4);

						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_20M,tvb, *plen+4, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI1_20M,tvb, *plen+4, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV1_20M,tvb, *plen+4, 4, TRUE);
						
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_PRECODING_20M,tvb, *plen+4, 4, TRUE);
						break;
					}// end of switch-case (BANDWIDTH)
                }
                *plen += 4*8;
                break;		
            case 7:
				if (val != 0)
                {
				val 	= tvb_get_letohl(tvb, *plen);
                    f_val2 	= tvb_get_letohl(tvb, (*plen+4));
                    f2_val 	= val;
					f2_val<<= 32;
					f2_val |= f_val2;

					switch(global_dan_lte_sdk_PDCCH_bw_val)
					{	
					case 1:
						proto_tree_add_uint(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload, tvb, *plen, 4, val);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_TPC_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_HARQ_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_SWAP_1_4M,tvb, *plen, 4, TRUE);
						
						tmp_val32 = 1;
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload, ett_dan_lte_sdk_msg_data_subtree3);
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_tree_add_uint_format(dan_lte_sdk_msg_ue_payload,hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_TB1, tvb, *plen, 8, tmp_val32, "TB %d",tmp_val32);
						dan_lte_sdk_msg_ue_payload_tb1 = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload_tb1_tree, ett_dan_lte_sdk_msg_data_subtree4);
						
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS0_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI0_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV0_1_4M,tvb, *plen, 4, TRUE);
						
						tmp_val32 = 2;
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload, ett_dan_lte_sdk_msg_data_subtree3);
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_tree_add_uint_format(dan_lte_sdk_msg_ue_payload,hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_TB1, tvb, *plen, 8, tmp_val32, "TB %d",tmp_val32);
						dan_lte_sdk_msg_ue_payload_tb1 = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload_tb1_tree, ett_dan_lte_sdk_msg_data_subtree4);

						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI1_1_4M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV1_1_4M,tvb, *plen, 4, TRUE);
						break;
					case 3:
						proto_tree_add_uint(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload, tvb, *plen, 4, val);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_TYPE,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_TPC_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_HARQ_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_SWAP_3M,tvb, *plen, 4, TRUE);

						tmp_val32 = 1;
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload, ett_dan_lte_sdk_msg_data_subtree3);
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_tree_add_uint_format(dan_lte_sdk_msg_ue_payload,hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_TB1, tvb, *plen, 8, tmp_val32, "TB %d",tmp_val32);
						dan_lte_sdk_msg_ue_payload_tb1 = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload_tb1_tree, ett_dan_lte_sdk_msg_data_subtree4);
						
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS0_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI0_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV0_3M,tvb, *plen, 4, TRUE);
						
						tmp_val32 = 2;
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload, ett_dan_lte_sdk_msg_data_subtree3);
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_tree_add_uint_format(dan_lte_sdk_msg_ue_payload,hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_TB1, tvb, *plen, 8, tmp_val32, "TB %d",tmp_val32);
						dan_lte_sdk_msg_ue_payload_tb1 = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload_tb1_tree, ett_dan_lte_sdk_msg_data_subtree4);

						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI1_3M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV1_3M,tvb, *plen, 4, TRUE);
						break;
					case 5:
						proto_tree_add_uint64(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload_64b, tvb, *plen, 8, f2_val);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_TYPE,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_TPC_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_HARQ_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_SWAP_5M,tvb, *plen, 4, TRUE);
						
						tmp_val32 = 1;
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload, ett_dan_lte_sdk_msg_data_subtree3);
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_tree_add_uint_format(dan_lte_sdk_msg_ue_payload,hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_TB1, tvb, *plen, 8, tmp_val32, "TB %d",tmp_val32);
						dan_lte_sdk_msg_ue_payload_tb1 = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload_tb1_tree, ett_dan_lte_sdk_msg_data_subtree4);
						
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS0_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI0_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV0_5M,tvb, *plen, 4, TRUE);
						
						tmp_val32 = 2;
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload, ett_dan_lte_sdk_msg_data_subtree3);
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_tree_add_uint_format(dan_lte_sdk_msg_ue_payload,hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_TB1, tvb, *plen, 8, tmp_val32, "TB %d",tmp_val32);
						dan_lte_sdk_msg_ue_payload_tb1 = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload_tb1_tree, ett_dan_lte_sdk_msg_data_subtree4);

						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_0_5M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_1_5M,tvb, *plen+4, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI1_5M,tvb, *plen+4, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV1_5M,tvb, *plen+4, 4, TRUE);
						break;
					case 10:
						proto_tree_add_uint64(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload_64b, tvb, *plen, 8, f2_val);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_TYPE,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_TPC_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_HARQ_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_SWAP_10M,tvb, *plen, 4, TRUE);
						
						tmp_val32 = 1;
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload, ett_dan_lte_sdk_msg_data_subtree3);
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_tree_add_uint_format(dan_lte_sdk_msg_ue_payload,hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_TB1, tvb, *plen, 8, tmp_val32, "TB %d",tmp_val32);
						dan_lte_sdk_msg_ue_payload_tb1 = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload_tb1_tree, ett_dan_lte_sdk_msg_data_subtree4);
						
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS0_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI0_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV0_10M,tvb, *plen, 4, TRUE);
						
						tmp_val32 = 2;
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload, ett_dan_lte_sdk_msg_data_subtree3);
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_tree_add_uint_format(dan_lte_sdk_msg_ue_payload,hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_TB1, tvb, *plen, 8, tmp_val32, "TB %d",tmp_val32);
						dan_lte_sdk_msg_ue_payload_tb1 = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload_tb1_tree, ett_dan_lte_sdk_msg_data_subtree4);

						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_10M,tvb, *plen+4, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI1_10M,tvb, *plen+4, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV1_10M,tvb, *plen+4, 4, TRUE);
						
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2A_REST_10M,tvb, *plen+4, 4, TRUE);
						break;
					case 15:
						proto_tree_add_uint64(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload_64b, tvb, *plen, 8, f2_val);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_TYPE,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_TPC_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_HARQ_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_SWAP_15M,tvb, *plen, 4, TRUE);
						
						tmp_val32 = 1;
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload, ett_dan_lte_sdk_msg_data_subtree3);
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_tree_add_uint_format(dan_lte_sdk_msg_ue_payload,hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_TB1, tvb, *plen, 8, tmp_val32, "TB %d",tmp_val32);
						dan_lte_sdk_msg_ue_payload_tb1 = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload_tb1_tree, ett_dan_lte_sdk_msg_data_subtree4);
						
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS0_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI0_15M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV0_15M,tvb, *plen+4, 4, TRUE);
						
						tmp_val32 = 2;
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload, ett_dan_lte_sdk_msg_data_subtree3);
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_tree_add_uint_format(dan_lte_sdk_msg_ue_payload,hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_TB1, tvb, *plen, 8, tmp_val32, "TB %d",tmp_val32);
						dan_lte_sdk_msg_ue_payload_tb1 = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload_tb1_tree, ett_dan_lte_sdk_msg_data_subtree4);

						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_15M,tvb, *plen+4, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI1_15M,tvb, *plen+4, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV1_15M,tvb, *plen+4, 4, TRUE);
						break;
					case 20:
						proto_tree_add_uint64(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload_64b, tvb, *plen, 8, f2_val);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_TYPE,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P1_2_2A_RIV_20M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_TPC_20M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_HARQ_20M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_SWAP_20M,tvb, *plen, 4, TRUE);
						
						tmp_val32 = 1;
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload, ett_dan_lte_sdk_msg_data_subtree3);
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_tree_add_uint_format(dan_lte_sdk_msg_ue_payload,hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_TB1, tvb, *plen, 8, tmp_val32, "TB %d",tmp_val32);
						dan_lte_sdk_msg_ue_payload_tb1 = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload_tb1_tree, ett_dan_lte_sdk_msg_data_subtree4);
						
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS0_20M,tvb, *plen+4, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI0_20M,tvb, *plen+4, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV0_20M,tvb, *plen+4, 4, TRUE);
						
						tmp_val32 = 2;
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload, ett_dan_lte_sdk_msg_data_subtree3);
						dan_lte_sdk_msg_ue_payload_tb1_tree = proto_tree_add_uint_format(dan_lte_sdk_msg_ue_payload,hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_TB1, tvb, *plen, 8, tmp_val32, "TB %d",tmp_val32);
						dan_lte_sdk_msg_ue_payload_tb1 = proto_item_add_subtree(dan_lte_sdk_msg_ue_payload_tb1_tree, ett_dan_lte_sdk_msg_data_subtree4);

						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_MCS1_20M,tvb, *plen+4, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_NDI1_20M,tvb, *plen+4, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload_tb1, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P2_2A_RV1_20M,tvb, *plen+4, 4, TRUE);
						break;
					}// end of switch-case (BANDWIDTH)
                }
                *plen += 4*8;
                break;		
				
            case 8:
				if (val != 0)
                {
					val = tvb_get_letohl(tvb, *plen);	
					switch(global_dan_lte_sdk_PDCCH_bw_val)
					{	
					case 10:
						proto_tree_add_uint(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_payload, tvb, *plen, 4, val);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P3_TPC_10M,tvb, *plen, 4, TRUE);
						proto_tree_add_item(dan_lte_sdk_msg_ue_payload, hf_dan_lte_sdk_msg_AIRDL_PDCCH_REQ_P3_REST_10M,tvb, *plen, 4, TRUE);
						break;
					}// end of switch-case (BANDWIDTH)
				}
				*plen += 4*8;
				break;
            case 9:
            default:
                break;
        }
	}
}

static void
dissect_dan_lte_dan_msg_AIRDL_PHICH_REQ(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32* plen)
{
    proto_item  *ti;
    proto_tree      *dan_lte_sdk_msg_data = NULL;
    proto_tree      *dan_lte_sdk_msg_ue_dsc = NULL;
    guint32         num_of_ue;
    guint32         i;
    guint32         val;

    col_set_str (pinfo->cinfo, COL_INFO, "DAN_AIRDL_PHICH_REQ");
    dan_lte_sdk_msg_data = proto_item_add_subtree(tree, ett_dan_lte_sdk_msg_data);

    /* Number of UEs */
    num_of_ue = tvb_get_guint8(tvb, *plen);
    proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRDL_PHICH_REQ_n_ue, tvb, *plen, 1, num_of_ue);
    *plen += 1;

    val = tvb_get_guint8(tvb, *plen);
    proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRDL_PHICH_REQ_reserve1, tvb, *plen, 1, val);
    *plen += 3;

    /* Loop over TBs */
    for (i = 0; i < num_of_ue; i++)
    {
        ti = proto_tree_add_protocol_format(dan_lte_sdk_msg_data, proto_dan_lte_sdk, tvb, (36+i*4), 4,
                                          "PHICH_DSC[%d]", i);
        dan_lte_sdk_msg_ue_dsc = proto_item_add_subtree(ti, ett_dan_lte_sdk_msg_data_subtree1);


        val = tvb_get_guint8(tvb, *plen);
        proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRDL_PHICH_REQ_group_id, tvb, *plen, 1, val);
        *plen += 1;

        val = tvb_get_guint8(tvb, *plen);
        proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRDL_PHICH_REQ_ack_nack, tvb, *plen, 1, val);
        *plen += 1;

        val = tvb_get_guint8(tvb, *plen);
        proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRDL_PHICH_REQ_seq_idx, tvb, *plen, 1, val);
        *plen += 1;

        val = tvb_get_guint8(tvb, *plen);
        proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRDL_PHICH_REQ_reserve3, tvb, *plen, 1, val);
        *plen += 1;

    }
}

static void
dissect_dan_lte_dan_msg_TTI_EVT(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32* plen)
{
    proto_tree      *dan_lte_sdk_tti_msg = NULL;
    guint32         val;

    col_set_str (pinfo->cinfo, COL_INFO, "DAN_TTI_EVT");

    dan_lte_sdk_tti_msg = proto_item_add_subtree(tree, ett_dan_lte_sdk_msg_data);

    /* TTI packet */
    val = dan_tvb_get_ntohs(tvb, *plen);
    proto_tree_add_uint(dan_lte_sdk_tti_msg, hf_dan_lte_sdk_msg_TTI_EVT_nf, tvb, *plen, 2, val);
    *plen += 2;

    val = tvb_get_guint8(tvb, *plen);
    proto_tree_add_uint(dan_lte_sdk_tti_msg, hf_dan_lte_sdk_msg_TTI_EVT_nsf, tvb, *plen, 1, val);
    *plen += 1;

	val = tvb_get_guint8(tvb, *plen);
    proto_tree_add_uint(dan_lte_sdk_tti_msg, hf_dan_lte_sdk_msg_TTI_EVT_reserve, tvb, *plen, 1, val);
    *plen += 1;


}

static void
dissect_dan_lte_dan_msg_SYS_START_RSP(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32* plen)
{
    proto_tree      *dan_lte_sdk_sys_start_rsp = NULL;
    guint32         val;

    col_set_str (pinfo->cinfo, COL_INFO, "DAN_SYS_START_RSP");

    dan_lte_sdk_sys_start_rsp = proto_item_add_subtree(tree, ett_dan_lte_sdk_msg_data);

    /* Start Responce packet */
    val = dan_tvb_get_ntohl(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_sys_start_rsp, hf_dan_lte_sdk_msg_SYS_START_RSP_err_code, tvb, *plen, 4, val);
	*plen += 4;

}

static void
dissect_dan_lte_dan_msg_AIRUL_PUSCH_REQ(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32* plen)
{
	proto_item	*ti;
	proto_tree		*dan_lte_sdk_msg_data = NULL;
	proto_tree		*dan_lte_sdk_msg_ue_dsc = NULL;
	guint32 		num_of_ue;
	guint32 		i;
	guint32 		val;
	const guint8	*val_ptr;
	guint32 ue_dsc_size = 28;

    col_set_str (pinfo->cinfo, COL_INFO, "AIRUL_PUSCH_REQ");

	dan_lte_sdk_msg_data = proto_item_add_subtree(tree, ett_dan_lte_sdk_msg_data);

	/* Number of UEs */
	num_of_ue = tvb_get_guint8(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUSCH_REQ_n_ue, tvb, *plen, 1, num_of_ue);
	*plen += 1;

	val = dan_tvb_get_ntohl(tvb, *plen) >> 8;
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUSCH_REQ_reserved, tvb, *plen, 3, val);
	*plen += 3;

	/* Loop over UEs */
	if(global_dan_lte_sdk_parse_crc_data){
		ue_dsc_size += 8;
	}else if(global_dan_lte_sdk_parse_sounding){
		ue_dsc_size += 4;
	}
	for (i = 0; i < num_of_ue; i++)
	{
		ti = proto_tree_add_protocol_format(dan_lte_sdk_msg_data, proto_dan_lte_sdk, tvb, (32+i*ue_dsc_size), ue_dsc_size,
			"PUSCH_UE_DSC[%d]", i);
		dan_lte_sdk_msg_ue_dsc = proto_item_add_subtree(ti, ett_dan_lte_sdk_msg_data_subtree1);

		val = dan_tvb_get_ntohs(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_rnti, tvb, *plen, 2, val);
		*plen += 2;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_MCS, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_rank, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_rb_start, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_rb_num, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_dl_harq_chan_id, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_n2dmrs, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_harq_re_tx, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_cqi_nbits, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_ri_nbits, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_acknack_nbits, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_beta_offset_acknack, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_beta_offset_cqi, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_beta_offset_ri, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_rb_num_init, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_srs_init, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_MCS_init, tvb, *plen, 1, val);
		*plen += 1;

		val = dan_tvb_get_ntohs(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_tb_size, tvb, *plen, 2, val);
		*plen += 2;

		val = dan_tvb_get_ntohl(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_uci_format, tvb, *plen, 4, val);
		*plen += 4;
		
		if(global_dan_lte_sdk_parse_crc_data){
			val = tvb_get_guint8(tvb, *plen);
			proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_crc_data, tvb, *plen, 1, val);
			*plen += 1;

			val = tvb_get_guint8(tvb, *plen);
			proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_ul_harq_chan_id, tvb, *plen, 1, val);
			*plen += 1;
				
			val = tvb_get_guint8(tvb, *plen);
			proto_tree_add_int(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_ri_bo, tvb, *plen, 1, ((gint32)val) - 16);
			*plen += 1;

			val = tvb_get_guint8(tvb, *plen);
			proto_tree_add_int(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_cqi_bo, tvb, *plen, 1, ((gint32)val) - 16);
			*plen += 1;

			val = tvb_get_guint8(tvb, *plen);
			proto_tree_add_int(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_acknack_bo, tvb, *plen, 1, ((gint32)val) - 16);
			*plen += 1;

			if(global_dan_lte_sdk_parse_sounding){
				val = tvb_get_guint8(tvb, *plen);
				proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_srs_present, tvb, *plen, 1, val);
				*plen += 1;
			
				val = dan_tvb_get_ntohl(tvb, *plen) >> 16;
				proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_reserved2, tvb, *plen, 2, val);
				*plen += 2;

			}else{			
				val = dan_tvb_get_ntohl(tvb, *plen) >> 8;
				proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_reserved, tvb, *plen, 3, val);
				*plen += 3;
			}

		}else if(global_dan_lte_sdk_parse_sounding){
			val = tvb_get_guint8(tvb, *plen);
			proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_srs_present, tvb, *plen, 1, val);
			*plen += 1;
		
			val = dan_tvb_get_ntohl(tvb, *plen) >> 8;
			proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_reserved, tvb, *plen, 3, val);
			*plen += 3;
		}

		val_ptr = tvb_get_ptr(tvb, *plen, (sizeof(guint32)));
		proto_tree_add_bytes(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_user_data, tvb, *plen, (sizeof(guint32)), val_ptr);
		*plen += (sizeof(guint32));

        if(global_dan_lte_sdk_UL_parse_p_data)
        {
            val = dan_tvb_get_ntohl(tvb, *plen);
            proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_PUSCH_TB_DSC_p_data, tvb, *plen, 4, val);
            *plen += 4;
        }

	}
}

static void
dissect_dan_lte_dan_msg_AIRUL_PUSCH_EVT(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32* plen)
{
	proto_item	*ti;
	proto_item	*ei;
	proto_item	*di;
	proto_tree		*dan_lte_sdk_msg_data = NULL;
	proto_tree		*dan_lte_sdk_msg_ue_dsc = NULL;
    proto_tree      *dan_lte_sdk_msg_elm_arr = NULL;
	proto_tree      *dan_lte_sdk_msg_chunk_dsc = NULL;
	guint32 		num_of_ue;
	guint32         TB_size = 0;
	guint32 		i,j;
	guint32 		val;
	gint32			s_val;
	guint32         data_size = 0;
	guint32			num_of_data_chunks;
	guint32         tb_idx;
	float           off_val;
	float           un_start_val  = -20;
	float           zer_start_val = -130;
	float           to_start_val  = -1024;
	float           un_del = (float)(0.2);
	float           zer_del = 1;

    /* Wireshark MAC dissecting */
    tvbuff_t        *total_payload = NULL;
    tvbuff_t        *tvb_temp = NULL;
	tvbuff_t        *mac_tvb = NULL;
    gint            data_length;
    mac_lte_info    *mac_info = NULL;
    guint32         sfn;
	const guint8	*val_ptr;
	guint8			data_present;

    col_set_str (pinfo->cinfo, COL_INFO, "AIRUL_PUSCH_EVT");

	dan_lte_sdk_msg_data = proto_item_add_subtree(tree, ett_dan_lte_sdk_msg_data);

    /* Number of UEs */
	num_of_ue = tvb_get_guint8(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_n_ue, tvb, *plen, 1, num_of_ue);
	*plen += 1;

	val = dan_tvb_get_ntoh24(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_reserved, tvb, *plen, 3, val);
	*plen += 3;

	/* Loop over UEs */
	for (i = 0; i < num_of_ue; i++)
	{
		ti = proto_tree_add_protocol_format(dan_lte_sdk_msg_data, proto_dan_lte_sdk, tvb, *plen, 20,
										  "PUSCH_UE_DSC[%d]", i);
		dan_lte_sdk_msg_ue_dsc = proto_item_add_subtree(ti, ett_dan_lte_sdk_msg_data_subtree1);

		val = dan_tvb_get_ntohs(tvb, *plen);
		rnti = val;
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_rnti, tvb, *plen, 2, val);
		*plen += 2;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_n_rb, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_rank, tvb, *plen, 1, val);
		*plen += 1;

		s_val = dan_tvb_get_ntohs(tvb, *plen);
		off_val = api_val_to_lgcl_val(s_val,to_start_val,zer_del);
		proto_tree_add_int(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_timing_offset, tvb, *plen, 2, (gint32)off_val);
		*plen += 2;

		val = dan_tvb_get_ntohs(tvb, *plen);
		off_val = api_val_to_lgcl_val(val,un_start_val,un_del);
		proto_tree_add_float(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_c2i, tvb, *plen, 2, off_val);
		*plen += 2;

		TB_size = dan_tvb_get_ntohs(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_tb_size, tvb, *plen, 2, TB_size);
		*plen += 2;

		if(global_dan_lte_sdk_parse_crc_data){
			val = tvb_get_guint8(tvb, *plen);
			off_val = api_val_to_lgcl_val(val,zer_start_val,zer_del);
			proto_tree_add_int(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_RSSI, tvb, *plen, 1, (gint32)off_val);
			*plen += 1;

			data_present = tvb_get_guint8(tvb, *plen);
			proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_data_present, tvb, *plen, 1, data_present);
			*plen += 1;
		}else{
			val = dan_tvb_get_ntohs(tvb, *plen);
			off_val = api_val_to_lgcl_val(val,zer_start_val,zer_del);
			proto_tree_add_int(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_RSSI, tvb, *plen, 2, (gint32)off_val);
			*plen += 2;
			
			data_present = (~tvb_get_guint8(tvb, *plen))&(0x1);
		}

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_crc_detect, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_sigma_kr, tvb, *plen, 1, val);
		*plen += 1;

		s_val = dan_tvb_get_ntohs(tvb, *plen);
		off_val = api_val_to_lgcl_val(s_val,un_start_val,un_del);
		proto_tree_add_float(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_ec2i, tvb, *plen, 2, off_val);
		*plen += 2;

		val = dan_tvb_get_ntohl(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_user_data, tvb, *plen, 4, val);
		*plen += 4;

        if(data_present != 0)
        {
            if(global_dan_lte_sdk_IPC_NO_ELM_ARR_UL)
            {
                 di = proto_tree_add_protocol_format(dan_lte_sdk_msg_ue_dsc, proto_dan_lte_sdk, tvb, *plen, 4,
                                                   "PUSCH_TB_DATA_ELM_ARR");
                 dan_lte_sdk_msg_elm_arr = proto_item_add_subtree(di, ett_dan_lte_sdk_msg_data_subtree2);


                 val = tvb_get_guint8(tvb, *plen);
                 proto_tree_add_uint(dan_lte_sdk_msg_elm_arr, hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_reserve1, tvb, *plen, 1, val);
                 *plen += 1;

                 val = tvb_get_guint8(tvb, *plen);
                 tb_idx = val;
                 proto_tree_add_uint(dan_lte_sdk_msg_elm_arr, hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_tb_idx, tvb, *plen, 1, val);
                 *plen += 1;


                 num_of_data_chunks = dan_tvb_get_ntohs(tvb, *plen);
                 proto_tree_add_uint(dan_lte_sdk_msg_elm_arr, hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_num_of_data_chunks, tvb, *plen, 2, num_of_data_chunks);
                 *plen += 2;

                 /* Initializing the composed buffer and the temp buffer to be of type TVBUFF_COMPOSITE */
                 total_payload = dan_tvb_new_composite();
                 tvb_temp = dan_tvb_new_composite();

                 /* Loop over data elements */
                 for (j = 0; j < num_of_data_chunks; j++)
                 {
                     ei = proto_tree_add_protocol_format(dan_lte_sdk_msg_elm_arr, proto_dan_lte_sdk, tvb, *plen, 4,
                                                       "PUSCH_TB_DATA_CHUNKS[%d]", j);
                     dan_lte_sdk_msg_chunk_dsc = proto_item_add_subtree(ei, ett_dan_lte_sdk_msg_data_subtree2);

                     data_size = dan_tvb_get_ntohs(tvb, *plen);
                     proto_tree_add_uint(dan_lte_sdk_msg_chunk_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_tb_size, tvb, *plen, 2, data_size);
                     *plen += 2;

                     val = dan_tvb_get_ntohs(tvb, *plen);
                     proto_tree_add_uint(dan_lte_sdk_msg_chunk_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_reserve2, tvb, *plen, 2, val);
                     *plen += 2;

                     data_length = tvb_length_remaining(tvb, *plen);
                     mac_tvb = tvb_new_subset(tvb, *plen, data_length, data_length);

                     /* make the temp buffer to be only the data out of the #j chunk */
                     tvb_temp = tvb_new_subset(tvb, *plen, data_size, data_size);

                     val_ptr = tvb_get_ptr(tvb, *plen, data_size);
                     proto_tree_add_bytes(dan_lte_sdk_msg_chunk_dsc, hf_dan_lte_sdk_msg_AIRDL_PDSCH_DATA_ELMS_REQ_chunk_data, tvb, *plen, data_size, val_ptr);
                     *plen += data_size;

                     /* Compose the final buffer with the temp buffer (add the curent data chunk to the total data buffer) */
                     dan_tvb_composite_append(total_payload, tvb_temp);

                 }

                 /* Dissect the MAC layers only if the user has enabled it in  in the preferences menu */
                 if (global_dan_lte_sdk_dissect_MAC_UL)
                 {
                     /* Finalize the composed buffer */
                     dan_tvb_composite_finalize(total_payload);

                     if (mac_info == NULL)
                     {
                         /* Allocate & zero struct */
                         mac_info = se_alloc0(sizeof(struct mac_lte_info));
                     }

                     /* Attach mandatory info to the pinfo of the buffer sent to the MAC dissector */
                     sfn = tvb_get_guint8(tvb, 9);
                     mac_info->subframeNumber = sfn;
                     mac_info->rnti = rnti;
                     mac_info->radioType = FDD_RADIO;
                     mac_info->direction = DIRECTION_UPLINK;
                     mac_info->rntiType = C_RNTI;
                     mac_info->length = TB_size;
                     mac_info->ueid = i;

                     attach_mac_info_to_dan(pinfo, mac_info);
                     call_dissector_only(dan_mac_lte_handle, (tvbuff_t*)total_payload->used_in->data, pinfo, tree);
                }
                else
                {
                    /* Finalize the composed buffer */
                    dan_tvb_composite_finalize(total_payload);
                }

           }
            else
            {

                data_length = tvb_length_remaining(tvb, *plen);
                mac_tvb = tvb_new_subset(tvb, *plen, data_length, data_length);

                if (mac_info == NULL)
                {
                    /* Allocate & zero struct */
                    mac_info = se_alloc0(sizeof(struct mac_lte_info));
                }

                sfn = tvb_get_guint8(tvb, 9);
                mac_info->subframeNumber = sfn;
                mac_info->rnti = rnti;
                mac_info->radioType = FDD_RADIO;
                mac_info->direction = DIRECTION_UPLINK;
                mac_info->rntiType = C_RNTI;
                mac_info->length = TB_size;
                mac_info->ueid = i;



                attach_mac_info_to_dan(pinfo, mac_info);
                if(global_dan_lte_sdk_dissect_MAC_UL)
                    call_dissector_only(dan_mac_lte_handle, mac_tvb, pinfo, tree);
                else
                {
                    val_ptr = tvb_get_ptr(tvb, *plen, (TB_size));
        		    proto_tree_add_bytes(dan_lte_sdk_msg_ue_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_EVT_p_data, tvb, *plen, (TB_size), val_ptr);
                    *plen += TB_size;
                }
             }
        }
	}
}

static void
dissect_dan_lte_dan_msg_AIRUL_PUSCH_CTRL_EVT (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32* plen)
{
	proto_item	*ti;
	proto_tree		*dan_lte_sdk_msg_data = NULL;
	proto_tree		*dan_lte_sdk_msg_ue_ctrl_dsc = NULL;
	guint32 		num_of_ue;
	guint32         TB_size = 0;
	guint32 		i;
	guint32 		val;
	tvbuff_t        *mac_tvb = NULL;
	
	guint32			desc_size = 20;

    col_set_str (pinfo->cinfo, COL_INFO, "AIRUL_PUSCH_CTRL_EVT");

	dan_lte_sdk_msg_data = proto_item_add_subtree(tree, ett_dan_lte_sdk_msg_data);

    /* Number of UEs */
	num_of_ue = tvb_get_guint8(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_n_ue, tvb, *plen, 1, num_of_ue);
	*plen += 1;

	val = dan_tvb_get_ntoh24(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_reserved, tvb, *plen, 3, val);
	*plen += 3;

	/* Loop over UEs */
	if(global_dan_lte_sdk_ctrl_evt_yosi) desc_size += 4;
	for (i = 0; i < num_of_ue; i++)
	{
		ti = proto_tree_add_protocol_format(dan_lte_sdk_msg_data, proto_dan_lte_sdk, tvb, (36+i*(desc_size+(TB_size))), 20,
										  "PUSCH_UE_CTRL_DSC[%d]", i);
		dan_lte_sdk_msg_ue_ctrl_dsc = proto_item_add_subtree(ti, ett_dan_lte_sdk_msg_data_subtree1);

		val = dan_tvb_get_ntohs(tvb, *plen);
		rnti = val;
		proto_tree_add_uint(dan_lte_sdk_msg_ue_ctrl_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_rnti, tvb, *plen, 2, val);
		*plen += 2;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_ctrl_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_ack_nack_presence, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_ctrl_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_ack_nack, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_ctrl_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_dl_harq_chan_id, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_ctrl_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_ri_presence, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_ctrl_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_ri, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_ctrl_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_reseved2, tvb, *plen, 1, val);
		*plen += 1;

		val = dan_tvb_get_ntohl(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_ue_ctrl_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_cqi_presence, tvb, *plen, 4, val);
		*plen += 4;

		if(!global_dan_lte_sdk_ctrl_evt_yosi)
		{
			val = dan_tvb_get_ntohl(tvb, *plen);
			proto_tree_add_uint(dan_lte_sdk_msg_ue_ctrl_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_uci_format, tvb, *plen, 4, val);
			*plen += 4;

			val = dan_tvb_get_ntohl(tvb, *plen);
			proto_tree_add_uint(dan_lte_sdk_msg_ue_ctrl_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_Payload, tvb, *plen, 4, val);
			*plen += 4;
		}
		else
		{
			val = dan_tvb_get_ntohl(tvb, *plen);
			proto_tree_add_uint(dan_lte_sdk_msg_ue_ctrl_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_uci_format_yosi, tvb, *plen, 4, val);
			*plen += 4;

			val = dan_tvb_get_ntohl(tvb, *plen);
			proto_tree_add_uint(dan_lte_sdk_msg_ue_ctrl_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_Payload, tvb, *plen, 4, val);
			*plen += 4;

			val = dan_tvb_get_ntohl(tvb, *plen);
			proto_tree_add_uint(dan_lte_sdk_msg_ue_ctrl_dsc, hf_dan_lte_sdk_msg_AIRUL_PUSCH_CTRL_EVT_Payload_yosi, tvb, *plen, 4, val);
			*plen += 4;
		}

    }
}

static void
dissect_dan_lte_dan_msg_AIRUL_PUSCH_MEAS_EVT (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32* plen)
{
	proto_tree		*dan_lte_sdk_msg_data = NULL;
	guint32 		val;
	float           off_val;
	float           un_start_val = -20;
	float           zer_start_val = -130;
	float           un_del = (float)(0.2);
	float           zer_del = 1;

    col_set_str (pinfo->cinfo, COL_INFO, "DAN_AIRUL_PUSCH_MEAS_EVT");

	dan_lte_sdk_msg_data = proto_item_add_subtree(tree, ett_dan_lte_sdk_msg_data);

	val = dan_tvb_get_ntohs(tvb, *plen);
    off_val = api_val_to_lgcl_val(val,zer_start_val,zer_del);
	proto_tree_add_int(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_avg_rssi, tvb, *plen, 2, (gint32)off_val);
	*plen += 2;

	val = dan_tvb_get_ntohs(tvb, *plen);
    off_val = api_val_to_lgcl_val(val,zer_start_val,zer_del);
	proto_tree_add_int(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_avg_ant1_rssi, tvb, *plen, 2, (gint32)off_val);
	*plen += 2;

	val = dan_tvb_get_ntohs(tvb, *plen);
    off_val = api_val_to_lgcl_val(val,zer_start_val,zer_del);
	proto_tree_add_int(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_avg_ant2_rssi, tvb, *plen, 2, (gint32)off_val);
	*plen += 2;

	val = dan_tvb_get_ntohs(tvb, *plen);
    off_val = api_val_to_lgcl_val(val,zer_start_val,zer_del);
	proto_tree_add_int(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_avg_ant3_rssi, tvb, *plen, 2, (gint32)off_val);
	*plen += 2;

	val = dan_tvb_get_ntohs(tvb, *plen);
    off_val = api_val_to_lgcl_val(val,zer_start_val,zer_del);
	proto_tree_add_int(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_avg_ant4_rssi, tvb, *plen, 2, (gint32)off_val);
	*plen += 2;

	val = dan_tvb_get_ntohs(tvb, *plen);
    off_val = api_val_to_lgcl_val(val,un_start_val,un_del);
	proto_tree_add_float(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_avg_c2i, tvb, *plen, 2, off_val);
	*plen += 2;

	val = dan_tvb_get_ntohs(tvb, *plen);
	if(val == 0xFFFF)
		off_val = (float)val;
	else
		off_val = api_val_to_lgcl_val(val,zer_start_val,zer_del);
	proto_tree_add_int(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_avg_ni, tvb, *plen, 2, (gint32)off_val);
	*plen += 2;

	val = tvb_get_guint8(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_n_ue, tvb, *plen, 1, val);
	*plen += 1;

	if(global_dan_lte_sdk_parse_crc_data){

	val = tvb_get_guint8(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_n_tb, tvb, *plen, 1, val);
	*plen += 1;

	val = tvb_get_guint8(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_n_tb_crc, tvb, *plen, 1, val);
	*plen += 1;

	//val = dan_tvb_get_ntohl(tvb, *plen) >> 8;
	val = dan_tvb_get_ntoh24(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_reserved2, tvb, *plen, 3, val);
	*plen += 3;
	}else{
	val = tvb_get_guint8(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUSCH_MEAS_EVT_reserved, tvb, *plen, 1, val);
	*plen += 1;
	}
}


static void
dissect_dan_lte_dan_msg_CFG_GET_REQ(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32* plen)
{
	proto_tree	    *dan_lte_sdk_msg_data = NULL;
	guint32 		val;


    col_set_str (pinfo->cinfo, COL_INFO, "DAN_CFG_GET_REQ");

	dan_lte_sdk_msg_data = proto_item_add_subtree(tree, ett_dan_lte_sdk_msg_data);

	val = dan_tvb_get_ntohl(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_GET_REQ_param_id, tvb, *plen, 4, val);
	*plen += 4;

	val = dan_tvb_get_ntohl(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_GET_REQ_param_type, tvb, *plen, 4, val);
	*plen += 4;

	val = dan_tvb_get_ntohs(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_GET_REQ_index, tvb, *plen, 2, val);
	*plen += 2;

	val = dan_tvb_get_ntohs(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_GET_REQ_reserved, tvb, *plen, 2, val);
	*plen += 2;
}

static void
dissect_dan_lte_dan_msg_CFG_GET_RSP(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32* plen)
{
    proto_item  *param;
    proto_tree      *dan_lte_sdk_msg_data = NULL;
	proto_tree	    *dan_lte_sdk_msg_param_val = NULL;
	guint32 		param_type;
	guint32         num_of_param;
	guint32 		val;
	guint32 		i;
	guint32 		data_size;
	const guint8	*val_ptr;

    col_set_str (pinfo->cinfo, COL_INFO, "DAN_CFG_GET_RSP");

	dan_lte_sdk_msg_data = proto_item_add_subtree(tree, ett_dan_lte_sdk_msg_data);

	param_type = dan_tvb_get_ntohs(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_PARAM_DSC_param_type, tvb, *plen, 4, param_type);
	*plen += 4;

    switch(param_type)
    {
        case DAN_E_CFG_PARAM_TYPE_NUM:
            val = dan_tvb_get_ntohl(tvb, *plen);
	        proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_PARAM_NUM_DSC_param_id, tvb, *plen, 4, val);
	        *plen += 4;

	        val = dan_tvb_get_ntohl(tvb, *plen);
	        proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_PARAM_NUM_DSC_value, tvb, *plen, 4, val);
	        *plen += 4;

	        val = dan_tvb_get_ntohs(tvb, *plen);
	        proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_PARAM_NUM_DSC_index, tvb, *plen, 2, val);
	        *plen += 2;

	        val = dan_tvb_get_ntohs(tvb, *plen);
	        proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_PARAM_NUM_DSC_reserved, tvb, *plen, 2, val);
	        *plen += 2;

            break;

        case DAN_E_CFG_PARAM_TYPE_DATA:
            val = dan_tvb_get_ntohl(tvb, *plen);
	        proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_PARAM_DATA_DSC_param_id, tvb, *plen, 4, val);
	        *plen += 4;

	        val = dan_tvb_get_ntohs(tvb, *plen);
	        proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_PARAM_DATA_DSC_index, tvb, *plen, 2, val);
	        *plen += 2;

	        val = dan_tvb_get_ntohs(tvb, *plen);
	        proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_PARAM_DATA_DSC_reserved, tvb, *plen, 2, val);
	        *plen += 2;

	        data_size = dan_tvb_get_ntohl(tvb, *plen);
	        proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_DAN_BUF_size, tvb, *plen, 4, data_size);
	        *plen += 4;

	        val_ptr = tvb_get_ptr(tvb, *plen, data_size);
		    proto_tree_add_bytes(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_DAN_BUF_data, tvb, *plen, data_size, val_ptr);
		    *plen += data_size;

            break;

        case DAN_E_CFG_PARAM_TYPE_NUM_ARR:
            val = dan_tvb_get_ntohl(tvb, *plen);
	        proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_PARAM_NUM_ARR_DSC_param_id, tvb, *plen, 4, val);
	        *plen += 4;

	        val = dan_tvb_get_ntohs(tvb, *plen);
	        proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_PARAM_NUM_ARR_DSC_start_index, tvb, *plen, 2, val);
	        *plen += 2;

	        num_of_param = dan_tvb_get_ntohs(tvb, *plen);
	        proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_PARAM_NUM_ARR_DSC_num_of_params, tvb, *plen, 2, num_of_param);
	        *plen += 2;

            for (i=0; i<num_of_param; i++)
            {
                param = proto_tree_add_uint_format(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_PARAM_NUM_ARR_DSC_values,tvb,0,num_of_param*sizeof(guint32),val, "Values[%d]: ",num_of_param);
    	        val = dan_tvb_get_ntohl(tvb, *plen);

    	        proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_PARAM_NUM_ARR_DSC_values, tvb, *plen, 4, val);
    	        *plen += 4;
	        }

            break;
    }
}


static void
dissect_dan_lte_dan_msg_CFG_SET_RSP(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32* plen)
{
	proto_tree	    *dan_lte_sdk_msg_data = NULL;
	guint32 		val;


    col_set_str (pinfo->cinfo, COL_INFO, "DAN_CFG_SET_RSP");

	dan_lte_sdk_msg_data = proto_item_add_subtree(tree, ett_dan_lte_sdk_msg_data);

	val = dan_tvb_get_ntohl(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_COMMON_ERR_CODE_type, tvb, *plen, 4, val);
	*plen += 4;

	val = dan_tvb_get_ntohl(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_COMMON_ERR_CODE_msg_type, tvb, *plen, 4, val);
	*plen += 4;

	val = dan_tvb_get_ntohl(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_COMMON_ERR_CODE_msg_seq, tvb, *plen, 4, val);
	*plen += 4;

	val = dan_tvb_get_ntohl(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_COMMON_ERR_CODE_user_data, tvb, *plen, 4, val);
	*plen += 4;

}


static void
dissect_dan_lte_dan_msg_CFG_SET_REQ(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32* plen)
{
	proto_tree	    *dan_lte_sdk_msg_data = NULL;
	guint32 		param_type;
	guint32 		val;
	guint32 		data_size;
	const guint8	*val_ptr;

    col_set_str (pinfo->cinfo, COL_INFO, "DAN_CFG_SET_REQ");

	dan_lte_sdk_msg_data = proto_item_add_subtree(tree, ett_dan_lte_sdk_msg_data);

	param_type = dan_tvb_get_ntohl(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_PARAM_DSC_param_type, tvb, *plen, 4, param_type);
	*plen += 4;

    switch(param_type)
    {
        case DAN_E_CFG_PARAM_TYPE_NUM:
            val = dan_tvb_get_ntohl(tvb, *plen);
	        proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_PARAM_NUM_DSC_param_id, tvb, *plen, 4, val);
	        *plen += 4;

	        val = dan_tvb_get_ntohl(tvb, *plen);
	        proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_PARAM_NUM_DSC_value, tvb, *plen, 4, val);
	        *plen += 4;

	        val = dan_tvb_get_ntohs(tvb, *plen);
	        proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_PARAM_NUM_DSC_index, tvb, *plen, 2, val);
	        *plen += 2;

	        val = dan_tvb_get_ntohs(tvb, *plen);
	        proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_PARAM_NUM_DSC_reserved, tvb, *plen, 2, val);
	        *plen += 2;

            break;

        case DAN_E_CFG_PARAM_TYPE_DATA:
            val = dan_tvb_get_ntohl(tvb, *plen);
	        proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_PARAM_DATA_DSC_param_id, tvb, *plen, 4, val);
	        *plen += 4;

	        val = dan_tvb_get_ntohs(tvb, *plen);
	        proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_PARAM_DATA_DSC_index, tvb, *plen, 2, val);
	        *plen += 2;

	        val = dan_tvb_get_ntohs(tvb, *plen);
	        proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_PARAM_DATA_DSC_reserved, tvb, *plen, 2, val);
	        *plen += 2;

	        data_size = dan_tvb_get_ntohl(tvb, *plen);
	        proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_DAN_BUF_size, tvb, *plen, 4, data_size);
	        *plen += 4;

	        val_ptr = tvb_get_ptr(tvb, *plen, data_size);
		    proto_tree_add_bytes(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_DAN_BUF_data, tvb, *plen, data_size, val_ptr);
		    *plen += data_size;

            break;

        case DAN_E_CFG_PARAM_TYPE_NUM_ARR:
            val = dan_tvb_get_ntohl(tvb, *plen);
	        proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_PARAM_NUM_ARR_DSC_param_id, tvb, *plen, 4, val);
	        *plen += 4;

	        val = dan_tvb_get_ntohs(tvb, *plen);
	        proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_PARAM_NUM_ARR_DSC_start_index, tvb, *plen, 2, val);
	        *plen += 2;

	        val = dan_tvb_get_ntohs(tvb, *plen);
	        proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_PARAM_NUM_ARR_DSC_num_of_params, tvb, *plen, 2, val);
	        *plen += 2;

	        val = dan_tvb_get_ntohl(tvb, *plen);
	        proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_CFG_PARAM_NUM_ARR_DSC_values, tvb, *plen, 4, val);
	        *plen += 4;

            break;
    }
}

static void
dissect_dan_lte_dan_msg_AIRUL_PRACH_REQ(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32* plen)
{
	proto_tree	    *dan_lte_sdk_msg_data = NULL;
	guint32 		val;


    col_set_str (pinfo->cinfo, COL_INFO, "DAN_AIRUL_PRACH_REQ");

	dan_lte_sdk_msg_data = proto_item_add_subtree(tree, ett_dan_lte_sdk_msg_data);

	val = dan_tvb_get_ntohs(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PRACH_REQ_logical_root_sn, tvb, *plen, 2, val);
	*plen += 2;

	val = tvb_get_guint8(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PRACH_REQ_prach_conf_index, tvb, *plen, 1, val);
	*plen += 1;

	val = tvb_get_guint8(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PRACH_REQ_Ncs, tvb, *plen, 1, val);
	*plen += 1;

	val = tvb_get_guint8(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PRACH_REQ_prach_req_offset, tvb, *plen, 1, val);
	*plen += 1;

	val = tvb_get_guint8(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PRACH_REQ_highSpeedFlag, tvb, *plen, 1, val);
	*plen += 1;

	val = tvb_get_guint8(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PRACH_REQ_prach_format, tvb, *plen, 1, val);
	*plen += 1;

	val = tvb_get_guint8(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PRACH_REQ_thr, tvb, *plen, 1, val);
	*plen += 1;

}

static void
dissect_dan_lte_dan_msg_AIRUL_PRACH_RSP(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32* plen)
{
	proto_item	*ti;
	proto_tree		*dan_lte_sdk_msg_data = NULL;
	proto_tree		*dan_lte_sdk_msg_preambles = NULL;
	guint32 		num_of_preambles;
	guint32 		i;
	guint32 		val;
	gint32 			s_val;

    col_set_str (pinfo->cinfo, COL_INFO, "AIRUL_PRACH_RSP");

	dan_lte_sdk_msg_data = proto_item_add_subtree(tree, ett_dan_lte_sdk_msg_data);

    /* Number of Preambles */
    num_of_preambles = tvb_get_guint8(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PRACH_RSP_num_preambles, tvb, *plen, 1, num_of_preambles);
	*plen += 1;

	val = tvb_get_guint8(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PRACH_RSP_error_indication, tvb, *plen, 1, val);
	*plen += 1;

	val = dan_tvb_get_ntohs(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PRACH_RSP_reserve, tvb, *plen, 2, val);
	*plen += 2;

	/* Loop over Preambles */
	for (i = 0; i < num_of_preambles; i++)
	{
		ti = proto_tree_add_protocol_format(dan_lte_sdk_msg_data, proto_dan_lte_sdk, tvb, (36+i*8), 8,
										  "PRACH_PREAMBLES[%d]", i);
		dan_lte_sdk_msg_preambles = proto_item_add_subtree(ti, ett_dan_lte_sdk_msg_data_subtree1);

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_preambles, hf_dan_lte_sdk_msg_AIRUL_PRACH_RSP_preamble_id, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_preambles, hf_dan_lte_sdk_msg_AIRUL_PRACH_RSP_detection_metric, tvb, *plen, 1, val);
		*plen += 1;

		s_val = dan_tvb_get_ntohs(tvb, *plen);
		proto_tree_add_int(dan_lte_sdk_msg_preambles, hf_dan_lte_sdk_msg_AIRUL_PRACH_RSP_timing_offset, tvb, *plen, 2, s_val);
		*plen += 2;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_preambles, hf_dan_lte_sdk_msg_AIRUL_PRACH_RSP_RTWP, tvb, *plen, 1, val);
		*plen += 1;

		val = dan_tvb_get_ntoh24(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_preambles, hf_dan_lte_sdk_msg_AIRUL_PRACH_RSP_reserve2, tvb, *plen, 3, val);
		*plen += 3;

	}
}

static void
dissect_dan_lte_dan_msg_AIRUL_PUCCH_REQ(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32* plen)
{
	proto_item	*ti;
	proto_tree		*dan_lte_sdk_msg_data = NULL;
	proto_tree		*dan_lte_sdk_msg_req = NULL;
	guint32 		num_of_req;
	guint32 		i;
	guint32 		val;

    col_set_str (pinfo->cinfo, COL_INFO, "AIRUL_PUCCH_REQ");

	dan_lte_sdk_msg_data = proto_item_add_subtree(tree, ett_dan_lte_sdk_msg_data);

    /* Number of Request */
    val = tvb_get_guint8(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_n_rb, tvb, *plen, 1, val);
	*plen += 1;

	val = tvb_get_guint8(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_delta_pucch_shift, tvb, *plen, 1, val);
	*plen += 1;

	val = tvb_get_guint8(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_n_rb_cqi, tvb, *plen, 1, val);
	*plen += 1;

	val = tvb_get_guint8(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_n_cs_an, tvb, *plen, 1, val);
	*plen += 1;

	num_of_req = dan_tvb_get_ntohs(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_n_pucch_req, tvb, *plen, 2, num_of_req);
	*plen += 2;
	
	if(global_dan_lte_sdk_parse_sounding){
		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_srs_present, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_reserve, tvb, *plen, 1, val);
		*plen += 1;
	}else{
		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_reserve, tvb, *plen, 1, val);
		*plen += 1;
		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_reserve, tvb, *plen, 1, val);
		*plen += 1;
	}

	/* Loop over Request */
	for (i = 0; i < num_of_req; i++)
	{
		ti = proto_tree_add_protocol_format(dan_lte_sdk_msg_data, proto_dan_lte_sdk, tvb, (40+i*16), 16,
										  "PUCCH_REQUEST[%d]", i);
		dan_lte_sdk_msg_req = proto_item_add_subtree(ti, ett_dan_lte_sdk_msg_data_subtree1);

		val = dan_tvb_get_ntohs(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_req, hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_rnti, tvb, *plen, 2, val);
		*plen += 2;

		val = dan_tvb_get_ntohs(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_req, hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_n_pucch_sr, tvb, *plen, 2, val);
		*plen += 2;

		val = dan_tvb_get_ntohl(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_req, hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_pucch_format, tvb, *plen, 4, val);
		*plen += 4;

		val = dan_tvb_get_ntohl(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_req, hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_uci_format, tvb, *plen, 4, val);
		*plen += 4;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_req, hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_thr, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_req, hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_dl_harq_chan_id, tvb, *plen, 1, val);
		*plen += 1;

		val = dan_tvb_get_ntohs(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_req, hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_n_pucch_an_cqi, tvb, *plen, 2, val);
		*plen += 2;

		if(global_dan_lte_sdk_PUCCH_parse_cqi_nbits)
		{
            val = tvb_get_guint8(tvb, *plen);
            proto_tree_add_uint(dan_lte_sdk_msg_req, hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_cqi_n_bits, tvb, *plen, 1, val);
            *plen += 1;

    		val = dan_tvb_get_ntoh24(tvb, *plen);
    		proto_tree_add_uint(dan_lte_sdk_msg_req, hf_dan_lte_sdk_msg_AIRUL_PUCCH_REQ_reserve2, tvb, *plen, 3, val);
    		*plen += 3;

		}

	}
}

static void
dissect_dan_lte_dan_msg_AIRUL_PUCCH_EVT(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32* plen)
{
	proto_item	*ti;
	proto_tree		*dan_lte_sdk_msg_data = NULL;
	proto_tree		*dan_lte_sdk_msg_pucch_dsc = NULL;
	guint32 		num_of_ue;
	guint32 		i;
	guint32 		val;
	float           off_val;
	float			un_start_val  = -20   ;
	float			zen_start_val = -130  ;
	float			to_start_val  = -1024 ;
	float			un_del  = (float)(0.2);
	float			c2i_del = (float)(0.5);
	float			zen_del = 1;
	
    col_set_str (pinfo->cinfo, COL_INFO, "AIRUL_PUCCH_EVT");

	dan_lte_sdk_msg_data = proto_item_add_subtree(tree, ett_dan_lte_sdk_msg_data);

    /* Number of UE's */
    num_of_ue = dan_tvb_get_ntohs(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_n_ue, tvb, *plen, 2, num_of_ue);
	*plen += 2;

	val = tvb_get_guint8(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_error_indication, tvb, *plen, 1, val);
	*plen += 1;

	val = tvb_get_guint8(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_reserved, tvb, *plen, 1, val);
	*plen += 1;

	/* Loop over UE's */
	for (i = 0; i < num_of_ue; i++)
	{
		ti = proto_tree_add_protocol_format(dan_lte_sdk_msg_data, proto_dan_lte_sdk, tvb, (36+i*20), 20,
										  "PUCCH IND[%d]", i);
		dan_lte_sdk_msg_pucch_dsc = proto_item_add_subtree(ti, ett_dan_lte_sdk_msg_data_subtree1);

		val = dan_tvb_get_ntohs(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_pucch_dsc, hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_rnti, tvb, *plen, 2, val);
		*plen += 2;

        val = dan_tvb_get_ntohs(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_pucch_dsc, hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_n_pucch_sr, tvb, *plen, 2, val);
		*plen += 2;

		val = dan_tvb_get_ntohl(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_pucch_dsc, hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_SR, tvb, *plen, 4, val);
		*plen += 4;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_pucch_dsc, hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_ack_nack_presence, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_pucch_dsc, hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_ack_nack, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_pucch_dsc, hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_dl_harq_chan_id, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_pucch_dsc, hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_reserved2, tvb, *plen, 1, val);
		*plen += 1;

		val = dan_tvb_get_ntohs(tvb, *plen);
		off_val = api_val_to_lgcl_val(val,zen_start_val,zen_del);		
		proto_tree_add_int(dan_lte_sdk_msg_pucch_dsc, hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_RSSI, tvb, *plen, 2, (gint32)off_val);
		*plen += 2;

		val = dan_tvb_get_ntohs(tvb, *plen);
		off_val = api_val_to_lgcl_val(val,un_start_val,c2i_del);
		proto_tree_add_float(dan_lte_sdk_msg_pucch_dsc, hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_C2I, tvb, *plen, 2, off_val);
		*plen += 2;

		val = dan_tvb_get_ntohs(tvb, *plen);
		off_val = api_val_to_lgcl_val(val,to_start_val,zen_del);
		proto_tree_add_int(dan_lte_sdk_msg_pucch_dsc, hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_STO, tvb, *plen, 2, (gint32)off_val);
		*plen += 2;

		val = dan_tvb_get_ntohs(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_pucch_dsc, hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_n_pucch_an_cqi, tvb, *plen, 2, val);
		*plen += 2;

        val = dan_tvb_get_ntohl(tvb, *plen);
	    proto_tree_add_uint(dan_lte_sdk_msg_pucch_dsc, hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_pucch_format, tvb, *plen, 4, val);
		*plen += 4;

		val = dan_tvb_get_ntohl(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_pucch_dsc, hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_cqi_presence, tvb, *plen, 4, val);
		*plen += 4;

		val = dan_tvb_get_ntohl(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_pucch_dsc, hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_uci_format, tvb, *plen, 4, val);
		*plen += 4;

		val = dan_tvb_get_ntohl(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_pucch_dsc, hf_dan_lte_sdk_msg_AIRUL_PUCCH_EVT_Payload, tvb, *plen, 4, val);
		*plen += 4;


	}
}

static void
dissect_dan_lte_dan_msg_AIRUL_SRS_REQ(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32* plen)
{
	proto_item	*ti;
	proto_tree		*dan_lte_sdk_msg_data = NULL;
	proto_tree		*dan_lte_sdk_msg_srs_dsc = NULL;
	guint32 		num_of_srs;
	guint32 		i;
	guint32 		val;

	float           off_val;
	float           boos_start_val = -3;
	float           boos_del = (float)(0.5);

    col_set_str (pinfo->cinfo, COL_INFO, "AIRUL_SRS_REQ");

	dan_lte_sdk_msg_data = proto_item_add_subtree(tree, ett_dan_lte_sdk_msg_data);

    /* Number of SRS */
    num_of_srs = tvb_get_guint8(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_SRS_REQ_n_srs, tvb, *plen, 1, num_of_srs);
	*plen += 1;

	val = dan_tvb_get_ntoh24(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_SRS_REQ_reserved, tvb, *plen, 3, val);
	*plen += 3;

	/* Loop over SRS-s */
	for (i = 0; i < num_of_srs; i++)
	{
		ti = proto_tree_add_protocol_format(dan_lte_sdk_msg_data, proto_dan_lte_sdk, tvb, (36+i*12), 12,
										  "SRS DSC[%d]", i);
		dan_lte_sdk_msg_srs_dsc = proto_item_add_subtree(ti, ett_dan_lte_sdk_msg_data_subtree1);

		val = dan_tvb_get_ntohs(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_srs_dsc, hf_dan_lte_sdk_msg_SRS_DSC_rnti, tvb, *plen, 2, val);
		*plen += 2;

        val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_srs_dsc, hf_dan_lte_sdk_msg_SRS_DSC_cs_srs, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_srs_dsc, hf_dan_lte_sdk_msg_SRS_DSC_nap, tvb, *plen, 1, val);
		*plen += 1;

		val = dan_tvb_get_ntohs(tvb, *plen);
		off_val = api_val_to_lgcl_val(val,boos_start_val,boos_del);
		proto_tree_add_float(dan_lte_sdk_msg_srs_dsc, hf_dan_lte_sdk_msg_SRS_DSC_boosting, tvb, *plen, 2, off_val);
		*plen += 2;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_srs_dsc, hf_dan_lte_sdk_msg_SRS_DSC_rb_start, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_srs_dsc, hf_dan_lte_sdk_msg_SRS_DSC_b_srs, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_srs_dsc, hf_dan_lte_sdk_msg_SRS_DSC_trans_comb, tvb, *plen, 1, val);
		*plen += 1;

		val = dan_tvb_get_ntoh24(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_srs_dsc, hf_dan_lte_sdk_msg_SRS_DSC_reserved, tvb, *plen, 3, val);
		*plen += 3;
	} // end of for

} // end of dissect_dan_lte_dan_msg_AIRUL_SRS_REQ

static void
dissect_dan_lte_dan_msg_AIRUL_SRS_EVT(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32* plen)
{
	proto_item	*ti;
	proto_tree	*dan_lte_sdk_msg_data = NULL;
	proto_tree	*dan_lte_sdk_msg_srs_dsc = NULL;

	proto_item	*csi;
	proto_tree	*dan_lte_sdk_msg_ch_state = NULL;
	guint32 	num_of_srs;
	guint32 	i;
	guint32		j;
	guint32 	val;
	
	float           off_val;
	float           mag_start_val = -130;
	float           mag_del = (float)(1);
	float           ph_start_val = -179;
	float           ph_del = (float)(2);

    col_set_str (pinfo->cinfo, COL_INFO, "AIRUL_SRS_EVT");

	dan_lte_sdk_msg_data = proto_item_add_subtree(tree, ett_dan_lte_sdk_msg_data);

    /* Number of SRS */
    num_of_srs = tvb_get_guint8(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_SRS_EVT_n_srs, tvb, *plen, 1, num_of_srs);
	*plen += 1;

	val = dan_tvb_get_ntoh24(tvb, *plen);
	proto_tree_add_uint(dan_lte_sdk_msg_data, hf_dan_lte_sdk_msg_AIRUL_SRS_EVT_reserved, tvb, *plen, 3, val);
	*plen += 3;

	/* Loop over SRS-s */
	for (i = 0; i < num_of_srs; i++)
	{
		ti = proto_tree_add_protocol_format(dan_lte_sdk_msg_data, proto_dan_lte_sdk, tvb, (36+i*20), 20,
										  "SRS Decode[%d]", i);
		dan_lte_sdk_msg_srs_dsc = proto_item_add_subtree(ti, ett_dan_lte_sdk_msg_data_subtree1);

		val = dan_tvb_get_ntohs(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_srs_dsc, hf_dan_lte_sdk_msg_SRS_DECODED_DSC_rnti, tvb, *plen, 2, val);
		*plen += 2;

        val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_srs_dsc, hf_dan_lte_sdk_msg_SRS_DECODED_DSC_rbg_indx, tvb, *plen, 1, val);
		*plen += 1;

		val = tvb_get_guint8(tvb, *plen);
		proto_tree_add_uint(dan_lte_sdk_msg_srs_dsc, hf_dan_lte_sdk_msg_SRS_DECODED_DSC_reserved, tvb, *plen, 1, val);
		*plen += 1;
		csi = proto_tree_add_protocol_format(dan_lte_sdk_msg_srs_dsc, proto_dan_lte_sdk, tvb, 40, 8,
											  "Channel Magnitude");
			dan_lte_sdk_msg_ch_state = proto_item_add_subtree(csi, ett_dan_lte_sdk_msg_data_subtree2);

		for (j = 0; j < 4; j++)
		{

			val = dan_tvb_get_ntohs(tvb, *plen);
			off_val = api_val_to_lgcl_val(val,mag_start_val,mag_del);
			proto_tree_add_int(dan_lte_sdk_msg_ch_state, hf_dan_lte_sdk_msg_SRS_DECODED_DSC_ch_state_mag[j], tvb, *plen, 2, (guint)off_val);
			*plen += 2;
		}
		csi = proto_tree_add_protocol_format(dan_lte_sdk_msg_srs_dsc, proto_dan_lte_sdk, tvb, 48, 8,
											  "Channel Phase");
			dan_lte_sdk_msg_ch_state = proto_item_add_subtree(csi, ett_dan_lte_sdk_msg_data_subtree2);

		for (j = 0; j < 4; j++)
		{
			val = dan_tvb_get_ntohs(tvb, *plen);
			off_val = api_val_to_lgcl_val(val,ph_start_val,ph_del);
			proto_tree_add_int(dan_lte_sdk_msg_ch_state, hf_dan_lte_sdk_msg_SRS_DECODED_DSC_ch_state_phase[j], tvb, *plen, 2, (guint)off_val);
			*plen += 2;
		}
	} // end of for every SRS

} // end of dissect_dan_lte_dan_msg_AIRUL_SRS_EVT

static void
dissect_dan_lte_dan_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int msg_type, guint32* plen)
{
    proto_item  *ti;


    /* Specific Message Data Handling */
    ti = proto_tree_add_protocol_format(tree, proto_dan_lte_sdk, tvb, 32, -1,
                                       "Message Data (%s)", (msg_type < array_length(dan_msg_header_string) - 1)?dan_msg_header_string[msg_type].strptr:"Unknown");

    switch (msg_type)
    {
        case DAN_E_AIRDL_PDSCH_REQ:
            dissect_dan_lte_dan_msg_AIRDL_PDSCH_REQ(tvb, pinfo, ti, plen);
            break;
		case DAN_E_AIRDL_PDSCH_DATA_ELMS_REQ:
            dissect_dan_lte_dan_msg_AIRDL_PDSCH_DATA_ELMS_REQ(tvb, pinfo, ti, plen);
            break;
		case DAN_E_AIRDL_PDCCH_REQ:
            dissect_dan_lte_dan_msg_AIRDL_PDCCH_REQ(tvb, pinfo, ti, plen);
            break;
		case DAN_E_TTI_EVT:
            dissect_dan_lte_dan_msg_TTI_EVT(tvb, pinfo, ti, plen);
            break;
		case DAN_E_SYS_START_RSP:
            dissect_dan_lte_dan_msg_SYS_START_RSP(tvb, pinfo, ti, plen);
            break;
		case DAN_E_SYS_INIT_EVT:
		    col_set_str (pinfo->cinfo, COL_INFO, "DAN_SYS_INIT_EVT");
            break;
		case DAN_E_SYS_START_REQ:
		    col_set_str (pinfo->cinfo, COL_INFO, "DAN_START_REQ");
            break;
        case DAN_E_AIRUL_PUSCH_REQ:
            dissect_dan_lte_dan_msg_AIRUL_PUSCH_REQ(tvb, pinfo, ti, plen);
            break;
        case DAN_E_AIRUL_PUSCH_EVT:
            dissect_dan_lte_dan_msg_AIRUL_PUSCH_EVT(tvb, pinfo, ti, plen);
            break;
        case DAN_E_CFG_GET_REQ:
            dissect_dan_lte_dan_msg_CFG_GET_REQ(tvb, pinfo, ti, plen);
            break;
        case DAN_E_CFG_GET_RSP:
            dissect_dan_lte_dan_msg_CFG_GET_RSP(tvb, pinfo, ti, plen);
            break;
        case DAN_E_CFG_SET_REQ:
            dissect_dan_lte_dan_msg_CFG_SET_REQ(tvb, pinfo, ti, plen);
            break;
        case DAN_E_CFG_SET_RSP:
            dissect_dan_lte_dan_msg_CFG_SET_RSP(tvb, pinfo, ti, plen);
            break;
        case DAN_E_AIRUL_PRACH_REQ:
            dissect_dan_lte_dan_msg_AIRUL_PRACH_REQ(tvb, pinfo, ti, plen);
            break;
        case DAN_E_AIRUL_PRACH_RSP:
            dissect_dan_lte_dan_msg_AIRUL_PRACH_RSP(tvb, pinfo, ti, plen);
            break;
        case DAN_E_AIRDL_PUCCH_EVT:
            dissect_dan_lte_dan_msg_AIRUL_PUCCH_EVT(tvb, pinfo, ti, plen);
            break;
        case DAN_E_AIRUL_PUCCH_REQ:
            dissect_dan_lte_dan_msg_AIRUL_PUCCH_REQ(tvb, pinfo, ti, plen);
            break;
        case DAN_E_AIRDL_PHICH_REQ:
            dissect_dan_lte_dan_msg_AIRDL_PHICH_REQ(tvb, pinfo, ti, plen);
            break;
        case DAN_E_AIRUL_PUSCH_CTRL_EVT:
            dissect_dan_lte_dan_msg_AIRUL_PUSCH_CTRL_EVT(tvb, pinfo, ti, plen);
            break;
        case DAN_E_AIRUL_PUSCH_MEAS_EVT:
            dissect_dan_lte_dan_msg_AIRUL_PUSCH_MEAS_EVT(tvb, pinfo, ti, plen);
            break;
		case DAN_E_AIRUL_SRS_REQ:
            dissect_dan_lte_dan_msg_AIRUL_SRS_REQ(tvb, pinfo, ti, plen);
            break;
        case DAN_E_AIRUL_SRS_EVT:
            dissect_dan_lte_dan_msg_AIRUL_SRS_EVT(tvb, pinfo, ti, plen);
            break;
        default:
            proto_item_append_text(ti, " Dissecting message type is not supported");
    }
}

static void
dissect_dan_lte_sdk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *ti;
    proto_tree  *dan_lte_sdk_pi_e_header_tree = NULL;
    proto_tree  *dan_lte_sdk_msg_header_tree = NULL;

	guint32 pi_e_header_type;
	guint16 pi_e_header_seq;
	guint16 pi_e_header_size;
	guint8  pi_e_header_frag;
	guint16 pi_e_header_nf;
	guint8 pi_e_header_nsf;

	guint32 msg_header_seq;
	guint32 msg_header_type;
	guint32 msg_header_ack_req;
	guint16 msg_header_size;
	guint16 msg_header_nf;
	guint8  msg_header_nsf;
	guint8  msg_header_sector_id;
	guint16 msg_header_reserve;


	guint32   len = 0;
	gboolean  save_fragmented;
	guint8   flags;
	int       offset = 0;
	int       frag_offset = 0;
	tvbuff_t* next_tvb = NULL;
	guint16   msg_id = 2;
	gboolean  dan_parse_frag = FALSE;
	guint32   frag_remaining;

	static guint32  patch_seq;
	static guint16  msg_id_gen;
	
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_dan_lte_sdk);
		//col_append_fstr(pinfo->cinfo, COL_PROTOCOL, " %d", proto_get_id_by_filter_name("dan_lte_sdk"));
	/* Clear out stuff in the info column */
	if(check_col(pinfo->cinfo,COL_INFO)){
		col_clear(pinfo->cinfo,COL_INFO);
	}

	/* "Litte" PI-E header parsing */
   	pi_e_header_type = dan_tvb_get_ntohl(tvb, len);
   	len += 4;
   	pi_e_header_seq  = dan_tvb_get_ntohs(tvb, len);
   	len += 2;
   	pi_e_header_size = dan_tvb_get_ntohs(tvb, len);
   	len += 2;
   	pi_e_header_frag = tvb_get_guint8(tvb, len);
   	len += 1;
   	pi_e_header_nsf = tvb_get_guint8(tvb, len);
   	len += 1;
   	pi_e_header_nf = dan_tvb_get_ntohs(tvb, len);
   	len += 2;

    /* Fregmetation Test (Yosi) */
    flags = tvb_get_guint8(tvb, 8);
    //flags = FR_FULL; //for Yoav Testing. Remove
    save_fragmented = pinfo->fragmented;

	if(flags != FR_FULL)
	{
		tvbuff_t* new_tvb = NULL;
		fragment_data *frag_msg = NULL;
		guint16 msg_seq = dan_tvb_get_ntohs(tvb,4);
		guint8 fr_full = FR_FULL;


	    if (flags == FR_FIRST)
		{
			offset          = 0;
			patch_seq       = 0;
			frag_remaining  = pi_e_header_size + len;
			msg_id_gen      = pinfo->fd->abs_ts.nsecs;
			if(tvb->length<100) dan_parse_frag = TRUE; /*parse the FISRT message*/
        }
		else
		{
			offset = len;
			patch_seq++;
			frag_remaining = pi_e_header_size;
        }


        msg_id              = msg_id_gen;
        msg_seq             = patch_seq;
		pinfo->fragmented   = TRUE;

		frag_msg = fragment_add_seq_check(tvb,offset,pinfo,msg_id,dan_fragment_table,
						dan_reassembled_table,msg_seq,frag_remaining/*tvb_length_remaining(tvb,offset)*/,(flags != FR_LAST));

		new_tvb = process_reassembled_data(tvb,offset,pinfo,"Reassembled Message",frag_msg, &dan_frag_items,
					   NULL,tree);

		if(frag_msg)
			col_append_str(pinfo->cinfo, COL_INFO, "Message Reassembled");
		else
			col_append_fstr(pinfo->cinfo, COL_INFO, "Message Fragment %u", msg_seq);

		if (new_tvb)
		{
			next_tvb = new_tvb;
			dan_parse_frag = TRUE;
		}
		else
			next_tvb = tvb;
	}
	else
	{
			//next_tvb = tvb_new_subset(tvb,offset,-1,-1);
			dan_parse_frag = TRUE;
			next_tvb = tvb;
	}

    if (tree)
    {
	        /* we are being asked for details */
    	    /* PI-E Header */
			ti = proto_tree_add_protocol_format(tree, proto_dan_lte_sdk, next_tvb, 0, 12,
                                              "PI-E Header");
            dan_lte_sdk_pi_e_header_tree = proto_item_add_subtree(ti, ett_dan_lte_sdk_pi_e_header);

            proto_tree_add_uint(dan_lte_sdk_pi_e_header_tree, hf_dan_lte_sdk_pi_e_header_type, next_tvb, PROTO_DAN_LTE_SDK_PI_E_HEADER_TYPE_OFF, 4, pi_e_header_type);
            proto_tree_add_uint(dan_lte_sdk_pi_e_header_tree, hf_dan_lte_sdk_pi_e_header_seq,  next_tvb, PROTO_DAN_LTE_SDK_PI_E_HEADER_SEQ_OFF,  2, pi_e_header_seq);
            proto_tree_add_uint(dan_lte_sdk_pi_e_header_tree, hf_dan_lte_sdk_pi_e_header_size, next_tvb, PROTO_DAN_LTE_SDK_PI_E_HEADER_SIZE_OFF, 2, pi_e_header_size);
            proto_tree_add_uint(dan_lte_sdk_pi_e_header_tree, hf_dan_lte_sdk_pi_e_header_frag, next_tvb, PROTO_DAN_LTE_SDK_PI_E_HEADER_FRAG_OFF, 1, pi_e_header_frag);
            proto_tree_add_uint(dan_lte_sdk_pi_e_header_tree, hf_dan_lte_sdk_pi_e_header_nsf,  next_tvb, PROTO_DAN_LTE_SDK_PI_E_HEADER_NSF_OFF,  1, pi_e_header_nsf);
            proto_tree_add_uint(dan_lte_sdk_pi_e_header_tree, hf_dan_lte_sdk_pi_e_header_nf,   next_tvb, PROTO_DAN_LTE_SDK_PI_E_HEADER_NF_OFF,   2, pi_e_header_nf);


            /* DAN Message Header */
			if (dan_parse_frag)
			{
    			ti = proto_tree_add_protocol_format(tree, proto_dan_lte_sdk, next_tvb, frag_offset, 20,
												  "Message Header");
				dan_lte_sdk_msg_header_tree = proto_item_add_subtree(ti, ett_dan_lte_sdk_msg_header);

                /* and some "little" message header parsing */
                msg_header_seq = dan_tvb_get_ntohl(next_tvb, len);
                len += 4;
                msg_header_type = dan_tvb_get_ntohl(next_tvb, len);
                len += 4;
                msg_header_ack_req = dan_tvb_get_ntohl(next_tvb, len);
                len += 4;
                msg_header_size = dan_tvb_get_ntohs(next_tvb, len);
                len += 2;
                msg_header_nf = dan_tvb_get_ntohs(next_tvb, len);
                len += 2;
                msg_header_nsf = tvb_get_guint8(next_tvb, len);
                len += 1;
                msg_header_sector_id= tvb_get_guint8(next_tvb, len);
                len += 1;
                msg_header_reserve= dan_tvb_get_ntohs(next_tvb, len);
                len += 2;

				proto_tree_add_uint(dan_lte_sdk_msg_header_tree, hf_dan_lte_sdk_msg_header_seq, next_tvb, (PROTO_DAN_LTE_SDK_MSG_HEADER_SEQ_OFF - frag_offset),   4, msg_header_seq);
				proto_tree_add_uint(dan_lte_sdk_msg_header_tree, hf_dan_lte_sdk_msg_header_type,  next_tvb, (PROTO_DAN_LTE_SDK_MSG_HEADER_TYPE_OFF - frag_offset),  4, msg_header_type);
				proto_tree_add_uint(dan_lte_sdk_msg_header_tree, hf_dan_lte_sdk_msg_header_ack_req, next_tvb, (PROTO_DAN_LTE_SDK_MSG_HEADER_TYPE_ACK_REQ_OFF - frag_offset), 4, msg_header_ack_req);
				proto_tree_add_uint(dan_lte_sdk_msg_header_tree, hf_dan_lte_sdk_msg_header_size, next_tvb, (PROTO_DAN_LTE_SDK_MSG_HEADER_TYPE_SIZE_OFF - frag_offset), 2, msg_header_size);
				proto_tree_add_uint(dan_lte_sdk_msg_header_tree, hf_dan_lte_sdk_msg_header_nf,  next_tvb, (PROTO_DAN_LTE_SDK_MSG_HEADER_TYPE_NF_OFF - frag_offset),  2, msg_header_nf);
				proto_tree_add_uint(dan_lte_sdk_msg_header_tree, hf_dan_lte_sdk_msg_header_nsf,   next_tvb, (PROTO_DAN_LTE_SDK_MSG_HEADER_TYPE_NSF_OFF - frag_offset),   1, msg_header_nsf);
				proto_tree_add_uint(dan_lte_sdk_msg_header_tree, hf_dan_lte_sdk_msg_header_sector_id,   next_tvb, (PROTO_DAN_LTE_SDK_MSG_HEADER_TYPE_SECTOR_ID_OFF - frag_offset),   1, msg_header_sector_id);
				proto_tree_add_uint(dan_lte_sdk_msg_header_tree, hf_dan_lte_sdk_msg_header_rsrv,   next_tvb, (PROTO_DAN_LTE_SDK_MSG_HEADER_TYPE_RESERVE_OFF - frag_offset),   2, msg_header_reserve);


				/* DAN Message Data */
				dissect_dan_lte_dan_msg(next_tvb, pinfo, tree, msg_header_type, &len);
			}
    }

    pinfo->fragmented = save_fragmented;
}
