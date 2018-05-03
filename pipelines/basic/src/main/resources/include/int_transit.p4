/*
 * Copyright 2017-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* -*- P4_16 -*- */
#ifndef __INT_TRANSIT__
#define __INT_TRANSIT__

const bit<32> FLOW_NUM = 0xFFFFFFFF;

const bit<4> INT = 0x0;
const bit<4> DEVIATION = 0x1;
const bit<4> DEVIATION_MA = 0x2;
const bit<4> SAMPLEVALUE = 0x3;
const bit<4> SAMPLEVALUE_MA = 0x4;

// control function that excecutes distributed sampling for the hop latency
control hop_latency_sampling_deviation (
    inout headers_t hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata) {
        /* Resgister variables for the latest sample values in DS-INT */
        register<bit<32>>(FLOW_NUM) dsint_hop_latency_latest_reg;
        /* Register variable for hop latency sampling threshold in DS-INT */
        register<bit<32>>(1) dsint_hop_latency_threshold_reg;
        action dsint_calculate_flow_hash(){
            hash(
                  local_metadata.flow_hash,
                  HashAlgorithm.crc32,
                  32w0,
                  { hdr.ipv4.src_addr,
                    hdr.ipv4.dst_addr,
                    hdr.ipv4.protocol,
                    local_metadata.l4_src_port,
                    local_metadata.l4_dst_port },
                    FLOW_NUM);
        }

        apply {
            if (hdr.int_hop_latency.isValid()) {
                // invalidate the hop latency inserted by the original INT
                hdr.int_hop_latency.setInvalid();
                // calculate flow identifier
                if (hdr.ipv4.isValid()){
                   dsint_calculate_flow_hash();
                }
                // read the delta value for hop latency
                bit<32> dsint_hop_latency_deviation_threshold;
                dsint_hop_latency_threshold_reg.read(dsint_hop_latency_deviation_threshold,0);

                // read the lastly sampled hop latency value
                bit<32> dsint_hop_latency_latest;
                dsint_hop_latency_latest_reg.read(dsint_hop_latency_latest, (bit<32>)local_metadata.flow_hash);

                // Distributed Sampling
                if ((bit<32>) dsint_hop_latency_latest == 0){
                    hdr.int_hop_latency.setValid();
                    hdr.int_hop_latency.hop_latency = (bit<32>) standard_metadata.deq_timedelta;
                    dsint_hop_latency_latest_reg.write((bit<32>)local_metadata.flow_hash, (bit<32>)hdr.int_hop_latency.hop_latency);
                } else {
                    bit<32> hop_latency_deviation = (bit<32>) standard_metadata.deq_timedelta - dsint_hop_latency_latest;
                    bit<32> mask = hop_latency_deviation >> 31;
                    hop_latency_deviation = (hop_latency_deviation ^ mask) - mask; // absolute value of the latency deviation

                    if (hop_latency_deviation <= dsint_hop_latency_deviation_threshold){
                        // do nothing
                        local_metadata.int_meta.insert_byte_cnt = local_metadata.int_meta.insert_byte_cnt - 4;
                        // set omittence infomration (hop index, metadata type)
                    } else {
                        hdr.int_hop_latency.setValid();
                        hdr.int_hop_latency.hop_latency = (bit<32>) standard_metadata.deq_timedelta;
                        dsint_hop_latency_latest_reg.write(local_metadata.flow_hash, hdr.int_hop_latency.hop_latency);
                    }
                }

            } else {
                // do nothing (instruction bit for hop latency is not set)
            }
        }
}

control hop_latency_sampling_deviation_ma (
    inout headers_t hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata) {
    apply {

    }
}
control hop_latency_sampling_samplevalue (
    inout headers_t hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata) {
    apply {

    }
}

control hop_latency_sampling_samplevalue_ma (
    inout headers_t hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata) {
    apply {

    }
}


control process_int_transit (
    inout headers_t hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata) {

    direct_counter(CounterType.packets_and_bytes) counter_int_insert;
    direct_counter(CounterType.packets_and_bytes) counter_int_inst_0003;
    direct_counter(CounterType.packets_and_bytes) counter_int_inst_0407;
        register<bit<4>>(1) hop_latency_sampling_mode_reg;

    /* Resister variable for DS-INT mode. If set, excecute DS-INT, otherwise, execute original INT. */
//    register<bit<1>>(1) dsint_on;


    action int_update_total_hop_cnt() {
        hdr.int_header.total_hop_cnt = hdr.int_header.total_hop_cnt + 1;
    }

    action int_transit(switch_id_t switch_id) {
        local_metadata.int_meta.switch_id = switch_id;
        local_metadata.int_meta.insert_byte_cnt = (bit<16>) hdr.int_header.ins_cnt << 2;
    }

    /* Instr Bit 0 */
    action int_set_header_0() { //switch_id
        hdr.int_switch_id.setValid();
        hdr.int_switch_id.switch_id = local_metadata.int_meta.switch_id;
    }
    action int_set_header_1() { //port_ids
        hdr.int_port_ids.setValid();
        hdr.int_port_ids.ingress_port_id =
        (bit<16>) standard_metadata.ingress_port;
        hdr.int_port_ids.egress_port_id =
        (bit<16>) standard_metadata.egress_port;
    }

    action int_set_header_2() { // set the hop latency metadata
        hdr.int_hop_latency.setValid();
        hdr.int_hop_latency.hop_latency = (bit<32>) standard_metadata.deq_timedelta;
    }
    action int_set_header_3() { //q_occupancy
        // TODO: Support egress queue ID
        hdr.int_q_occupancy.setValid();
        hdr.int_q_occupancy.q_id =
        0;
        // (bit<8>) standard_metadata.egress_qid;
        hdr.int_q_occupancy.q_occupancy =
        (bit<24>) standard_metadata.deq_qdepth;
    }
    action int_set_header_4() { //ingress_tstamp
        hdr.int_ingress_tstamp.setValid();
        hdr.int_ingress_tstamp.ingress_tstamp =
        (bit<32>) standard_metadata.enq_timestamp;
    }
    action int_set_header_5() { //egress_timestamp
        hdr.int_egress_tstamp.setValid();
        hdr.int_egress_tstamp.egress_tstamp =
        (bit<32>) standard_metadata.enq_timestamp +
        (bit<32>) standard_metadata.deq_timedelta;
    }
    action int_set_header_6() { //q_congestion
        // TODO: implement queue congestion support in BMv2
        // TODO: update egress queue ID
        hdr.int_q_congestion.setValid();
        hdr.int_q_congestion.q_id =
        0;
        // (bit<8>) standard_metadata.egress_qid;
        hdr.int_q_congestion.q_congestion =
        // (bit<24>) queueing_metadata.deq_congestion;
        0;
    }
    action int_set_header_7() { //egress_port_tx_utilization
        // TODO: implement tx utilization support in BMv2
        hdr.int_egress_tx_util.setValid();
        hdr.int_egress_tx_util.egress_port_tx_util =
        // (bit<32>) queueing_metadata.tx_utilization;
        0;
    }

    /* action function for bits 0-3 combinations, 0 is msb, 3 is lsb */
    /* Each bit set indicates that corresponding INT header should be added */
    action int_set_header_0003_i0() {
    }
    action int_set_header_0003_i1() {
        int_set_header_3();
    }
    action int_set_header_0003_i2() {
        int_set_header_2();
    }
    action int_set_header_0003_i3() {
        int_set_header_3();
        int_set_header_2();
    }
    action int_set_header_0003_i4() {
        int_set_header_1();
    }
    action int_set_header_0003_i5() {
        int_set_header_3();
        int_set_header_1();
    }
    action int_set_header_0003_i6() {
        int_set_header_2();
        int_set_header_1();
    }
    action int_set_header_0003_i7() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_1();
    }
    action int_set_header_0003_i8() {
        int_set_header_0();
    }
    action int_set_header_0003_i9() {
        int_set_header_3();
        int_set_header_0();
    }
    action int_set_header_0003_i10() {
        int_set_header_2();
        int_set_header_0();
    }
    action int_set_header_0003_i11() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_0();
    }
    action int_set_header_0003_i12() {
        int_set_header_1();
        int_set_header_0();
    }
    action int_set_header_0003_i13() {
        int_set_header_3();
        int_set_header_1();
        int_set_header_0();
    }
    action int_set_header_0003_i14() {
        int_set_header_2();
        int_set_header_1();
        int_set_header_0();
    }
    action int_set_header_0003_i15() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_1();
        int_set_header_0();
    }

    /* action function for bits 4-7 combinations, 4 is msb, 7 is lsb */
    action int_set_header_0407_i0() {
    }
    action int_set_header_0407_i1() {
        int_set_header_7();
    }
    action int_set_header_0407_i2() {
        int_set_header_6();
    }
    action int_set_header_0407_i3() {
        int_set_header_7();
        int_set_header_6();
    }
    action int_set_header_0407_i4() {
        int_set_header_5();
    }
    action int_set_header_0407_i5() {
        int_set_header_7();
        int_set_header_5();
    }
    action int_set_header_0407_i6() {
        int_set_header_6();
        int_set_header_5();
    }
    action int_set_header_0407_i7() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_5();
    }
    action int_set_header_0407_i8() {
        int_set_header_4();
    }
    action int_set_header_0407_i9() {
        int_set_header_7();
        int_set_header_4();
    }
    action int_set_header_0407_i10() {
        int_set_header_6();
        int_set_header_4();
    }
    action int_set_header_0407_i11() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_4();
    }
    action int_set_header_0407_i12() {
        int_set_header_5();
        int_set_header_4();
    }
    action int_set_header_0407_i13() {
        int_set_header_7();
        int_set_header_5();
        int_set_header_4();
    }
    action int_set_header_0407_i14() {
        int_set_header_6();
        int_set_header_5();
        int_set_header_4();
    }
    action int_set_header_0407_i15() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_5();
        int_set_header_4();
    }

    table tb_int_insert {
        key = {
            local_metadata.int_meta.sink: exact;
        }
        actions = {
            int_transit;
        }
        counters = counter_int_insert;
        size = 2;
    }

    /* Table to process instruction bits 0-3 */
    table tb_int_inst_0003 {
        key = {
            hdr.int_header.instruction_mask_0003 : exact;
        }
        actions = {
            int_set_header_0003_i0;
            int_set_header_0003_i1;
            int_set_header_0003_i2;
            int_set_header_0003_i3;
            int_set_header_0003_i4;
            int_set_header_0003_i5;
            int_set_header_0003_i6;
            int_set_header_0003_i7;
            int_set_header_0003_i8;
            int_set_header_0003_i9;
            int_set_header_0003_i10;
            int_set_header_0003_i11;
            int_set_header_0003_i12;
            int_set_header_0003_i13;
            int_set_header_0003_i14;
            int_set_header_0003_i15;
        }
        counters = counter_int_inst_0003;
        size = 16;
    }

    /* Table to process instruction bits 4-7 */
    table tb_int_inst_0407 {
        key = {
            hdr.int_header.instruction_mask_0407 : exact;
        }
        actions = {
            int_set_header_0407_i0;
            int_set_header_0407_i1;
            int_set_header_0407_i2;
            int_set_header_0407_i3;
            int_set_header_0407_i4;
            int_set_header_0407_i5;
            int_set_header_0407_i6;
            int_set_header_0407_i7;
            int_set_header_0407_i8;
            int_set_header_0407_i9;
            int_set_header_0407_i10;
            int_set_header_0407_i11;
            int_set_header_0407_i12;
            int_set_header_0407_i13;
            int_set_header_0407_i14;
            int_set_header_0407_i15;
        }
        counters = counter_int_inst_0407;
        size = 16;
    }

    apply {
        tb_int_insert.apply();
        tb_int_inst_0003.apply();
        tb_int_inst_0407.apply();
/*      apply select (hop_latency_sampling_mode) {
            INT : hop_latency_sampling_deviation.apply(hdr, local_metadata, standard_metadata);
        }*/
        bit<4> hop_latency_sampling_mode;
        hop_latency_sampling_mode_reg.read(hop_latency_sampling_mode,0);
        
        if (hop_latency_sampling_mode==INT) {
            // original INT
        } else if ((bit<4>) hop_latency_sampling_mode==(bit<4>) DEVIATION) {
            hop_latency_sampling_deviation.apply(hdr, local_metadata, standard_metadata);
        } else if (hop_latency_sampling_mode==DEVIATION_MA) {
            hop_latency_sampling_deviation_ma.apply(hdr, local_metadata, standard_metadata);
        } else if (hop_latency_sampling_mode==SAMPLEVALUE) {
            hop_latency_sampling_samplevalue.apply(hdr, local_metadata, standard_metadata);
        } else if (hop_latency_sampling_mode== SAMPLEVALUE_MA) {
            hop_latency_sampling_samplevalue_ma.apply(hdr, local_metadata, standard_metadata);
        }
        int_update_total_hop_cnt();
    }
}

control process_int_outer_encap (
    inout headers_t hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata) {

    action int_update_ipv4() {
        hdr.ipv4.len = hdr.ipv4.len + local_metadata.int_meta.insert_byte_cnt;
    }
    action int_update_udp() {
        hdr.udp.length_ = hdr.udp.length_ + local_metadata.int_meta.insert_byte_cnt;
    }
    action int_update_shim() {
        hdr.intl4_shim.len = hdr.intl4_shim.len + (bit<8>)hdr.int_header.ins_cnt;
    }

    apply {
        if (hdr.ipv4.isValid()) {
            int_update_ipv4();
        }
        if (hdr.udp.isValid()) {
            int_update_udp();
        }
        if (hdr.intl4_shim.isValid()) {
            int_update_shim();
        }
    }
}

#endif
