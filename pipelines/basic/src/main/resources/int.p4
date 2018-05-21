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
#include <core.p4>
#include <v1model.p4>

#include "include/defines.p4"
#include "include/headers.p4"
#include "include/actions.p4"
#include "include/int_definitions.p4"
#include "include/int_headers.p4"
#include "include/packet_io.p4"
#include "include/port_counters.p4"
#include "include/table0.p4"
#include "include/checksums.p4"
#include "include/int_parser.p4"
#include "include/int_source.p4"
#include "include/int_transit.p4"
#include "include/int_sink.p4"


register<bit<4>>(1) sampling_strategy_reg;
const bit<4> Original_INT = 0x0;
const bit<4> RATE_BASED = 0x1;
const bit<4> EVENT_BASED = 0x2;

register<int<32>>(1) rate_based_counter_reg;
register<int<32>>(1) temp_counter_reg;


control ingress (
    inout headers_t hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata) {

    apply {
        port_counters_ingress.apply(hdr, standard_metadata);
        packetio_ingress.apply(hdr, standard_metadata);
        table0_control.apply(hdr, local_metadata, standard_metadata);
    }
}

/*
control int_source_transit_sink (
    inout headers_t hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata) {
        apply{
        if (standard_metadata.ingress_port != CPU_PORT &&
            standard_metadata.egress_port != CPU_PORT &&
            (hdr.udp.isValid() || hdr.tcp.isValid())) {
            if (local_metadata.int_meta.sink == 0 && local_metadata.int_meta.source == 1) {
                process_int_source.apply(hdr, local_metadata, standard_metadata);
            }
            if(hdr.int_header.isValid()) {
                process_int_transit.apply(hdr, local_metadata, standard_metadata);
                // update underlay header based on INT information inserted
                process_int_outer_encap.apply(hdr, local_metadata, standard_metadata);
                // int sink
                process_int_sink.apply(hdr, local_metadata, standard_metadata);
            }
        }
    }
}*/

control egress (
    inout headers_t hdr,
    inout local_metadata_t local_metadata,
    inout standard_metadata_t standard_metadata) {

    action read_sampling_strategy() {
        sampling_strategy_reg.read(local_metadata.sampling_strategy,32w0);
    }
    action initialize_temp_counter() {
        rate_based_counter_reg.read(local_metadata.temp_counter,32w0);
        temp_counter_reg.write(32w0, local_metadata.temp_counter);
    }
    action read_temp_counter() {
        temp_counter_reg.read(local_metadata.temp_counter,32w0);
    }
    action decrease_temp_counter() {
        local_metadata.temp_counter = local_metadata.temp_counter -1;
        temp_counter_reg.write(32w0, local_metadata.temp_counter);
    }

    apply {
        if (standard_metadata.ingress_port != CPU_PORT &&
            standard_metadata.egress_port != CPU_PORT &&
            (hdr.udp.isValid() || hdr.tcp.isValid())) {
            read_sampling_strategy();
            if (local_metadata.sampling_strategy == Original_INT) {

            } else if (local_metadata.sampling_strategy == RATE_BASED) {
                read_temp_counter();
                if (local_metadata.temp_counter > 0) {
                    local_metadata.int_meta.source = 0;
                    decrease_temp_counter();
                } else if (local_metadata.temp_counter == 0) {
                    initialize_temp_counter();
                }
            } else if (local_metadata.sampling_strategy == EVENT_BASED) {
                local_metadata.event_based_activated = 1;
            }
            process_set_source_sink.apply(hdr, local_metadata, standard_metadata);
            if (local_metadata.int_meta.source == 1) {
                 process_int_source.apply(hdr, local_metadata, standard_metadata);
            }

            if(hdr.int_header.isValid()) {
                process_int_transit.apply(hdr, local_metadata, standard_metadata);
                // update underlay header based on INT information inserted
                process_int_outer_encap.apply(hdr, local_metadata, standard_metadata);
                if (local_metadata.int_meta.sink == 1) {
                    // int sink
                    process_int_sink.apply(hdr, local_metadata, standard_metadata);
                }
            }
        }
        port_counters_egress.apply(hdr, standard_metadata);
        packetio_egress.apply(hdr, standard_metadata);
    }
}

V1Switch(
    int_parser(),
    verify_checksum_control(),
    ingress(),
    egress(),
    compute_checksum_control(),
    int_deparser()
) main;
