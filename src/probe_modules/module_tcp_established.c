/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// TCP Established Connection Probe Module for Educational/Research Purposes
// Sends TCP packets with ACK+PSH flags and custom payloads

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "../../lib/includes.h"
#include "../fieldset.h"
#include "logger.h"
#include "module_tcp_established.h"
#include "module_tcp_synscan.h"  // For synscan_print_packet
#include "probe_modules.h"
#include "packet.h"
#include "validate.h"

probe_module_t module_tcp_established;

static uint32_t num_ports;
static char *payload = NULL;
static uint16_t payload_len = 0;

// Process escape sequences in the payload string
char* tcp_established_process_escape_sequences(const char *input, int *out_len)
{
    if (!input) {
        *out_len = 0;
        return NULL;
    }
    
    int len = strlen(input);
    char *processed = malloc(len + 1);
    if (!processed) {
        log_fatal("tcp_established", "Failed to allocate memory for payload processing");
        return NULL;
    }
    
    int j = 0;
    
    for (int i = 0; i < len; i++) {
        if (input[i] == '\\' && i + 1 < len) {
            switch(input[i + 1]) {
                case 'r':
                    processed[j++] = '\r';
                    i++;
                    break;
                case 'n':
                    processed[j++] = '\n';
                    i++;
                    break;
                case 't':
                    processed[j++] = '\t';
                    i++;
                    break;
                case 'x': // Hex escape sequence \xHH
                    if (i + 3 < len) {
                        char hex[3] = {input[i + 2], input[i + 3], '\0'};
                        char *endptr;
                        long val = strtol(hex, &endptr, 16);
                        if (*endptr == '\0') {
                            processed[j++] = (char)val;
                            i += 3;
                        } else {
                            processed[j++] = input[i];
                        }
                    } else {
                        processed[j++] = input[i];
                    }
                    break;
                case '\\':
                    processed[j++] = '\\';
                    i++;
                    break;
                case '0': // Null byte
                    processed[j++] = '\0';
                    i++;
                    break;
                default:
                    processed[j++] = input[i];
                    break;
            }
        } else {
            processed[j++] = input[i];
        }
    }
    
    processed[j] = '\0';
    *out_len = j;
    return processed;
}

void tcp_established_print_packet(FILE *fp, void *packet)
{
    struct ether_header *eth_header = (struct ether_header *)packet;
    struct ip *ip_header = (struct ip *)(&eth_header[1]);
    struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
    
    fprintf(fp, "TCP Established Packet:\n");
    fprintf(fp, "  Eth: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
            eth_header->ether_shost[0], eth_header->ether_shost[1],
            eth_header->ether_shost[2], eth_header->ether_shost[3],
            eth_header->ether_shost[4], eth_header->ether_shost[5],
            eth_header->ether_dhost[0], eth_header->ether_dhost[1],
            eth_header->ether_dhost[2], eth_header->ether_dhost[3],
            eth_header->ether_dhost[4], eth_header->ether_dhost[5]);
    
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_header->ip_src, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_header->ip_dst, dst_ip, INET_ADDRSTRLEN);
    
    fprintf(fp, "  IP: %s:%u -> %s:%u\n",
            src_ip, ntohs(tcp_header->th_sport),
            dst_ip, ntohs(tcp_header->th_dport));
    
    fprintf(fp, "  TCP Flags: ");
    if (tcp_header->th_flags & TH_FIN) fprintf(fp, "FIN ");
    if (tcp_header->th_flags & TH_SYN) fprintf(fp, "SYN ");
    if (tcp_header->th_flags & TH_RST) fprintf(fp, "RST ");
    if (tcp_header->th_flags & TH_PUSH) fprintf(fp, "PSH ");
    if (tcp_header->th_flags & TH_ACK) fprintf(fp, "ACK ");
    if (tcp_header->th_flags & TH_URG) fprintf(fp, "URG ");
    fprintf(fp, "\n");
    
    fprintf(fp, "  Seq: %u, Ack: %u, Win: %u\n",
            ntohl(tcp_header->th_seq),
            ntohl(tcp_header->th_ack),
            ntohs(tcp_header->th_win));
    
    if (payload_len > 0) {
        fprintf(fp, "  Payload: %d bytes\n", payload_len);
        // Print first 32 bytes of payload
        unsigned char *data = (unsigned char *)tcp_header + sizeof(struct tcphdr);
        fprintf(fp, "  Data: ");
        for (int i = 0; i < payload_len && i < 32; i++) {
            if (data[i] >= 32 && data[i] < 127) {
                fprintf(fp, "%c", data[i]);
            } else {
                fprintf(fp, "\\x%02x", data[i]);
            }
        }
        if (payload_len > 32) fprintf(fp, "...");
        fprintf(fp, "\n");
    }
}

static int tcp_established_global_initialize(struct state_conf *state)
{
    num_ports = state->source_port_last - state->source_port_first + 1;
    
    // Process probe arguments for payload
    if (state->probe_args && strlen(state->probe_args) > 0) {
        int processed_len;
        char *processed = tcp_established_process_escape_sequences(state->probe_args, &processed_len);
        
        if (!processed) {
            log_fatal("tcp_established", "Failed to process payload");
            return EXIT_FAILURE;
        }
        
        if (processed_len > ZMAP_TCP_ESTABLISHED_PAYLOAD_MAX_LEN) {
            log_fatal("tcp_established", 
                     "payload length %d exceeds maximum %d", 
                     processed_len, ZMAP_TCP_ESTABLISHED_PAYLOAD_MAX_LEN);
            free(processed);
            return EXIT_FAILURE;
        }
        
        payload = processed;
        payload_len = processed_len;
        
        log_info("tcp_established", 
                "payload configured: %d bytes", payload_len);
        
        // Update module packet length
        module_tcp_established.max_packet_length = TCP_ESTABLISHED_PACKET_HEADER_SIZE + payload_len;
    } else {
        log_info("tcp_established", 
                "no payload specified, sending empty ACK+PSH packets");
        module_tcp_established.max_packet_length = TCP_ESTABLISHED_PACKET_HEADER_SIZE;
    }
    
    return EXIT_SUCCESS;
}

static int tcp_established_prepare_packet(void *buf, macaddr_t *src, macaddr_t *gw,
                                         UNUSED void *arg_ptr)
{
    memset(buf, 0, MAX_PACKET_SIZE);
    
    // Ethernet header
    struct ether_header *eth_header = (struct ether_header *)buf;
    make_eth_header(eth_header, src, gw);
    
    // IP header
    struct ip *ip_header = (struct ip *)(&eth_header[1]);
    uint16_t ip_len = sizeof(struct ip) + sizeof(struct tcphdr) + payload_len;
    make_ip_header(ip_header, IPPROTO_TCP, htons(ip_len));
    
    // TCP header - use ACK+PSH flags
    struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
    make_tcp_header(tcp_header, TH_ACK | TH_PUSH);
    
    // Set TCP header fields
    tcp_header->th_off = 5;  // 5 * 4 = 20 bytes (no options)
    tcp_header->th_win = htons(65535);  // Maximum window size
    
    return EXIT_SUCCESS;
}

static int tcp_established_make_packet(void *buf, size_t *buf_len,
                                      ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
                                      port_n_t dport, uint8_t ttl,
                                      uint32_t *validation, int probe_num,
                                      uint16_t ip_id, UNUSED void *arg)
{
    struct ether_header *eth_header = (struct ether_header *)buf;
    struct ip *ip_header = (struct ip *)(&eth_header[1]);
    struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
    
    // Update IP header
    ip_header->ip_src.s_addr = src_ip;
    ip_header->ip_dst.s_addr = dst_ip;
    ip_header->ip_ttl = ttl;
    ip_header->ip_id = htons(ip_id);
    
    uint16_t ip_len = sizeof(struct ip) + sizeof(struct tcphdr) + payload_len;
    ip_header->ip_len = htons(ip_len);
    
    // Configure TCP header
    uint16_t sport = get_src_port(num_ports, probe_num, validation);
    tcp_header->th_sport = htons(sport);
    tcp_header->th_dport = dport;
    
    // Generate pseudo-random sequence and ack numbers using validation array
    tcp_header->th_seq = htonl(validation[0] ^ validation[1]);
    tcp_header->th_ack = htonl(validation[2] ^ validation[3]);
    
    // Set TCP flags and window
    tcp_header->th_off = 5;  // 5 * 4 = 20 bytes (no options)
    tcp_header->th_flags = TH_ACK | TH_PUSH;  // ACK + PSH for data transfer
    tcp_header->th_win = htons(65535);
    tcp_header->th_urp = 0;
    
    // Copy payload if present
    if (payload && payload_len > 0) {
        memcpy((char *)tcp_header + sizeof(struct tcphdr), payload, payload_len);
    }
    
    // Calculate TCP checksum
    tcp_header->th_sum = 0;
    tcp_header->th_sum = tcp_checksum(sizeof(struct tcphdr) + payload_len,
                                      ip_header->ip_src.s_addr,
                                      ip_header->ip_dst.s_addr, 
                                      tcp_header);
    
    // Calculate IP checksum (use zmap_ip_checksum which is the correct function)
    ip_header->ip_sum = 0;
    ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);
    
    // Set actual packet length
    *buf_len = sizeof(struct ether_header) + ntohs(ip_header->ip_len);
    
    return EXIT_SUCCESS;
}

static int tcp_established_validate_packet(const struct ip *ip_hdr, uint32_t len,
                                          uint32_t *src_ip, uint32_t *validation,
                                          const struct port_conf *ports)
{
    // Must be TCP
    if (ip_hdr->ip_p != IPPROTO_TCP) {
        return 0;
    }
    
    // Check packet length
    if ((4 * ip_hdr->ip_hl + sizeof(struct tcphdr)) > len) {
        return 0;
    }
    
    struct tcphdr *tcp = (struct tcphdr *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);
    
    // Validate source port (should match our target port)
    // Use ports->port_count to determine the target port
    uint16_t sport = ntohs(tcp->th_sport);
    
    // For single port scans, validate against the specified port
    // For multi-port scans, this would need more complex validation
    
    // Validate destination port (should match our source port)
    if (!check_dst_port(ntohs(tcp->th_dport), num_ports, validation)) {
        return 0;
    }
    
    // Store source IP
    *src_ip = ip_hdr->ip_src.s_addr;
    
    return 1;
}

static void tcp_established_process_packet(const u_char *packet,
                                          UNUSED uint32_t len,
                                          fieldset_t *fs,
                                          UNUSED uint32_t *validation,
                                          struct timespec ts)
{
    struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
    struct tcphdr *tcp = (struct tcphdr *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);
    
    // Add basic TCP fields
    fs_add_uint64(fs, "sport", (uint64_t)ntohs(tcp->th_sport));
    fs_add_uint64(fs, "dport", (uint64_t)ntohs(tcp->th_dport));
    fs_add_uint64(fs, "seqnum", (uint64_t)ntohl(tcp->th_seq));
    fs_add_uint64(fs, "acknum", (uint64_t)ntohl(tcp->th_ack));
    fs_add_uint64(fs, "window", (uint64_t)ntohs(tcp->th_win));
    
    // Classify response based on TCP flags
    if (tcp->th_flags & TH_RST) {
        // RST means port is closed or connection rejected
        fs_add_string(fs, "classification", (char *)"rst", 0);
        fs_add_bool(fs, "success", 0);
    } else if ((tcp->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
        // SYN-ACK shouldn't happen for established packets, but indicates open port
        fs_add_string(fs, "classification", (char *)"synack", 0);
        fs_add_bool(fs, "success", 1);
    } else if (tcp->th_flags & TH_ACK) {
        // Check if response contains data
        uint32_t tcp_hdr_len = tcp->th_off * 4;
        uint32_t ip_hdr_len = ip_hdr->ip_hl * 4;
        uint32_t ip_total_len = ntohs(ip_hdr->ip_len);
        uint32_t data_len = 0;
        
        if (ip_total_len > (ip_hdr_len + tcp_hdr_len)) {
            data_len = ip_total_len - ip_hdr_len - tcp_hdr_len;
        }
        
        if (data_len > 0) {
            // Received data in response
            fs_add_string(fs, "classification", (char *)"data", 0);
            fs_add_bool(fs, "success", 1);
            fs_add_uint64(fs, "data_len", (uint64_t)data_len);
        } else {
            // Just ACK, no data
            fs_add_string(fs, "classification", (char *)"ack", 0);
            fs_add_bool(fs, "success", 1);
            fs_add_uint64(fs, "data_len", 0);
        }
    } else if (tcp->th_flags & TH_FIN) {
        // FIN flag - connection termination
        fs_add_string(fs, "classification", (char *)"fin", 0);
        fs_add_bool(fs, "success", 0);
        fs_add_uint64(fs, "data_len", 0);
    } else {
        // Other response
        fs_add_string(fs, "classification", (char *)"other", 0);
        fs_add_bool(fs, "success", 0);
        fs_add_uint64(fs, "data_len", 0);
    }
    
    // Add TCP flags as integer
    fs_add_uint64(fs, "tcp_flags", (uint64_t)tcp->th_flags);
    
    // Add timestamp
    fs_add_uint64(fs, "timestamp_ts", (uint64_t)ts.tv_sec);
    fs_add_uint64(fs, "timestamp_us", (uint64_t)ts.tv_nsec / 1000);
}

static int tcp_established_close(UNUSED struct state_conf *zconf, 
                                UNUSED struct state_send *zsend,
                                UNUSED struct state_recv *zrecv)
{
    if (payload) {
        free(payload);
        payload = NULL;
        payload_len = 0;
    }
    return EXIT_SUCCESS;
}

static fielddef_t fields[] = {
    {.name = "sport", .type = "int", .desc = "TCP source port"},
    {.name = "dport", .type = "int", .desc = "TCP destination port"},
    {.name = "seqnum", .type = "int", .desc = "TCP sequence number"},
    {.name = "acknum", .type = "int", .desc = "TCP acknowledgement number"},
    {.name = "window", .type = "int", .desc = "TCP window size"},
    {.name = "tcp_flags", .type = "int", .desc = "TCP flags value"},
    {.name = "classification", .type = "string", .desc = "packet classification"},
    {.name = "success", .type = "bool", .desc = "is response considered success"},
    {.name = "data_len", .type = "int", .desc = "response data length"},
    {.name = "timestamp_ts", .type = "int", .desc = "timestamp seconds"},
    {.name = "timestamp_us", .type = "int", .desc = "timestamp microseconds"}
};

probe_module_t module_tcp_established = {
    .name = "tcp_established",
    .max_packet_length = TCP_ESTABLISHED_PACKET_HEADER_SIZE,  // Updated dynamically in init
    .pcap_filter = "tcp && tcp[13] != 0",  // Any TCP flags
    .pcap_snaplen = 256,  // Capture more for potential response data
    .port_args = 1,
    .global_initialize = &tcp_established_global_initialize,
    .prepare_packet = &tcp_established_prepare_packet,
    .make_packet = &tcp_established_make_packet,
    .print_packet = &tcp_established_print_packet,  // Use our custom print function
    .process_packet = &tcp_established_process_packet,
    .validate_packet = &tcp_established_validate_packet,
    .close = &tcp_established_close,
    .helptext = "Probe module that sends TCP ACK+PSH packets with optional payload "
                "to simulate established connection traffic. For educational and "
                "authorized security research only. Payload specified with --probe-args. "
                "Supports escape sequences: \\r \\n \\t \\x## \\\\ \\0",
    .output_type = OUTPUT_TYPE_STATIC,
    .fields = fields,
    .numfields = sizeof(fields) / sizeof(fields[0])
};