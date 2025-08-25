/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// TCP Established Connection Probe Module for Educational/Research Purposes
// Sends TCP packets with configurable flags, options, and payloads

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "../../lib/includes.h"
#include "../fieldset.h"
#include "logger.h"
#include "module_tcp_established.h"
#include "module_tcp_synscan.h"
#include "probe_modules.h"
#include "packet.h"
#include "validate.h"

probe_module_t module_tcp_established;

static uint32_t num_ports;
static char *payload = NULL;
static uint16_t payload_len = 0;

// Configuration parameters
static uint8_t tcp_flags = TH_ACK | TH_PUSH;  // Default: ACK+PSH
static bool use_random_ack = false;            // Default: use validation-based ACK
static uint32_t fixed_ack_num = 0;            // If specified, use this ACK number
static bool use_fixed_ack = false;            // Flag to use fixed ACK
static uint16_t tcp_window = 65535;           // Default: maximum window
static bool use_realistic_window = false;      // Use more realistic window sizes
static bool include_tcp_options = false;       // Include TCP options
static uint8_t tcp_options_data[40];          // Maximum TCP options size
static uint8_t tcp_options_len = 0;           // Actual TCP options length

// Common realistic window sizes
static const uint16_t realistic_windows[] = {
    8192, 14600, 29200, 64240, 65535, 32768, 16384, 24576
};
static const int num_realistic_windows = 8;

// Parse TCP flags from string like "SYN,ACK" or "PSH+ACK" or "RST"
static uint8_t parse_tcp_flags(const char *flags_str)
{
    uint8_t flags = 0;
    char *str_copy = strdup(flags_str);
    char *token;
    char *saveptr;
    
    // Convert to uppercase for easier parsing
    for (char *p = str_copy; *p; p++) {
        *p = toupper(*p);
    }
    
    // Parse tokens separated by comma, plus, or pipe
    token = strtok_r(str_copy, ",+|", &saveptr);
    while (token != NULL) {
        // Remove leading/trailing whitespace
        while (*token == ' ') token++;
        char *end = token + strlen(token) - 1;
        while (end > token && *end == ' ') *end-- = '\0';
        
        if (strcmp(token, "SYN") == 0) {
            flags |= TH_SYN;
        } else if (strcmp(token, "ACK") == 0) {
            flags |= TH_ACK;
        } else if (strcmp(token, "PSH") == 0 || strcmp(token, "PUSH") == 0) {
            flags |= TH_PUSH;
        } else if (strcmp(token, "RST") == 0) {
            flags |= TH_RST;
        } else if (strcmp(token, "FIN") == 0) {
            flags |= TH_FIN;
        } else if (strcmp(token, "URG") == 0) {
            flags |= TH_URG;
        } else {
            log_warn("tcp_established", "Unknown TCP flag: %s", token);
        }
        
        token = strtok_r(NULL, ",+|", &saveptr);
    }
    
    free(str_copy);
    return flags;
}

// Build common TCP options
static void build_tcp_options(void)
{
    tcp_options_len = 0;
    
    if (!include_tcp_options) {
        return;
    }
    
    // MSS option (kind=2, length=4)
    tcp_options_data[tcp_options_len++] = 0x02;  // MSS
    tcp_options_data[tcp_options_len++] = 0x04;  // Length
    tcp_options_data[tcp_options_len++] = 0x05;  // MSS value: 1460
    tcp_options_data[tcp_options_len++] = 0xb4;
    
    // Window Scale option (kind=3, length=3)
    tcp_options_data[tcp_options_len++] = 0x03;  // Window Scale
    tcp_options_data[tcp_options_len++] = 0x03;  // Length
    tcp_options_data[tcp_options_len++] = 0x07;  // Scale factor: 7
    
    // SACK Permitted (kind=4, length=2)
    tcp_options_data[tcp_options_len++] = 0x04;  // SACK Permitted
    tcp_options_data[tcp_options_len++] = 0x02;  // Length
    
    // Timestamps (kind=8, length=10)
    tcp_options_data[tcp_options_len++] = 0x08;  // Timestamps
    tcp_options_data[tcp_options_len++] = 0x0a;  // Length
    // Timestamp value (4 bytes)
    uint32_t ts = (uint32_t)time(NULL);
    tcp_options_data[tcp_options_len++] = (ts >> 24) & 0xFF;
    tcp_options_data[tcp_options_len++] = (ts >> 16) & 0xFF;
    tcp_options_data[tcp_options_len++] = (ts >> 8) & 0xFF;
    tcp_options_data[tcp_options_len++] = ts & 0xFF;
    // Echo reply (4 bytes) - set to 0
    tcp_options_data[tcp_options_len++] = 0x00;
    tcp_options_data[tcp_options_len++] = 0x00;
    tcp_options_data[tcp_options_len++] = 0x00;
    tcp_options_data[tcp_options_len++] = 0x00;
    
    // NOP padding to align to 4-byte boundary
    while (tcp_options_len % 4 != 0) {
        tcp_options_data[tcp_options_len++] = 0x01;  // NOP
    }
}

// Parse probe arguments
static void parse_probe_args(const char *args)
{
    if (!args || strlen(args) == 0) {
        return;
    }
    
    char *args_copy = strdup(args);
    char *token;
    char *saveptr;
    
    token = strtok_r(args_copy, ";", &saveptr);
    while (token != NULL) {
        // Remove leading whitespace
        while (*token == ' ') token++;
        
        if (strncmp(token, "flags=", 6) == 0) {
            tcp_flags = parse_tcp_flags(token + 6);
            log_info("tcp_established", "TCP flags set to: 0x%02x", tcp_flags);
        } else if (strncmp(token, "ack=", 4) == 0) {
            if (strcmp(token + 4, "random") == 0) {
                use_random_ack = true;
                log_info("tcp_established", "Using random ACK numbers");
            } else {
                fixed_ack_num = (uint32_t)strtoul(token + 4, NULL, 0);
                use_fixed_ack = true;
                log_info("tcp_established", "Using fixed ACK number: %u", fixed_ack_num);
            }
        } else if (strncmp(token, "window=", 7) == 0) {
            if (strcmp(token + 7, "realistic") == 0) {
                use_realistic_window = true;
                log_info("tcp_established", "Using realistic window sizes");
            } else {
                tcp_window = (uint16_t)strtoul(token + 7, NULL, 0);
                log_info("tcp_established", "TCP window set to: %u", tcp_window);
            }
        } else if (strncmp(token, "options=", 8) == 0) {
            if (strcmp(token + 8, "yes") == 0 || strcmp(token + 8, "true") == 0 || 
                strcmp(token + 8, "1") == 0) {
                include_tcp_options = true;
                log_info("tcp_established", "Including TCP options");
            }
        } else if (strncmp(token, "payload=", 8) == 0) {
            int processed_len;
            char *processed = tcp_established_process_escape_sequences(token + 8, &processed_len);
            
            if (processed) {
                if (processed_len > ZMAP_TCP_ESTABLISHED_PAYLOAD_MAX_LEN) {
                    log_warn("tcp_established", 
                            "payload length %d exceeds maximum %d, truncating", 
                            processed_len, ZMAP_TCP_ESTABLISHED_PAYLOAD_MAX_LEN);
                    processed_len = ZMAP_TCP_ESTABLISHED_PAYLOAD_MAX_LEN;
                }
                
                if (payload) {
                    free(payload);
                }
                payload = processed;
                payload_len = processed_len;
                log_info("tcp_established", "Payload configured: %d bytes", payload_len);
            }
        } else {
            log_warn("tcp_established", "Unknown parameter: %s", token);
        }
        
        token = strtok_r(NULL, ";", &saveptr);
    }
    
    free(args_copy);
    
    // Special handling for PSH+ACK with random ACK
    if ((tcp_flags == (TH_PUSH | TH_ACK)) && !use_fixed_ack && !use_random_ack) {
        use_random_ack = true;
        log_info("tcp_established", "Auto-enabling random ACK for PSH+ACK packets");
    }
}

// A correct, standard checksum implementation
static inline uint16_t ipv4_checksum(const void* data, size_t len)
{
    const uint16_t* buf = data;
    uint64_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(const uint8_t*)buf;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

static uint16_t tcp_est_checksum(uint16_t tcp_len, uint32_t saddr, uint32_t daddr,
                                 struct tcphdr *tcp_header)
{
    struct {
        uint32_t source_address;
        uint32_t dest_address;
        uint8_t placeholder;
        uint8_t protocol;
        uint16_t tcp_length;
    } pseudo_header;

    pseudo_header.source_address = saddr;
    pseudo_header.dest_address = daddr;
    pseudo_header.placeholder = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_length = htons(tcp_len);

    size_t total_len = sizeof(pseudo_header) + tcp_len;
    char *checksum_buf = malloc(total_len);
    if (!checksum_buf) {
        log_fatal("tcp_established", "Failed to allocate memory for checksum calculation");
        return 0;
    }

    memcpy(checksum_buf, &pseudo_header, sizeof(pseudo_header));
    memcpy(checksum_buf + sizeof(pseudo_header), tcp_header, tcp_len);

    uint16_t checksum = ipv4_checksum(checksum_buf, total_len);
    
    free(checksum_buf);
    return checksum;
}

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
    
    if (tcp_header->th_off > 5) {
        fprintf(fp, "  TCP Options: %d bytes\n", (tcp_header->th_off - 5) * 4);
    }
    
    if (payload_len > 0) {
        fprintf(fp, "  Payload: %d bytes\n", payload_len);
        unsigned char *data = (unsigned char *)tcp_header + (tcp_header->th_off * 4);
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
    
    // Seed random number generator
    srand(time(NULL) ^ getpid());
    
    // Parse probe arguments
    if (state->probe_args && strlen(state->probe_args) > 0) {
        parse_probe_args(state->probe_args);
    } else {
        log_info("tcp_established", 
                "No parameters specified, using defaults: flags=PSH+ACK, window=65535");
    }
    
    // Build TCP options if requested
    if (include_tcp_options) {
        build_tcp_options();
    }
    
    // Calculate maximum packet length
    uint16_t tcp_header_len = sizeof(struct tcphdr) + tcp_options_len;
    module_tcp_established.max_packet_length = 
        sizeof(struct ether_header) + sizeof(struct ip) + tcp_header_len + payload_len;
    
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
    uint16_t tcp_header_len = sizeof(struct tcphdr) + tcp_options_len;
    uint16_t ip_len = sizeof(struct ip) + tcp_header_len + payload_len;
    make_ip_header(ip_header, IPPROTO_TCP, htons(ip_len));
    
    // TCP header
    struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
    make_tcp_header(tcp_header, tcp_flags);
    
    // Set TCP header offset (5 + options in 32-bit words)
    tcp_header->th_off = 5 + (tcp_options_len / 4);
    
    // Set window size
    if (use_realistic_window) {
        tcp_header->th_win = htons(realistic_windows[rand() % num_realistic_windows]);
    } else {
        tcp_header->th_win = htons(tcp_window);
    }
    
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
    //ip_header->ip_off = htons(IP_DF);
    
    uint16_t tcp_header_len = sizeof(struct tcphdr) + tcp_options_len;
    uint16_t ip_len = sizeof(struct ip) + tcp_header_len + payload_len;
    ip_header->ip_len = htons(ip_len);
    
    // Set ports
    uint16_t sport = get_src_port(num_ports, probe_num, validation);
    tcp_header->th_sport = htons(sport);
    tcp_header->th_dport = dport;
    
    // Set sequence number
    tcp_header->th_seq = htonl(validation[0] ^ validation[1]);
    
    // Set ACK number
    if (use_fixed_ack) {
        tcp_header->th_ack = htonl(fixed_ack_num);
    } else if (use_random_ack) {
        tcp_header->th_ack = htonl(rand());
    } else {
        tcp_header->th_ack = htonl(validation[2] ^ validation[3]);
    }
    
    // Set TCP header fields
    tcp_header->th_off = 5 + (tcp_options_len / 4);
    tcp_header->th_flags = tcp_flags;
    
    // Set window
    if (use_realistic_window) {
        tcp_header->th_win = htons(realistic_windows[rand() % num_realistic_windows]);
    } else {
        tcp_header->th_win = htons(tcp_window);
    }
    
    tcp_header->th_urp = 0;
    
    // Add TCP options if configured
    if (tcp_options_len > 0) {
        memcpy((char *)tcp_header + sizeof(struct tcphdr), tcp_options_data, tcp_options_len);
    }
    
    // Add payload if configured
    if (payload && payload_len > 0) {
        memcpy((char *)tcp_header + tcp_header_len, payload, payload_len);
    }
    
    // Calculate TCP checksum
    tcp_header->th_sum = 0;
    uint16_t tcp_seg_len = tcp_header_len + payload_len;
    tcp_header->th_sum = tcp_est_checksum(tcp_seg_len, ip_header->ip_src.s_addr,
                                          ip_header->ip_dst.s_addr, tcp_header);
    
    // Calculate IP checksum
    ip_header->ip_sum = 0;
    ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);
    
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
    
    // Add fields in order
    fs_add_uint64(fs, "sport", (uint64_t)ntohs(tcp->th_sport));
    fs_add_uint64(fs, "dport", (uint64_t)ntohs(tcp->th_dport));
    fs_add_uint64(fs, "seqnum", (uint64_t)ntohl(tcp->th_seq));
    fs_add_uint64(fs, "acknum", (uint64_t)ntohl(tcp->th_ack));
    fs_add_uint64(fs, "window", (uint64_t)ntohs(tcp->th_win));
    fs_add_uint64(fs, "tcp_flags", (uint64_t)tcp->th_flags);
    
    // Determine classification
    const char *classification;
    int success;
    uint32_t data_len = 0;
    
    if (tcp->th_flags & TH_RST) {
        classification = "rst";
        success = 0;
    } else if ((tcp->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
        classification = "synack";
        success = 1;
    } else if (tcp->th_flags & TH_ACK) {
        // Check if response contains data
        uint32_t tcp_hdr_len = tcp->th_off * 4;
        uint32_t ip_hdr_len = ip_hdr->ip_hl * 4;
        uint32_t ip_total_len = ntohs(ip_hdr->ip_len);
        
        if (ip_total_len > (ip_hdr_len + tcp_hdr_len)) {
            data_len = ip_total_len - ip_hdr_len - tcp_hdr_len;
        }
        
        if (data_len > 0) {
            classification = "data";
            success = 1;
        } else {
            classification = "ack";
            success = 1;
        }
    } else if (tcp->th_flags & TH_FIN) {
        classification = "fin";
        success = 0;
    } else {
        classification = "other";
        success = 0;
    }
    
    fs_add_string(fs, "classification", (char *)classification, 0);
    fs_add_bool(fs, "success", success);
    fs_add_uint64(fs, "data_len", (uint64_t)data_len);
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
    .max_packet_length = TCP_ESTABLISHED_PACKET_HEADER_SIZE,
    .pcap_filter = "tcp && tcp[13] != 0",
    .pcap_snaplen = 256,
    .port_args = 1,
    .global_initialize = &tcp_established_global_initialize,
    .prepare_packet = &tcp_established_prepare_packet,
    .make_packet = &tcp_established_make_packet,
    .print_packet = &tcp_established_print_packet,
    .process_packet = &tcp_established_process_packet,
    .validate_packet = &tcp_established_validate_packet,
    .close = &tcp_established_close,
    .helptext = "Probe module that sends TCP packets with configurable flags, options, and payloads.\n"
                "For educational and authorized security research only.\n"
                "Parameters (semicolon-separated in --probe-args):\n"
                "  flags=<FLAGS>     : TCP flags (e.g., 'SYN', 'ACK', 'PSH+ACK', 'RST', 'FIN')\n"
                "                      Default: PSH+ACK\n"
                "  ack=<VALUE>       : ACK number - 'random', or specific number\n"
                "                      Default: validation-based (random for PSH+ACK)\n"
                "  window=<VALUE>    : Window size - number or 'realistic'\n"
                "                      Default: 65535\n"
                "  options=<yes/no>  : Include common TCP options\n"
                "                      Default: no\n"
                "  payload=<STRING>  : Payload with escape sequences (\\r \\n \\t \\x## \\\\ \\0)\n"
                "Example: --probe-args 'flags=PSH+ACK;ack=random;window=realistic;options=yes'",
    .output_type = OUTPUT_TYPE_STATIC,
    .fields = fields,
    .numfields = sizeof(fields) / sizeof(fields[0])
};