/*
 * ZMap Copyright 2023 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for performing TCP custom scans with configurable flags and payload

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#include "../../lib/includes.h"
#include "../fieldset.h"
#include "logger.h"
#include "probe_modules.h"
#include "packet.h"
#include "validate.h"
#include "module_tcp_synscan.h"

// defaults
static uint16_t tcp_header_len = 20; // Default TCP header length
static bool should_validate_src_port = true; // default to validating source port
static uint16_t num_source_ports;

// Define missing TCP flags if not defined in the system headers
#ifndef TH_ECE
#define TH_ECE 0x40
#endif

#ifndef TH_CWR
#define TH_CWR 0x80
#endif

// Custom TCP flags and payload settings
static uint8_t tcp_flags = 0;
static char *custom_payload = NULL;
static size_t payload_len = 0;
static bool random_acks = false;
static uint16_t tcp_window = 65535; // Default max window size

// Forward declarations
static int custom_global_initialize(struct state_conf *state);
static int custom_prepare_packet(void *buf, macaddr_t *src, macaddr_t *gw, UNUSED void *arg_ptr);
static int custom_make_packet(void *buf, size_t *buf_len, ipaddr_n_t src_ip, ipaddr_n_t dst_ip, 
                            port_n_t dport, uint8_t ttl, uint32_t *validation, int probe_num, 
                            uint16_t ip_id, UNUSED void *arg);
static int custom_validate_packet(const struct ip *ip_hdr, uint32_t len, uint32_t *src_ip, 
                                uint32_t *validation, const struct port_conf *ports);
static void custom_process_packet(const u_char *packet, UNUSED uint32_t len, fieldset_t *fs, 
                                UNUSED uint32_t *validation, UNUSED struct timespec ts);

// Module definition
probe_module_t module_tcp_custom;

// Function to parse escape sequences in payload
static char *parse_escapes(const char *input, size_t *output_len) 
{
    if (!input) {
        *output_len = 0;
        return NULL;
    }

    size_t input_len = strlen(input);
    char *output = malloc(input_len + 1); // Output will be at most as long as input
    if (!output) {
        log_fatal("tcp_custom", "Failed to allocate memory for payload");
        return NULL;
    }

    size_t i = 0, j = 0;
    while (i < input_len) {
        if (input[i] == '\\' && i + 1 < input_len) {
            switch (input[i + 1]) {
                case 'r':
                    output[j++] = '\r';
                    i += 2;
                    break;
                case 'n':
                    output[j++] = '\n';
                    i += 2;
                    break;
                case 't':
                    output[j++] = '\t';
                    i += 2;
                    break;
                case '\\':
                    output[j++] = '\\';
                    i += 2;
                    break;
                case 'x': // Handle hex sequences \xHH
                    if (i + 3 < input_len && isxdigit(input[i + 2]) && isxdigit(input[i + 3])) {
                        char hex[3] = {input[i + 2], input[i + 3], '\0'};
                        output[j++] = (char)strtol(hex, NULL, 16);
                        i += 4;
                    } else {
                        output[j++] = 'x'; // Invalid hex sequence, just output 'x'
                        i += 2;
                    }
                    break;
                default:
                    output[j++] = input[i + 1];
                    i += 2;
                    break;
            }
        } else {
            output[j++] = input[i++];
        }
    }

    output[j] = '\0';
    *output_len = j;
    return output;
}

// Parse TCP flags from string
static uint8_t parse_tcp_flags(const char *flags_str) 
{
    if (!flags_str || !*flags_str) {
        return 0;
    }

    uint8_t flags = 0;
    char *flags_copy = strdup(flags_str);
    char *token = strtok(flags_copy, "+");

    while (token) {
        if (strcasecmp(token, "FIN") == 0) {
            flags |= TH_FIN;
        } else if (strcasecmp(token, "SYN") == 0) {
            flags |= TH_SYN;
        } else if (strcasecmp(token, "RST") == 0) {
            flags |= TH_RST;
        } else if (strcasecmp(token, "PSH") == 0) {
            flags |= TH_PUSH;
        } else if (strcasecmp(token, "ACK") == 0) {
            flags |= TH_ACK;
        } else if (strcasecmp(token, "URG") == 0) {
            flags |= TH_URG;
        } else if (strcasecmp(token, "ECE") == 0) {
            flags |= TH_ECE;
        } else if (strcasecmp(token, "CWR") == 0) {
            flags |= TH_CWR;
        } else {
            log_warn("tcp_custom", "Unknown TCP flag: %s", token);
        }
        token = strtok(NULL, "+");
    }

    free(flags_copy);
    return flags;
}

// Parse arguments
static int parse_args(const char *args) 
{
    if (!args) {
        return EXIT_SUCCESS; // No args, use defaults
    }

    char *args_copy = strdup(args);
    char *arg = strtok(args_copy, ";");

    while (arg) {
        char *key = strtok(arg, "=");
        char *value = strtok(NULL, "");

        if (!key || !value) {
            log_warn("tcp_custom", "Invalid argument format: %s", arg);
            arg = strtok(NULL, ";");
            continue;
        }

        if (strcmp(key, "flags") == 0) {
            tcp_flags = parse_tcp_flags(value);
            log_debug("tcp_custom", "Set TCP flags: 0x%02x", tcp_flags);
        } else if (strcmp(key, "payload") == 0) {
            free(custom_payload); // Free any existing payload
            custom_payload = parse_escapes(value, &payload_len);
            log_debug("tcp_custom", "Set payload of length %zu", payload_len);
        } else if (strcmp(key, "random_acks") == 0) {
            if (strcmp(value, "true") == 0 || strcmp(value, "1") == 0) {
                random_acks = true;
                log_debug("tcp_custom", "Enabled random ACKs");
            } else {
                random_acks = false;
                log_debug("tcp_custom", "Disabled random ACKs");
            }
        } else if (strcmp(key, "window") == 0) {
            tcp_window = (uint16_t)atoi(value);
            log_debug("tcp_custom", "Set TCP window: %u", tcp_window);
        } else {
            log_warn("tcp_custom", "Unknown argument: %s", key);
        }

        arg = strtok(NULL, ";");
    }

    free(args_copy);
    return EXIT_SUCCESS;
}

static int custom_global_initialize(struct state_conf *state)
{
    num_source_ports = state->source_port_last - state->source_port_first + 1;
    
    if (state->validate_source_port_override == VALIDATE_SRC_PORT_DISABLE_OVERRIDE) {
        log_debug("tcp_custom", "disabling source port validation");
        should_validate_src_port = false;
    }

    // Parse probe args if present
    if (state->probe_args) {
        log_debug("tcp_custom", "Parsing probe args: %s", state->probe_args);
        parse_args(state->probe_args);
    }

    // Calculate total packet length based on payload
    size_t total_len = sizeof(struct ether_header) + sizeof(struct ip) + tcp_header_len;
    if (custom_payload) {
        total_len += payload_len;
    }
    
    module_tcp_custom.max_packet_length = total_len;
    log_debug("tcp_custom", "Max packet length set to: %zu", total_len);

    return EXIT_SUCCESS;
}

static int custom_prepare_packet(void *buf, macaddr_t *src, macaddr_t *gw, UNUSED void *arg_ptr)
{
    memset(buf, 0, MAX_PACKET_SIZE);
    
    // Ethernet header
    struct ether_header *eth_header = (struct ether_header *)buf;
    make_eth_header(eth_header, src, gw);
    
    // IP header
    struct ip *ip_header = (struct ip *)(&eth_header[1]);
    uint16_t ip_len = htons(sizeof(struct ip) + tcp_header_len + payload_len);
    make_ip_header(ip_header, IPPROTO_TCP, ip_len);
    
    // Set DF flag on IP header
    ip_header->ip_off |= htons(IP_DF);
    
    // TCP header
    struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
    tcp_header->th_off = tcp_header_len / 4; // Header length in 32-bit words
    tcp_header->th_win = htons(tcp_window);
    
    // Set user-defined flags or leave them all at 0
    tcp_header->th_flags = tcp_flags;
    
    return EXIT_SUCCESS;
}

static int custom_make_packet(void *buf, size_t *buf_len, ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
                            port_n_t dport, uint8_t ttl, uint32_t *validation, int probe_num,
                            uint16_t ip_id, UNUSED void *arg)
{
    struct ether_header *eth_header = (struct ether_header *)buf;
    struct ip *ip_header = (struct ip *)(&eth_header[1]);
    struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
    
    // Set IP header fields
    ip_header->ip_src.s_addr = src_ip;
    ip_header->ip_dst.s_addr = dst_ip;
    ip_header->ip_ttl = ttl;
    ip_header->ip_id = ip_id;
    
    // Set TCP header fields
    port_h_t sport = get_src_port(num_source_ports, probe_num, validation);
    tcp_header->th_sport = htons(sport);
    tcp_header->th_dport = dport;
    
    // Set sequence number from validation
    tcp_header->th_seq = validation[0];
    
    // Set ACK number
    if (tcp_flags & TH_ACK) {
        if (random_acks) {
            // Generate a random ACK number if random_acks is enabled
            uint32_t ack = validation[1]; // Use a different validation field for randomness
            tcp_header->th_ack = ack;
        } else {
            // Default ACK is 0
            tcp_header->th_ack = 0;
        }
    } else {
        tcp_header->th_ack = 0;
    }
    
    // Add payload if it exists
    if (custom_payload && payload_len > 0) {
        char *payload_ptr = (char *)tcp_header + tcp_header_len;
        memcpy(payload_ptr, custom_payload, payload_len);
    }
    
    // Calculate TCP checksum
    tcp_header->th_sum = 0;
    size_t tcp_total_len = tcp_header_len + payload_len;
    tcp_header->th_sum = tcp_checksum(tcp_total_len, ip_header->ip_src.s_addr,
                                      ip_header->ip_dst.s_addr, tcp_header);
    
    // Calculate IP checksum
    ip_header->ip_sum = 0;
    ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);
    
    // Set total packet length
    *buf_len = sizeof(struct ether_header) + sizeof(struct ip) + tcp_header_len + payload_len;
    
    return EXIT_SUCCESS;
}

static int custom_validate_packet(const struct ip *ip_hdr, uint32_t len, uint32_t *src_ip,
                                uint32_t *validation, const struct port_conf *ports)
{
    // TCP packet validation logic
    if (ip_hdr->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp = get_tcp_header(ip_hdr, len);
        if (!tcp) {
            return PACKET_INVALID;
        }
        
        port_h_t sport = ntohs(tcp->th_sport);
        port_h_t dport = ntohs(tcp->th_dport);
        
        // validate source port
        if (should_validate_src_port && !check_src_port(sport, ports)) {
            return PACKET_INVALID;
        }
        
        // validate destination port
        if (!check_dst_port(dport, num_source_ports, validation)) {
            return PACKET_INVALID;
        }
        
        // check whether we'll ever send to this IP during the scan
        if (!blocklist_is_allowed(*src_ip)) {
            return PACKET_INVALID;
        }
        
        // Validate response based on sent flags
        if (tcp_flags & TH_SYN) {
            // For SYN packets, we expect SYN-ACK or RST
            if (tcp->th_flags & TH_RST) {
                // RST packet is valid
                if (!(htonl(tcp->th_ack) == htonl(validation[0]) + 1)) {
                    return PACKET_INVALID;
                }
            } else if ((tcp->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
                // SYN-ACK packet is valid
                if (htonl(tcp->th_ack) != htonl(validation[0]) + 1) {
                    return PACKET_INVALID;
                }
            } else {
                // Unexpected flags
                return PACKET_INVALID;
            }
        } else {
            // For other packets, just check if it's a response to our probe
            // This is a very basic validation that can be enhanced based on needs
            return PACKET_VALID;
        }
    } else if (ip_hdr->ip_p == IPPROTO_ICMP) {
        // ICMP packet validation (e.g., port unreachable)
        struct ip *ip_inner;
        size_t ip_inner_len;
        if (icmp_helper_validate(ip_hdr, len, sizeof(struct tcphdr),
                                &ip_inner, &ip_inner_len) == PACKET_INVALID) {
            return PACKET_INVALID;
        }
        
        struct tcphdr *tcp = get_tcp_header(ip_inner, ip_inner_len);
        if (!tcp) {
            return PACKET_INVALID;
        }
        
        // we can check the destination port because this is the original packet
        port_h_t sport = ntohs(tcp->th_sport);
        port_h_t dport = ntohs(tcp->th_dport);
        
        if (!check_src_port(dport, ports)) {
            return PACKET_INVALID;
        }
        
        validate_gen(ip_hdr->ip_dst.s_addr, ip_inner->ip_dst.s_addr,
                    tcp->th_dport, (uint8_t *)validation);
        
        if (!check_dst_port(sport, num_source_ports, validation)) {
            return PACKET_INVALID;
        }
    } else {
        return PACKET_INVALID;
    }
    
    return PACKET_VALID;
}

static void custom_process_packet(const u_char *packet, UNUSED uint32_t len, fieldset_t *fs,
                                UNUSED uint32_t *validation, UNUSED struct timespec ts)
{
    struct ip *ip_hdr = get_ip_header(packet, len);
    
    if (ip_hdr->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp = get_tcp_header(ip_hdr, len);
        
        fs_add_uint64(fs, "sport", (uint64_t)ntohs(tcp->th_sport));
        fs_add_uint64(fs, "dport", (uint64_t)ntohs(tcp->th_dport));
        fs_add_uint64(fs, "seqnum", (uint64_t)ntohl(tcp->th_seq));
        fs_add_uint64(fs, "acknum", (uint64_t)ntohl(tcp->th_ack));
        fs_add_uint64(fs, "window", (uint64_t)ntohs(tcp->th_win));
        
        // Extract all TCP flags
        fs_add_bool(fs, "flag_fin", tcp->th_flags & TH_FIN);
        fs_add_bool(fs, "flag_syn", tcp->th_flags & TH_SYN);
        fs_add_bool(fs, "flag_rst", tcp->th_flags & TH_RST);
        fs_add_bool(fs, "flag_psh", tcp->th_flags & TH_PUSH);
        fs_add_bool(fs, "flag_ack", tcp->th_flags & TH_ACK);
        fs_add_bool(fs, "flag_urg", tcp->th_flags & TH_URG);
        fs_add_bool(fs, "flag_ece", tcp->th_flags & TH_ECE);
        fs_add_bool(fs, "flag_cwr", tcp->th_flags & TH_CWR);
        
        // Classify response based on flags
        if (tcp->th_flags & TH_RST) {
            fs_add_constchar(fs, "classification", "rst");
            // For custom module, success depends on what we're looking for
            // Default to considering RST as a negative response
            fs_add_bool(fs, "success", 0);
        } else if ((tcp->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
            fs_add_constchar(fs, "classification", "synack");
            fs_add_bool(fs, "success", 1);
        } else {
            // Other responses
            char classification[32];
            snprintf(classification, sizeof(classification), "tcp_flags=0x%02x", tcp->th_flags);
            fs_add_string(fs, "classification", strdup(classification), 1);
            // For custom scans, we consider any response a success
            fs_add_bool(fs, "success", 1);
        }
        
        fs_add_null_icmp(fs);
    } else if (ip_hdr->ip_p == IPPROTO_ICMP) {
        // Handle ICMP responses
        fs_add_null(fs, "sport");
        fs_add_null(fs, "dport");
        fs_add_null(fs, "seqnum");
        fs_add_null(fs, "acknum");
        fs_add_null(fs, "window");
        fs_add_null(fs, "flag_fin");
        fs_add_null(fs, "flag_syn");
        fs_add_null(fs, "flag_rst");
        fs_add_null(fs, "flag_psh");
        fs_add_null(fs, "flag_ack");
        fs_add_null(fs, "flag_urg");
        fs_add_null(fs, "flag_ece");
        fs_add_null(fs, "flag_cwr");
        
        fs_add_constchar(fs, "classification", "icmp");
        fs_add_bool(fs, "success", 0);
        
        fs_populate_icmp_from_iphdr(ip_hdr, len, fs);
    }
}

// Custom print packet function
static void custom_print_packet(FILE *fp, void *packet)
{
    struct ether_header *ethh = (struct ether_header *)packet;
    struct ip *iph = (struct ip *)&ethh[1];
    struct tcphdr *tcph = (struct tcphdr *)&iph[1];
    
    if (zconf.fast_dryrun) {
        // Binary output format for fast dryrun
        struct in_addr *dest_IP = (struct in_addr *)&(iph->ip_dst);
        const uint8_t IP_ADDR_LEN = 4;
        const uint8_t TCP_PORT_LEN = 2;
        fwrite(&(dest_IP->s_addr), IP_ADDR_LEN, 1, fp);
        fwrite(&(tcph->th_dport), TCP_PORT_LEN, 1, fp);
        return;
    }
    
    // Human-readable format
    fprintf(fp, "tcp { source: %u | dest: %u | seq: %u | ack: %u | flags: ",
            ntohs(tcph->th_sport), ntohs(tcph->th_dport),
            ntohl(tcph->th_seq), ntohl(tcph->th_ack));
    
    // Print TCP flags
    if (tcph->th_flags & TH_FIN) fprintf(fp, "FIN ");
    if (tcph->th_flags & TH_SYN) fprintf(fp, "SYN ");
    if (tcph->th_flags & TH_RST) fprintf(fp, "RST ");
    if (tcph->th_flags & TH_PUSH) fprintf(fp, "PSH ");
    if (tcph->th_flags & TH_ACK) fprintf(fp, "ACK ");
    if (tcph->th_flags & TH_URG) fprintf(fp, "URG ");
    if (tcph->th_flags & TH_ECE) fprintf(fp, "ECE ");
    if (tcph->th_flags & TH_CWR) fprintf(fp, "CWR ");
    
    fprintf(fp, "| window: %u | checksum: %#04X }\n",
            ntohs(tcph->th_win), ntohs(tcph->th_sum));
    
    fprintf_ip_header(fp, iph);
    fprintf_eth_header(fp, ethh);
    
    // Print payload if present
    if (custom_payload && payload_len > 0) {
        fprintf(fp, "payload (%zu bytes): ", payload_len);
        const unsigned char *payload = (const unsigned char *)tcph + tcp_header_len;
        for (size_t i = 0; i < payload_len; i++) {
            if (isprint(payload[i])) {
                fprintf(fp, "%c", payload[i]);
            } else {
                fprintf(fp, "\\x%02x", payload[i]);
            }
        }
        fprintf(fp, "\n");
    }
    
    fprintf(fp, PRINT_PACKET_SEP);
}

// Module cleanup function
static int custom_close(UNUSED struct state_conf *conf, UNUSED struct state_send *send,
                      UNUSED struct state_recv *recv)
{
    if (custom_payload) {
        free(custom_payload);
        custom_payload = NULL;
    }
    return EXIT_SUCCESS;
}

// Field definitions for output
static fielddef_t fields[] = {
    {.name = "sport", .type = "int", .desc = "TCP source port"},
    {.name = "dport", .type = "int", .desc = "TCP destination port"},
    {.name = "seqnum", .type = "int", .desc = "TCP sequence number"},
    {.name = "acknum", .type = "int", .desc = "TCP acknowledgement number"},
    {.name = "window", .type = "int", .desc = "TCP window"},
    {.name = "flag_fin", .type = "bool", .desc = "TCP FIN flag"},
    {.name = "flag_syn", .type = "bool", .desc = "TCP SYN flag"},
    {.name = "flag_rst", .type = "bool", .desc = "TCP RST flag"},
    {.name = "flag_psh", .type = "bool", .desc = "TCP PSH flag"},
    {.name = "flag_ack", .type = "bool", .desc = "TCP ACK flag"},
    {.name = "flag_urg", .type = "bool", .desc = "TCP URG flag"},
    {.name = "flag_ece", .type = "bool", .desc = "TCP ECE flag"},
    {.name = "flag_cwr", .type = "bool", .desc = "TCP CWR flag"},
    CLASSIFICATION_SUCCESS_FIELDSET_FIELDS,
    ICMP_FIELDSET_FIELDS,
};

// Module definition
probe_module_t module_tcp_custom = {
    .name = "tcp_custom",
    .pcap_filter = "tcp || icmp",
    .pcap_snaplen = 96,
    .port_args = 1,
    .global_initialize = &custom_global_initialize,
    .prepare_packet = &custom_prepare_packet,
    .make_packet = &custom_make_packet,
    .print_packet = &custom_print_packet,
    .process_packet = &custom_process_packet,
    .validate_packet = &custom_validate_packet,
    .close = &custom_close,
    .helptext =
        "Probe module that sends TCP packets with customizable flags and payload.\n"
        "Customize TCP flags, payload, window size, and more using --probe-args:\n"
        "--probe-args='flags=SYN+ACK;payload=GET / HTTP/1.0\\r\\n\\r\\n;window=4096;random_acks=true'\n"
        "Available flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR\n"
        "Escape sequences in payload: \\r, \\n, \\t, \\x00 (hex bytes)",
    .output_type = OUTPUT_TYPE_STATIC,
    .fields = fields,
    .numfields = sizeof(fields) / sizeof(fields[0])
};