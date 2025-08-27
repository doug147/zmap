/*
 * ZMap Copyright 2024 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for performing custom TCP scans

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "../../lib/includes.h"
#include "../../lib/xalloc.h"
#include "../fieldset.h"
#include "probe_modules.h"
#include "packet.h"
#include "logger.h"
#include "validate.h"

#include "module_tcp_custom.h"
#include "module_tcp_synscan.h"

#define MAX_PAYLOAD_SIZE 1400

probe_module_t module_tcp_custom;

static uint16_t num_source_ports;
static char *payload = NULL;
static size_t payload_len = 0;
static uint16_t tcp_flags = 0;
static int random_ack = 0;
static uint16_t window_size = 65535;

// Function to unescape a string
static size_t unescape_payload(const char *input, char *output)
{
    size_t len = 0;
    while (*input) {
        if (*input == '\\' && *(input + 1)) {
            switch (*(++input)) {
            case 'n':
                *output++ = '\n';
                len++;
                break;
            case 'r':
                *output++ = '\r';
                len++;
                break;
            case 't':
                *output++ = '\t';
                len++;
                break;
            case 'x': {
                char hex[3] = {*(input + 1), *(input + 2), 0};
                *output++ = (char)strtol(hex, NULL, 16);
                len++;
                input += 2;
                break;
            }
            default:
                *output++ = *input;
                len++;
            }
        } else {
            *output++ = *input;
            len++;
        }
        input++;
    }
    return len;
}

static int customscan_global_initialize(struct state_conf *state)
{
    num_source_ports = state->source_port_last - state->source_port_first + 1;

    if (state->probe_args) {
        char *args = strdup(state->probe_args);
        char *token;
        char *rest = args;

        while ((token = strtok_r(rest, ";", &rest))) {
            char *key = strtok(token, "=");
            char *value = strtok(NULL, "");

            if (!value) {
                log_fatal("customscan", "Invalid probe-arg: %s", key);
            }

            if (strcmp(key, "flags") == 0) {
                char *flag_token;
                char *flag_rest = value;
                while ((flag_token = strtok_r(flag_rest, "+", &flag_rest))) {
                    if (strcmp(flag_token, "SYN") == 0) tcp_flags |= TH_SYN;
                    else if (strcmp(flag_token, "ACK") == 0) tcp_flags |= TH_ACK;
                    else if (strcmp(flag_token, "RST") == 0) tcp_flags |= TH_RST;
                    else if (strcmp(flag_token, "PSH") == 0) tcp_flags |= TH_PUSH;
                    else if (strcmp(flag_token, "FIN") == 0) tcp_flags |= TH_FIN;
                    else if (strcmp(flag_token, "URG") == 0) tcp_flags |= TH_URG;
                    else log_warn("customscan", "Unknown TCP flag: %s", flag_token);
                }
            } else if (strcmp(key, "payload") == 0) {
                payload = xmalloc(strlen(value) + 1);
                payload_len = unescape_payload(value, payload);
            } else if (strcmp(key, "random_ack") == 0) {
                random_ack = (strcmp(value, "true") == 0);
            } else if (strcmp(key, "window") == 0) {
                window_size = atoi(value);
            } else {
                log_warn("customscan", "Unknown probe-arg: %s", key);
            }
        }
        free(args);
    }
    if (payload_len > MAX_PAYLOAD_SIZE) {
        log_fatal("customscan", "Payload size exceeds MAX_PAYLOAD_SIZE");
    }

    module_tcp_custom.max_packet_length = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + payload_len;
    return EXIT_SUCCESS;
}

static int customscan_prepare_packet(void *buf, macaddr_t *src, macaddr_t *gw, UNUSED void *arg_ptr)
{
    memset(buf, 0, MAX_PACKET_SIZE);

    struct ether_header *eth_header = (struct ether_header *)buf;
    make_eth_header(eth_header, src, gw);

    struct ip *ip_header = (struct ip *)(&eth_header[1]);
    uint16_t len = htons(sizeof(struct ip) + sizeof(struct tcphdr) + payload_len);
    make_ip_header(ip_header, IPPROTO_TCP, len);
    ip_header->ip_off |= htons(IP_DF);

    struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
    make_tcp_header(tcp_header, tcp_flags);

    if (payload) {
        char *payload_start = (char *)tcp_header + sizeof(struct tcphdr);
        memcpy(payload_start, payload, payload_len);
    }

    return EXIT_SUCCESS;
}

static int customscan_make_packet(void *buf, size_t *buf_len, ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
                  port_n_t dport, uint8_t ttl, uint32_t *validation, int probe_num, uint16_t ip_id,
                  UNUSED void *arg)
{
    struct ether_header *eth_header = (struct ether_header *)buf;
    struct ip *ip_header = (struct ip *)(&eth_header[1]);
    struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);

    uint32_t tcp_seq = validation[0];
    uint32_t tcp_ack = random_ack ? validation[2] : 0;

    ip_header->ip_src.s_addr = src_ip;
    ip_header->ip_dst.s_addr = dst_ip;
    ip_header->ip_ttl = ttl;
    ip_header->ip_id = ip_id;

    tcp_header->th_sport = htons(get_src_port(num_source_ports, probe_num, validation));
    tcp_header->th_dport = dport;
    tcp_header->th_seq = tcp_seq;
    tcp_header->th_ack = tcp_ack;
    tcp_header->th_win = htons(window_size);

    tcp_header->th_sum = 0;
    tcp_header->th_sum = tcp_checksum(sizeof(struct tcphdr) + payload_len,
                      ip_header->ip_src.s_addr,
                      ip_header->ip_dst.s_addr, tcp_header);

    ip_header->ip_sum = 0;
    ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

    *buf_len = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr) + payload_len;

    return EXIT_SUCCESS;
}

static int customscan_validate_packet(const struct ip *ip_hdr, uint32_t len,
                      UNUSED uint32_t *src_ip,
                      uint32_t *validation, const struct port_conf *ports)
{
    if (ip_hdr->ip_p != IPPROTO_TCP) {
        return 0;
    }
    struct tcphdr *tcp = get_tcp_header(ip_hdr, len);
    if (!tcp) {
        return 0;
    }
    uint16_t sport = ntohs(tcp->th_sport);
    uint16_t dport = ntohs(tcp->th_dport);

    if (!check_src_port(sport, ports)) {
        return 0;
    }
    if (!check_dst_port(dport, num_source_ports, validation)) {
        return 0;
    }

    if (tcp->th_flags & TH_RST) {
        if (htonl(tcp->th_ack) != htonl(validation[0]) &&
            htonl(tcp->th_ack) != htonl(validation[0]) + 1) {
            return 0;
        }
    } else {
        if (htonl(tcp->th_ack) != htonl(validation[0]) + 1) {
            return 0;
        }
    }

    return 1;
}

static void customscan_process_packet(const u_char *packet,
                      UNUSED uint32_t len, fieldset_t *fs,
                      UNUSED uint32_t *validation,
                      UNUSED struct timespec ts)
{
    struct ip *ip_hdr = (struct ip *)&packet[sizeof(struct ether_header)];
    struct tcphdr *tcp = (struct tcphdr *)((char *)ip_hdr + 4*ip_hdr->ip_hl);

    fs_add_uint64(fs, "sport", (uint64_t)ntohs(tcp->th_sport));
    fs_add_uint64(fs, "dport", (uint64_t)ntohs(tcp->th_dport));
    fs_add_uint64(fs, "seqnum", (uint64_t)ntohl(tcp->th_seq));
    fs_add_uint64(fs, "acknum", (uint64_t)ntohl(tcp->th_ack));
    fs_add_uint64(fs, "window", (uint64_t)ntohs(tcp->th_win));

    if (tcp->th_flags & TH_RST) {
        fs_add_constchar(fs, "classification", "rst");
        fs_add_bool(fs, "success", 0);
    } else {
        fs_add_constchar(fs, "classification", "synack");
        fs_add_bool(fs, "success", 1);
    }
}

static fielddef_t fields[] = {
    {.name = "sport", .type = "int", .desc = "TCP source port"},
    {.name = "dport", .type = "int", .desc = "TCP destination port"},
    {.name = "seqnum", .type = "int", .desc = "TCP sequence number"},
    {.name = "acknum", .type = "int", .desc = "TCP acknowledgement number"},
    {.name = "window", .type = "int", .desc = "TCP window"},
    CLASSIFICATION_SUCCESS_FIELDSET_FIELDS
};


probe_module_t module_tcp_custom = {
    .name = "tcp_custom",
    .pcap_filter = "tcp",
    .pcap_snaplen = 96,
    .port_args = 1,
    .global_initialize = &customscan_global_initialize,
    .prepare_packet = &customscan_prepare_packet,
    .make_packet = &customscan_make_packet,
    .print_packet = &synscan_print_packet,
    .process_packet = &customscan_process_packet,
    .validate_packet = &customscan_validate_packet,
    .close = NULL,
    .helptext = "Probe module for sending custom TCP packets. Use --probe-args to specify flags, payload, etc. "
        "e.g. 'flags=SYN+ACK;payload=\\x01\\x02;random_ack=true;window=1024'",
    .output_type = OUTPUT_TYPE_STATIC,
    .fields = fields,
    .numfields = sizeof(fields)/sizeof(fields[0])
};