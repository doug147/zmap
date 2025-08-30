/*
 * ZMap Copyright 2024 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for performing custom TCP scans with TFO support

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <time.h>

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
#define MAX_TCP_OPTIONS_SIZE 40
#define TFO_COOKIE_SIZE 8

// TCP Option kinds
#define TCPOPT_EOL      0
#define TCPOPT_NOP      1
#define TCPOPT_MSS      2
#define TCPOPT_WSCALE   3
#define TCPOPT_SACKOK   4
#define TCPOPT_SACK     5
#define TCPOPT_TIMESTAMP 8
#define TCPOPT_TFO      34  // TCP Fast Open option

probe_module_t module_tcp_custom;

// TFO modes
typedef enum {
    TFO_MODE_DISABLED,     // Don't use TFO
    TFO_MODE_REQUEST,      // Send TFO request (empty cookie)
    TFO_MODE_COOKIE,       // Send with cookie
    TFO_MODE_SYN_DATA,     // Send SYN with data (requires cookie)
} tfo_mode_t;

// TFO configuration
typedef struct {
    tfo_mode_t mode;
    uint8_t cookie[TFO_COOKIE_SIZE];
    uint8_t cookie_len;
    int use_random_cookie;
} tfo_config_t;

// TCP Options configuration
typedef struct {
    int include_mss;
    int include_window_scale;
    int include_sack_permitted;
    int include_timestamps;
    int include_nop_padding;
    uint16_t mss_value;
    uint8_t window_scale_value;
    uint32_t timestamp_value;
    uint32_t timestamp_echo;
    tfo_config_t tfo;  // TFO configuration
} tcp_options_config_t;

// Global configuration
static uint16_t num_source_ports;
static char *payload = NULL;
static size_t payload_len = 0;
static uint16_t tcp_flags = 0;
static int random_ack = 0;
static uint32_t fixed_ack = 0;
static uint16_t window_size = 65535;
static tcp_options_config_t tcp_options = {0};
static int tcp_options_len = 0;
static uint8_t tcp_options_buffer[MAX_TCP_OPTIONS_SIZE];

// Function to generate random bytes for TFO cookie
static void generate_random_tfo_cookie(uint8_t *cookie, uint8_t len)
{
    if (!cookie || len == 0 || len > TFO_COOKIE_SIZE) return;
    
    for (uint8_t i = 0; i < len; i++) {
        cookie[i] = (uint8_t)(rand() & 0xFF);
    }
}

// Function to parse hex string to bytes
static int parse_hex_string(const char *hex_str, uint8_t *output, int max_len)
{
    int len = 0;
    while (*hex_str && *(hex_str + 1) && len < max_len) {
        if (isxdigit(hex_str[0]) && isxdigit(hex_str[1])) {
            char hex[3] = {hex_str[0], hex_str[1], '\0'};
            output[len++] = (uint8_t)strtol(hex, NULL, 16);
            hex_str += 2;
        } else {
            break;
        }
    }
    return len;
}

// Function to parse TFO mode from string
static void parse_tfo_mode(const char *tfo_str, tfo_config_t *tfo)
{
    if (!tfo_str || !tfo) return;

    // Reset TFO config
    memset(tfo, 0, sizeof(tfo_config_t));

    if (strcasecmp(tfo_str, "disabled") == 0 || strcasecmp(tfo_str, "no") == 0 ||
        strcasecmp(tfo_str, "false") == 0 || strcmp(tfo_str, "0") == 0) {
        tfo->mode = TFO_MODE_DISABLED;
    } else if (strcasecmp(tfo_str, "request") == 0) {
        tfo->mode = TFO_MODE_REQUEST;
        tfo->cookie_len = 0;  // Empty cookie for request
    } else if (strcasecmp(tfo_str, "cookie") == 0 || strcasecmp(tfo_str, "yes") == 0 ||
               strcasecmp(tfo_str, "true") == 0 || strcmp(tfo_str, "1") == 0) {
        tfo->mode = TFO_MODE_COOKIE;
        tfo->cookie_len = TFO_COOKIE_SIZE;
        tfo->use_random_cookie = 1;
        generate_random_tfo_cookie(tfo->cookie, tfo->cookie_len);
    } else if (strcasecmp(tfo_str, "syn-data") == 0 || strcasecmp(tfo_str, "data") == 0) {
        tfo->mode = TFO_MODE_SYN_DATA;
        tfo->cookie_len = TFO_COOKIE_SIZE;
        tfo->use_random_cookie = 1;
        generate_random_tfo_cookie(tfo->cookie, tfo->cookie_len);
    } else if (strncasecmp(tfo_str, "cookie:", 7) == 0) {
        // Parse specific cookie value (hex format)
        tfo->mode = TFO_MODE_COOKIE;
        const char *hex_str = tfo_str + 7;
        tfo->cookie_len = parse_hex_string(hex_str, tfo->cookie, TFO_COOKIE_SIZE);
        
        if (tfo->cookie_len == 0) {
            // Invalid cookie, use random
            tfo->cookie_len = TFO_COOKIE_SIZE;
            tfo->use_random_cookie = 1;
            generate_random_tfo_cookie(tfo->cookie, tfo->cookie_len);
        } else {
            tfo->use_random_cookie = 0;
        }
    } else {
        tfo->mode = TFO_MODE_DISABLED;
    }
}

// Function to build TFO option
static int build_tfo_option(const tfo_config_t *tfo, uint8_t *buffer, int max_size)
{
    if (!tfo || !buffer || tfo->mode == TFO_MODE_DISABLED) return 0;
    
    int required_size = 2;  // Kind + Length
    if (tfo->mode == TFO_MODE_REQUEST) {
        required_size = 2;  // Empty cookie for request
    } else if (tfo->cookie_len > 0) {
        required_size = 2 + tfo->cookie_len;
    }
    
    if (required_size > max_size) return 0;
    
    buffer[0] = TCPOPT_TFO;  // TFO option kind (34)
    
    if (tfo->mode == TFO_MODE_REQUEST) {
        buffer[1] = 2;  // Length = 2 (just kind and length, no cookie)
        return 2;
    } else {
        buffer[1] = 2 + tfo->cookie_len;  // Length
        if (tfo->cookie_len > 0) {
            memcpy(buffer + 2, tfo->cookie, tfo->cookie_len);
        }
        return 2 + tfo->cookie_len;
    }
}

// Function to build TCP options buffer
static int build_tcp_options(const tcp_options_config_t *config, uint8_t *buffer, int max_size)
{
    if (!config || !buffer || max_size < 4) return 0;

    int offset = 0;

    // MSS option (kind=2, length=4)
    if (config->include_mss && offset + 4 <= max_size) {
        buffer[offset++] = TCPOPT_MSS;
        buffer[offset++] = 4;
        buffer[offset++] = (config->mss_value >> 8) & 0xFF;
        buffer[offset++] = config->mss_value & 0xFF;
    }

    // Window Scale option (kind=3, length=3)
    if (config->include_window_scale && offset + 3 <= max_size) {
        buffer[offset++] = TCPOPT_WSCALE;
        buffer[offset++] = 3;
        buffer[offset++] = config->window_scale_value;
    }

    // SACK Permitted (kind=4, length=2)
    if (config->include_sack_permitted && offset + 2 <= max_size) {
        buffer[offset++] = TCPOPT_SACKOK;
        buffer[offset++] = 2;
    }

    // Timestamps (kind=8, length=10)
    if (config->include_timestamps && offset + 10 <= max_size) {
        buffer[offset++] = TCPOPT_TIMESTAMP;
        buffer[offset++] = 10;
        // Timestamp value (4 bytes)
        uint32_t ts = config->timestamp_value;
        buffer[offset++] = (ts >> 24) & 0xFF;
        buffer[offset++] = (ts >> 16) & 0xFF;
        buffer[offset++] = (ts >> 8) & 0xFF;
        buffer[offset++] = ts & 0xFF;
        // Echo reply (4 bytes)
        uint32_t echo = config->timestamp_echo;
        buffer[offset++] = (echo >> 24) & 0xFF;
        buffer[offset++] = (echo >> 16) & 0xFF;
        buffer[offset++] = (echo >> 8) & 0xFF;
        buffer[offset++] = echo & 0xFF;
    }

    // TFO option
    if (config->tfo.mode != TFO_MODE_DISABLED) {
        int tfo_len = build_tfo_option(&config->tfo, buffer + offset, max_size - offset);
        offset += tfo_len;
    }

    // NOP padding to align to 4-byte boundary
    if (config->include_nop_padding) {
        while (offset % 4 != 0 && offset < max_size) {
            buffer[offset++] = TCPOPT_NOP;
        }
    }

    return offset;
}

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
                if (isxdigit(*(input + 1)) && isxdigit(*(input + 2))) {
                    char hex[3] = {*(input + 1), *(input + 2), 0};
                    *output++ = (char)strtol(hex, NULL, 16);
                    len++;
                    input += 2;
                } else {
                    *output++ = 'x';
                    len++;
                }
                break;
            }
            case '\\':
                *output++ = '\\';
                len++;
                break;
            case '0':
                *output++ = '\0';
                len++;
                break;
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

// Function to parse TCP options string
static void parse_tcp_options_string(const char *options_str, tcp_options_config_t *opts)
{
    if (!options_str || !opts) return;

    if (strcasecmp(options_str, "yes") == 0 || strcasecmp(options_str, "all") == 0 ||
        strcasecmp(options_str, "true") == 0 || strcmp(options_str, "1") == 0) {
        // Enable all common options
        opts->include_mss = 1;
        opts->include_window_scale = 1;
        opts->include_sack_permitted = 1;
        opts->include_timestamps = 1;
        opts->include_nop_padding = 1;
        opts->mss_value = 1460;
        opts->window_scale_value = 7;
        opts->timestamp_value = (uint32_t)time(NULL);
        opts->timestamp_echo = 0;
    } else if (strcasecmp(options_str, "no") == 0 || strcasecmp(options_str, "false") == 0 ||
               strcmp(options_str, "0") == 0) {
        // All options disabled
        memset(opts, 0, sizeof(tcp_options_config_t));
    } else {
        // Parse specific options
        char *str_copy = strdup(options_str);
        char *token;
        char *rest = str_copy;

        while ((token = strtok_r(rest, ",", &rest))) {
            // Trim whitespace
            while (*token == ' ') token++;
            char *end = token + strlen(token) - 1;
            while (end > token && *end == ' ') *end-- = '\0';

            if (strcasecmp(token, "mss") == 0) {
                opts->include_mss = 1;
                opts->mss_value = 1460;
            } else if (strcasecmp(token, "wscale") == 0 || strcasecmp(token, "ws") == 0) {
                opts->include_window_scale = 1;
                opts->window_scale_value = 7;
            } else if (strcasecmp(token, "sack") == 0) {
                opts->include_sack_permitted = 1;
            } else if (strcasecmp(token, "timestamp") == 0 || strcasecmp(token, "ts") == 0) {
                opts->include_timestamps = 1;
                opts->timestamp_value = (uint32_t)time(NULL);
                opts->timestamp_echo = 0;
            } else if (strcasecmp(token, "nop") == 0) {
                opts->include_nop_padding = 1;
            } else if (strncasecmp(token, "tfo", 3) == 0) {
                // Handle TFO option
                if (strlen(token) > 4 && token[3] == ':') {
                    parse_tfo_mode(token + 4, &opts->tfo);
                } else {
                    opts->tfo.mode = TFO_MODE_COOKIE;
                    opts->tfo.cookie_len = TFO_COOKIE_SIZE;
                    opts->tfo.use_random_cookie = 1;
                    generate_random_tfo_cookie(opts->tfo.cookie, opts->tfo.cookie_len);
                }
            }
        }
        free(str_copy);
    }
}

static int customscan_global_initialize(struct state_conf *state)
{
    num_source_ports = state->source_port_last - state->source_port_first + 1;

    // Seed random number generator for TFO cookies
    srand(time(NULL));

    // Reset configurations
    memset(&tcp_options, 0, sizeof(tcp_options_config_t));
    tcp_options_len = 0;

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
                tcp_flags = 0;  // Reset flags
                while ((flag_token = strtok_r(flag_rest, "+", &flag_rest))) {
                    if (strcasecmp(flag_token, "SYN") == 0) tcp_flags |= TH_SYN;
                    else if (strcasecmp(flag_token, "ACK") == 0) tcp_flags |= TH_ACK;
                    else if (strcasecmp(flag_token, "RST") == 0) tcp_flags |= TH_RST;
                    else if (strcasecmp(flag_token, "PSH") == 0 || strcasecmp(flag_token, "PUSH") == 0) tcp_flags |= TH_PUSH;
                    else if (strcasecmp(flag_token, "FIN") == 0) tcp_flags |= TH_FIN;
                    else if (strcasecmp(flag_token, "URG") == 0) tcp_flags |= TH_URG;
                    else log_warn("customscan", "Unknown TCP flag: %s", flag_token);
                }
            } else if (strcmp(key, "payload") == 0) {
                if (payload) free(payload);
                payload = xmalloc(strlen(value) + 1);
                payload_len = unescape_payload(value, payload);
            } else if (strcmp(key, "random_ack") == 0) {
                random_ack = (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0);
            } else if (strcmp(key, "fixed_ack") == 0) {
                fixed_ack = (uint32_t)strtoul(value, NULL, 0);
                random_ack = 0;  // Disable random_ack if fixed_ack is set
            } else if (strcmp(key, "window") == 0) {
                window_size = atoi(value);
            } else if (strcmp(key, "options") == 0) {
                parse_tcp_options_string(value, &tcp_options);
            } else if (strcmp(key, "tfo") == 0) {
                parse_tfo_mode(value, &tcp_options.tfo);
            } else if (strcmp(key, "mss") == 0) {
                tcp_options.include_mss = 1;
                tcp_options.mss_value = atoi(value);
            } else if (strcmp(key, "wscale") == 0) {
                tcp_options.include_window_scale = 1;
                tcp_options.window_scale_value = atoi(value);
            } else {
                log_warn("customscan", "Unknown probe-arg: %s", key);
            }
        }
        free(args);
    }

    // Default flags if none specified
    if (tcp_flags == 0) {
        tcp_flags = TH_SYN;  // Default to SYN
    }

    // If TFO SYN-DATA mode is enabled and SYN flag is set, ensure we have payload
    if (tcp_options.tfo.mode == TFO_MODE_SYN_DATA && (tcp_flags & TH_SYN)) {
        if (!payload || payload_len == 0) {
            // Add a default payload for TFO SYN-DATA
            const char *default_tfo_payload = "GET / HTTP/1.0\r\n\r\n";
            payload = xmalloc(strlen(default_tfo_payload) + 1);
            payload_len = unescape_payload(default_tfo_payload, payload);
        }
    }

    // Build TCP options once if they don't change per packet
    tcp_options_len = build_tcp_options(&tcp_options, tcp_options_buffer, MAX_TCP_OPTIONS_SIZE);

    if (payload_len > MAX_PAYLOAD_SIZE) {
        log_fatal("customscan", "Payload size exceeds MAX_PAYLOAD_SIZE");
    }

    // Calculate maximum packet length including TCP options
    int tcp_header_len = sizeof(struct tcphdr) + tcp_options_len;
    // Round up to 4-byte boundary
    tcp_header_len = ((tcp_header_len + 3) / 4) * 4;

    // Determine actual payload size for packet length calculation
    size_t actual_payload_len = payload_len;
    if ((tcp_flags & TH_SYN) && !(tcp_flags & TH_ACK)) {
        // Pure SYN packet - include payload only if TFO SYN-DATA
        if (tcp_options.tfo.mode != TFO_MODE_SYN_DATA) {
            actual_payload_len = 0;
        }
    }

    module_tcp_custom.max_packet_length = sizeof(struct ether_header) + 
                                          sizeof(struct ip) + 
                                          tcp_header_len + 
                                          actual_payload_len;

    // Log configuration
    log_info("customscan", "TCP flags: 0x%02x", tcp_flags);
    if (tcp_options.tfo.mode != TFO_MODE_DISABLED) {
        const char *tfo_mode_str[] = {"disabled", "request", "cookie", "syn-data"};
        log_info("customscan", "TFO mode: %s", tfo_mode_str[tcp_options.tfo.mode]);
        if (tcp_options.tfo.cookie_len > 0) {
            log_info("customscan", "TFO cookie length: %d bytes", tcp_options.tfo.cookie_len);
        }
    }
    if (payload_len > 0) {
        log_info("customscan", "Payload size: %zu bytes", payload_len);
    }
    log_info("customscan", "TCP options length: %d bytes", tcp_options_len);

    return EXIT_SUCCESS;
}

static int customscan_prepare_packet(void *buf, macaddr_t *src, macaddr_t *gw, UNUSED void *arg_ptr)
{
    memset(buf, 0, MAX_PACKET_SIZE);

    struct ether_header *eth_header = (struct ether_header *)buf;
    make_eth_header(eth_header, src, gw);

    struct ip *ip_header = (struct ip *)(&eth_header[1]);
    
    // Calculate TCP header length with options
    int tcp_header_len = sizeof(struct tcphdr) + tcp_options_len;
    tcp_header_len = ((tcp_header_len + 3) / 4) * 4;  // Round up to 4-byte boundary
    
    // Determine if we should include payload
    size_t actual_payload_len = payload_len;
    if ((tcp_flags & TH_SYN) && !(tcp_flags & TH_ACK)) {
        // Pure SYN packet - include payload only if TFO SYN-DATA
        if (tcp_options.tfo.mode != TFO_MODE_SYN_DATA) {
            actual_payload_len = 0;
        }
    }
    
    uint16_t len = htons(sizeof(struct ip) + tcp_header_len + actual_payload_len);
    make_ip_header(ip_header, IPPROTO_TCP, len);
    ip_header->ip_off |= htons(IP_DF);

    struct tcphdr *tcp_header = (struct tcphdr *)(&ip_header[1]);
    make_tcp_header(tcp_header, tcp_flags);
    
    // Set TCP data offset (header length in 32-bit words)
    tcp_header->th_off = tcp_header_len / 4;

    // Add TCP options if present
    if (tcp_options_len > 0) {
        memcpy((uint8_t *)tcp_header + sizeof(struct tcphdr), tcp_options_buffer, tcp_options_len);
        // Pad with zeros if needed
        int padding = tcp_header_len - sizeof(struct tcphdr) - tcp_options_len;
        if (padding > 0) {
            memset((uint8_t *)tcp_header + sizeof(struct tcphdr) + tcp_options_len, 0, padding);
        }
    }

    // Add payload if appropriate
    if (payload && actual_payload_len > 0) {
        char *payload_start = (char *)tcp_header + tcp_header_len;
        memcpy(payload_start, payload, actual_payload_len);
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

    // Update timestamps if using them
    if (tcp_options.include_timestamps) {
        tcp_options.timestamp_value = (uint32_t)time(NULL);
        // Rebuild options with new timestamp
        tcp_options_len = build_tcp_options(&tcp_options, tcp_options_buffer, MAX_TCP_OPTIONS_SIZE);
    }

    // Regenerate TFO cookie if using random mode
    if (tcp_options.tfo.use_random_cookie && tcp_options.tfo.mode != TFO_MODE_DISABLED) {
        generate_random_tfo_cookie(tcp_options.tfo.cookie, tcp_options.tfo.cookie_len);
        // Rebuild options with new cookie
        tcp_options_len = build_tcp_options(&tcp_options, tcp_options_buffer, MAX_TCP_OPTIONS_SIZE);
    }

    // Calculate TCP header length with options
    int tcp_header_len = sizeof(struct tcphdr) + tcp_options_len;
    tcp_header_len = ((tcp_header_len + 3) / 4) * 4;  // Round up to 4-byte boundary

    // Determine actual payload length
    size_t actual_payload_len = payload_len;
    if ((tcp_flags & TH_SYN) && !(tcp_flags & TH_ACK)) {
        if (tcp_options.tfo.mode != TFO_MODE_SYN_DATA) {
            actual_payload_len = 0;
        }
    }

    uint32_t tcp_seq = validation[0];
    uint32_t tcp_ack = 0;
    
    if (fixed_ack != 0) {
        tcp_ack = fixed_ack;
    } else if (random_ack) {
        tcp_ack = validation[2];
    }

    ip_header->ip_src.s_addr = src_ip;
    ip_header->ip_dst.s_addr = dst_ip;
    ip_header->ip_ttl = ttl;
    ip_header->ip_id = ip_id;
    ip_header->ip_len = htons(sizeof(struct ip) + tcp_header_len + actual_payload_len);

    tcp_header->th_sport = htons(get_src_port(num_source_ports, probe_num, validation));
    tcp_header->th_dport = dport;
    tcp_header->th_seq = tcp_seq;
    tcp_header->th_ack = tcp_ack;
    tcp_header->th_win = htons(window_size);
    tcp_header->th_off = tcp_header_len / 4;

    // Copy TCP options
    if (tcp_options_len > 0) {
        memcpy((uint8_t *)tcp_header + sizeof(struct tcphdr), tcp_options_buffer, tcp_options_len);
        // Pad with zeros if needed
        int padding = tcp_header_len - sizeof(struct tcphdr) - tcp_options_len;
        if (padding > 0) {
            memset((uint8_t *)tcp_header + sizeof(struct tcphdr) + tcp_options_len, 0, padding);
        }
    }

    // Copy payload if appropriate
    if (payload && actual_payload_len > 0) {
        memcpy((char *)tcp_header + tcp_header_len, payload, actual_payload_len);
    }

    tcp_header->th_sum = 0;
    tcp_header->th_sum = tcp_checksum(tcp_header_len + actual_payload_len,
                      ip_header->ip_src.s_addr,
                      ip_header->ip_dst.s_addr, tcp_header);

    ip_header->ip_sum = 0;
    ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);

    *buf_len = sizeof(struct ether_header) + sizeof(struct ip) + tcp_header_len + actual_payload_len;

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

    // For RST packets, check ACK matches our SEQ or SEQ+1
    if (tcp->th_flags & TH_RST) {
        uint32_t ack = ntohl(tcp->th_ack);
        uint32_t expected_ack = ntohl(validation[0]);
        
        // RST can acknowledge either the exact sequence or sequence+1
        // Also handle sequence+payload_len for data packets
        if (ack != expected_ack && 
            ack != expected_ack + 1 &&
            ack != expected_ack + payload_len) {
            return 0;
        }
    } else {
        // For non-RST responses (SYN-ACK, ACK, etc.)
        uint32_t ack = ntohl(tcp->th_ack);
        uint32_t expected_ack = ntohl(validation[0]);
        
        // Check for SYN-ACK or regular ACK
        if (tcp_flags & TH_SYN) {
            // For SYN scans, expect ACK = SEQ + 1
            if (ack != expected_ack + 1) {
                return 0;
            }
        } else if (payload_len > 0) {
            // For data packets, expect ACK = SEQ + payload_len
            if (ack != expected_ack + payload_len && 
                ack != expected_ack + 1) {  // Some systems ACK just the next byte
                return 0;
            }
        } else {
            // For other packets, expect ACK = SEQ + 1
            if (ack != expected_ack + 1) {
                return 0;
            }
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

    // Add fields in the exact order they're defined in the fields array
    fs_add_uint64(fs, "sport", (uint64_t)ntohs(tcp->th_sport));
    fs_add_uint64(fs, "dport", (uint64_t)ntohs(tcp->th_dport));
    fs_add_uint64(fs, "seqnum", (uint64_t)ntohl(tcp->th_seq));
    fs_add_uint64(fs, "acknum", (uint64_t)ntohl(tcp->th_ack));
    fs_add_uint64(fs, "window", (uint64_t)ntohs(tcp->th_win));
    
    // Add TCP flags
    fs_add_bool(fs, "flag_syn", (tcp->th_flags & TH_SYN) ? 1 : 0);
    fs_add_bool(fs, "flag_ack", (tcp->th_flags & TH_ACK) ? 1 : 0);
    fs_add_bool(fs, "flag_rst", (tcp->th_flags & TH_RST) ? 1 : 0);
    fs_add_bool(fs, "flag_psh", (tcp->th_flags & TH_PUSH) ? 1 : 0);
    fs_add_bool(fs, "flag_fin", (tcp->th_flags & TH_FIN) ? 1 : 0);
    fs_add_bool(fs, "flag_urg", (tcp->th_flags & TH_URG) ? 1 : 0);
    
    // Parse TCP options to check for TFO
    int tcp_data_offset = tcp->th_off * 4;
    int options_len = tcp_data_offset - sizeof(struct tcphdr);
    int has_tfo = 0;
    uint64_t tfo_cookie_len = 0;
    
    if (options_len > 0 && options_len <= 40) {
        uint8_t *options = (uint8_t *)tcp + sizeof(struct tcphdr);
        int offset = 0;
        
        while (offset < options_len) {
            uint8_t kind = options[offset];
            
            if (kind == TCPOPT_EOL) {
                break;
            } else if (kind == TCPOPT_NOP) {
                offset++;
                continue;
            }
            
            if (offset + 1 >= options_len) break;
            uint8_t length = options[offset + 1];
            
            if (length < 2 || offset + length > options_len) break;
            
            // Check for TFO option in response
            if (kind == TCPOPT_TFO) {
                has_tfo = 1;
                tfo_cookie_len = (uint64_t)(length - 2);
            }
            
            offset += length;
        }
    }
    
    fs_add_bool(fs, "has_tfo", has_tfo);
    fs_add_uint64(fs, "tfo_cookie_len", tfo_cookie_len);
    
    // Classification and success must be last (part of CLASSIFICATION_SUCCESS_FIELDSET_FIELDS)
    if (tcp->th_flags & TH_RST) {
        fs_add_constchar(fs, "classification", "rst");
        fs_add_bool(fs, "success", 0);
    } else if ((tcp->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK)) {
        fs_add_constchar(fs, "classification", "synack");
        fs_add_bool(fs, "success", 1);
    } else if (tcp->th_flags & TH_ACK) {
        fs_add_constchar(fs, "classification", "ack");
        fs_add_bool(fs, "success", 1);
    } else {
        fs_add_constchar(fs, "classification", "other");
        fs_add_bool(fs, "success", 0);
    }
}

static fielddef_t fields[] = {
    {.name = "sport", .type = "int", .desc = "TCP source port"},
    {.name = "dport", .type = "int", .desc = "TCP destination port"},
    {.name = "seqnum", .type = "int", .desc = "TCP sequence number"},
    {.name = "acknum", .type = "int", .desc = "TCP acknowledgement number"},
    {.name = "window", .type = "int", .desc = "TCP window size"},
    {.name = "flag_syn", .type = "bool", .desc = "TCP SYN flag"},
    {.name = "flag_ack", .type = "bool", .desc = "TCP ACK flag"},
    {.name = "flag_rst", .type = "bool", .desc = "TCP RST flag"},
    {.name = "flag_psh", .type = "bool", .desc = "TCP PSH flag"},
    {.name = "flag_fin", .type = "bool", .desc = "TCP FIN flag"},
    {.name = "flag_urg", .type = "bool", .desc = "TCP URG flag"},
    {.name = "has_tfo", .type = "bool", .desc = "Response contains TFO option"},
    {.name = "tfo_cookie_len", .type = "int", .desc = "TFO cookie length in response"},
    CLASSIFICATION_SUCCESS_FIELDSET_FIELDS
};

probe_module_t module_tcp_custom = {
    .name = "tcp_custom",
    .pcap_filter = "tcp",
    .pcap_snaplen = 256,  // Increased to capture TCP options
    .port_args = 1,
    .global_initialize = &customscan_global_initialize,
    .prepare_packet = &customscan_prepare_packet,
    .make_packet = &customscan_make_packet,
    .print_packet = &synscan_print_packet,
    .process_packet = &customscan_process_packet,
    .validate_packet = &customscan_validate_packet,
    .close = NULL,
    .helptext = "Probe module for sending custom TCP packets with TFO support. "
        "Use --probe-args to specify flags, payload, TCP options, and TFO mode.\n"
        "Examples:\n"
        "  Basic SYN scan: --probe-args 'flags=SYN'\n"
        "  TFO request: --probe-args 'flags=SYN;tfo=request'\n"
        "  TFO with data: --probe-args 'flags=SYN;tfo=syn-data;payload=GET / HTTP/1.0\\r\\n\\r\\n'\n"
        "  Custom cookie: --probe-args 'flags=SYN;tfo=cookie:deadbeef'\n"
        "  All options: --probe-args 'flags=SYN;options=all;tfo=cookie'\n"
        "  Options: flags, payload, random_ack, fixed_ack, window, options, tfo, mss, wscale",
    .output_type = OUTPUT_TYPE_STATIC,
    .fields = fields,
    .numfields = sizeof(fields)/sizeof(fields[0])
};