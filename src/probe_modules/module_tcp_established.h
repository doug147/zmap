/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for sending TCP packets with ACK+PSH flags and payloads
// simulates established TCP connections for educational/research purposes

#ifndef MODULE_TCP_ESTABLISHED_H
#define MODULE_TCP_ESTABLISHED_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "../../lib/includes.h"
#include "../fieldset.h"
#include "probe_modules.h"
#include "packet.h"

#define ZMAP_TCP_ESTABLISHED_PAYLOAD_MAX_LEN 1400
#define TCP_ESTABLISHED_PACKET_HEADER_SIZE 54  // Ethernet + IP + TCP headers

// Function to print packet for debugging
void tcp_established_print_packet(FILE *fp, void *packet);

// Process escape sequences in payload strings
char* tcp_established_process_escape_sequences(const char *input, int *out_len);

#endif // MODULE_TCP_ESTABLISHED_H