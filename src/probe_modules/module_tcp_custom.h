/*
 * ZMap Copyright 2023 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// Header for the custom TCP probe module

#ifndef MODULE_TCP_CUSTOM_H
#define MODULE_TCP_CUSTOM_H

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

// Module definition for other files to reference
extern probe_module_t module_tcp_custom;

#endif // MODULE_TCP_CUSTOM_H