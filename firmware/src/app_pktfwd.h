#pragma once

#include <stdint.h>
#include <stdbool.h>

void getPacketCount(uint32_t* pup, uint32_t* pdown);

bool APP_PKTFWD_Init();

void APP_PKTFWD_Tasks();
