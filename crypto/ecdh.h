#ifndef ECDH_H
#define ECDH_H

#include "fortuna.h"
#include "curve25519-donna.h"

static const uint8_t Curve25519Base[32] = {9};

void ECC_Curve25519_Create(uint8_t pub[32], uint8_t k[32], FortunaPRNG& fprng);
#endif