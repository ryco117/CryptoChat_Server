#ifndef ECDSA_H
#define ECDSA_H

#include <gmpxx.h>
#include "fortuna.h"
#include "curve25519-donna.c"

static const uint8_t Curve25519Base[32] = {9};

void ECC_Curve25519_Create(uint8_t pub[32], uint8_t k[32], FortunaPRNG& fprng)
{
	fprng.GenerateBlocks(k, 2);
	k[0] &= 248;
	k[31] &= 127;
	k[31] |= 64;

	curve25519_donna(pub, k, Curve25519Base);
	return;
}
#endif
