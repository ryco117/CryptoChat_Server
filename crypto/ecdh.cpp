#include "ecdh.h"

void ECC_Curve25519_Create(uint8_t pub[32], uint8_t k[32], FortunaPRNG& fprng)
{
	fprng.GenerateBlocks(k, 2);
	k[0] &= 248;
	k[31] &= 127;
	k[31] |= 64;

	curve25519_donna(pub, k, Curve25519Base);
	return;
}