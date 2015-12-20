#ifndef FORTUNA_H
#define FORTUNA_H
#include <string.h>
#include <stdlib.h>
extern "C"
{
	#include <libscrypt.h>
}
#include "AES.h"

class FortunaPRNG
{
public:
	FortunaPRNG();
	~FortunaPRNG();
	void Seed(const unsigned char* seed, unsigned int len);
	void GenerateBlocks(unsigned char* out, unsigned int n);
  private:
	void CountInc();
	AES BlkCipher;
	unsigned char Key[32];
	unsigned char Counter[16];
	unsigned char ZeroBlk[16];
};
#endif
