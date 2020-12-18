#include <stdio.h>

// Basic secp256k1 config
#define USE_BASIC_CONFIG
#define ECMULT_GEN_PREC_BITS 2

#include "src/basic-config.h"
#include "src/secp256k1.c"


#include "externs.h"
#include "segwit_addr.h"

// Chad Thundercock
#include <pthread.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>



// Stolen from supervanitygen
void announce_result(int found, const u8 result[52])
{
  align8 u8 priv_block[64], pub_block[64], cksum_block[64];
  align8 u8 wif[64], checksum[32];
  int j;

  /* Convert Private Key to WIF */

  /* Set up sha256 block for hashing the private key; length of 34 bytes */
  sha256_prepare(priv_block, 34);
  priv_block[0]=0x80;
  memcpy(priv_block+1, result, 32);
  priv_block[33]=0x01;  /* 1=Compressed Public Key */

  /* Set up checksum block; length of 32 bytes */
  sha256_prepare(cksum_block, 32);

  /* Compute checksum and copy first 4-bytes to end of private key */
  sha256_hash(cksum_block, priv_block);
  sha256_hash(checksum, cksum_block);
  memcpy(priv_block+34, checksum, 4);

  b58enc(wif, priv_block, 38);
  
  printf("Private Key:   %s\n", wif);

//   /* Convert Public Key to Compressed WIF */

//   /* Set up sha256 block for hashing the public key; length of 21 bytes */
//   sha256_prepare(pub_block, 21);
//   memcpy(pub_block+1, result+32, 20);

//   /* Compute checksum and copy first 4-bytes to end of public key */
//   sha256_hash(cksum_block, pub_block);
//   sha256_hash(checksum, cksum_block);
//   memcpy(pub_block+21, checksum, 4);

//   b58enc(wif, pub_block, 25);
 
//   printf("Address:       %s\n", wif);
}


// Run this on retarded user input
void print_usage()
{

}


void parse_arguments(int argc, char** argv)
{

}

// Useless function, don't know why I even wrote it
unsigned char* reverse_pubkey(unsigned char* compressed_pubkey)
{
	// Reverse Public Key (Useless)
	int j = 32;
	for(int i = 0; i < 17; i++)
	{
		// printf("%d vs %d\n",i,j);
		// printf("%02X vs %02X\n",compressed_pubkey[i],compressed_pubkey[j]);
		unsigned char temp;
		temp = compressed_pubkey[j];
		compressed_pubkey[j] = compressed_pubkey[i];
		compressed_pubkey[i] = temp;
		// printf("%02X vs %02X\n\n",compressed_pubkey[i],compressed_pubkey[j]);
		j--;
	}

	return compressed_pubkey;
}


// Here is where the magic happens
int main(int argc, char** argv)
{
	// Declare Secp256k1 Stuff
	secp256k1_context *sec_ctx;
	unsigned char sha_block[64], rmd_block[64], ScriptPubKey[20], ScriptPubKey_Append[22];
	u64 privkey[4];
	int i, k, fd, len; //for udev random


	/* Initialize the secp256k1 context */
	sec_ctx=secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

	/* Set up sha256 block for an input length of 33 bytes */
	sha256_prepare(sha_block, 33);

	/* Set up rmd160 block for an input length of 32 bytes */
	rmd160_prepare(rmd_block, 32);

	// Generate a random private key. Specifically, any 256-bit number from 0x1
	// to 0xFFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFE BAAE DCE6 AF48 A03B BFD2 5E8C
	// D036 4140 is a valid private key.

	again:

	if((fd=open("/dev/urandom", O_RDONLY|O_NOCTTY)) == -1) {
	perror("/dev/urandom");
	return;
	}

	/* Use 32 bytes from /dev/urandom as starting private key */
	do {
	if((len=read(fd, privkey, 32)) != 32) {
		if(len != -1)
		errno=EAGAIN;
		perror("/dev/urandom");
		return;
	}
	} while(privkey[0]+1 < 2);  /* Ensure only valid private keys */

	close(fd);



	// Generate public key from private key
	secp256k1_pubkey public_key;
	
	secp256k1_ec_pubkey_create(sec_ctx,&public_key,&privkey);


	unsigned char compressed_pubkey[33];
	
	size_t  var = 33;   		/* actual variable declaration */
	size_t  *outputlen;        /* pointer variable declaration */
	outputlen = &var;  		/* store address of var in pointer variable*/

	int result = secp256k1_ec_pubkey_serialize(sec_ctx,compressed_pubkey,outputlen,&public_key,SECP256K1_EC_COMPRESSED);
	

	int valid_private_key = secp256k1_ec_seckey_verify(sec_ctx,&privkey);




	
	// Obvious public key
	// compressed_pubkey[32] = 0x00;
	// compressed_pubkey[31] = 0x00;
	// compressed_pubkey[30] = 0x00;
	// compressed_pubkey[29] = 0x00;
	// compressed_pubkey[28] = 0x00;
	// compressed_pubkey[27] = 0x00;
	// compressed_pubkey[26] = 0x00;
	// compressed_pubkey[25] = 0x00;
	// compressed_pubkey[24] = 0x00;
	// compressed_pubkey[23] = 0x00;
	// compressed_pubkey[22] = 0x00;
	// compressed_pubkey[21] = 0x00;
	// compressed_pubkey[20] = 0x00;
	// compressed_pubkey[19] = 0x00;
	// compressed_pubkey[18] = 0x00;
	// compressed_pubkey[17] = 0x00;
	// compressed_pubkey[16] = 0x00;
	// compressed_pubkey[15] = 0x00;
	// compressed_pubkey[14] = 0x00;
	// compressed_pubkey[13] = 0x00;
	// compressed_pubkey[12] = 0x00;
	// compressed_pubkey[11] = 0x00;
	// compressed_pubkey[10] = 0x00;
	// compressed_pubkey[9] = 0x00;
	// compressed_pubkey[8] = 0x00;
	// compressed_pubkey[7] = 0x00;
	// compressed_pubkey[6] = 0x00;
	// compressed_pubkey[5] = 0x00;
	// compressed_pubkey[4] = 0x00;
	// compressed_pubkey[3] = 0x00;
	// compressed_pubkey[2] = 0x00;
	// compressed_pubkey[1] = 0x00;
	// compressed_pubkey[0] = 0x00;

	//Pttn Example
	// compressed_pubkey[32] = 0x03;
	// compressed_pubkey[31] = 0xf6;
	// compressed_pubkey[30] = 0xa8;
	// compressed_pubkey[29] = 0xf0;
	// compressed_pubkey[28] = 0xd8;
	// compressed_pubkey[27] = 0x54;
	// compressed_pubkey[26] = 0x2c;
	// compressed_pubkey[25] = 0x31;
	// compressed_pubkey[24] = 0xf2;
	// compressed_pubkey[23] = 0x30;
	// compressed_pubkey[22] = 0xa3;
	// compressed_pubkey[21] = 0xf4;
	// compressed_pubkey[20] = 0x51;
	// compressed_pubkey[19] = 0xa2;
	// compressed_pubkey[18] = 0x18;
	// compressed_pubkey[17] = 0xfa;
	// compressed_pubkey[16] = 0xcc;
	// compressed_pubkey[15] = 0xa8;
	// compressed_pubkey[14] = 0x54;
	// compressed_pubkey[13] = 0x26;
	// compressed_pubkey[12] = 0x51;
	// compressed_pubkey[11] = 0xc9;
	// compressed_pubkey[10] = 0xe6;
	// compressed_pubkey[9] = 	0x5b;
	// compressed_pubkey[8] = 	0xe7;
	// compressed_pubkey[7] = 	0xe1;
	// compressed_pubkey[6] = 	0x53;
	// compressed_pubkey[5] = 	0xcf;
	// compressed_pubkey[4] = 	0x26;
	// compressed_pubkey[3] = 	0x97;
	// compressed_pubkey[2] = 	0x48;
	// compressed_pubkey[1] = 	0x07;
	// compressed_pubkey[0] = 	0xce;

	//
	// Example from https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
	// compressed_pubkey[32] = 0x02;
	// compressed_pubkey[31] = 0x50;
	// compressed_pubkey[30] = 0x86;
	// compressed_pubkey[29] = 0x3a;
	// compressed_pubkey[28] = 0xd6;
	// compressed_pubkey[27] = 0x4a;
	// compressed_pubkey[26] = 0x87;
	// compressed_pubkey[25] = 0xae;
	// compressed_pubkey[24] = 0x8a;
	// compressed_pubkey[23] = 0x2f;
	// compressed_pubkey[22] = 0xe8;
	// compressed_pubkey[21] = 0x3c;
	// compressed_pubkey[20] = 0x1a;
	// compressed_pubkey[19] = 0xf1;
	// compressed_pubkey[18] = 0xa8;
	// compressed_pubkey[17] = 0x40;
	// compressed_pubkey[16] = 0x3c;
	// compressed_pubkey[15] = 0xb5;
	// compressed_pubkey[14] = 0x3f;
	// compressed_pubkey[13] = 0x53;
	// compressed_pubkey[12] = 0xe4;
	// compressed_pubkey[11] = 0x86;
	// compressed_pubkey[10] = 0xd8;
	// compressed_pubkey[9] =  0x51;
	// compressed_pubkey[8] =  0x1d;
	// compressed_pubkey[7] =  0xad;
	// compressed_pubkey[6] =  0x8a;
	// compressed_pubkey[5] =  0x04;
	// compressed_pubkey[4] =  0x88;
	// compressed_pubkey[3] =  0x7e;
	// compressed_pubkey[2] =  0x5b;
	// compressed_pubkey[1] =  0x23;
	// compressed_pubkey[0] =  0x52;


	printf("ScriptPubKey        =   ");
	for(int i = 20-1; i >= 0; i--)
	{
		printf("%02X",ScriptPubKey[i]);
		ScriptPubKey_Append[i] = ScriptPubKey[i];
	}

	printf("\n");

	printf("rmd_block: ");
	for(int i = 32-1; i >= 0; i--)
	{
		printf("%02X",i,rmd_block[i]);
	}
	printf("\n");

	printf("sha_block: ");
	for(int i = 32-1; i >= 0; i--)
	{
		printf("%02X",i,sha_block[i]);
	}
	printf("\n");


	// Using Openssl for double checking 
	//SHA256(compressed_pubkey, 33, rmd_block);

	printf("SHA256: ");
	for(int i = 32-1; i >= 0; i--)
	{
		printf("%02X",i,rmd_block[i]);
	}
	printf("\n");

	/* Double Hash Compressed public key */
	//sha256_hash(rmd_block, compressed_pubkey);

	printf("SHA256: ");
	for(int i = 32-1; i >= 0; i--)
	{
		printf("%02X",i,rmd_block[i]);
	}
	printf("\n");


    rmd160_hash(ScriptPubKey, rmd_block);

	



	char output[93];
	const char *hrp = "bc";

	const uint8_t *witprog; //ripemd(sha256(pub))
	witprog = ScriptPubKey;

	size_t witprog_len = 20;


	int convert_bench32 = segwit_addr_encode(output,hrp,0,witprog, witprog_len);


	if(convert_bench32 == 0)
	{
		printf("Bench32 convertion failed\n");
	}


	// Pattern Matching
	char *pattern = "bc1qpt";

	//printf("%s\n",pattern);
	//printf("Sizeof(pattern) %d\n",sizeof(pattern));

	// Check if pattern matches
	// for(int i = 0; i < 6; i++)
	// {
	// 	if(!(pattern[i] == output[i]))
	// 	{
	// 		goto again;
	// 	}
	// }


	// Don't know why this is printing like that
	// printf("privKey : ");
	// for(int i = 3; i >=0 ; i--)
	// {
	// 	printf("%02X",privkey[i]);
	// }
	// printf("\n");

	// Result Printing
	announce_result(1,privkey);

	printf("pubComp : ");
	//Print Binary Contents of public
	for(int i = 33-1; i >= 0; i--)
	{
		printf("%02X",compressed_pubkey[i]);
	}
	printf("\n");


	printf("SHA256: ");
	for(int i = 32-1; i >= 0; i--)
	{
		printf("%02X",i,rmd_block[i]);
	}
	printf("\n");

	printf("RIPEMD160: ");
	for(int i = 20-1; i >= 0; i--)
	{
		printf("%02X",ScriptPubKey[i]);
	}

	printf("\n");

	printf("ScriptPubKey        =   ");
	for(int i = 20-1; i >= 0; i--)
	{
		printf("%02X",ScriptPubKey[i]);
		ScriptPubKey_Append[i] = ScriptPubKey[i];
	}

	printf("\n");

	printf("ScriptPubKey_Append = ");
	ScriptPubKey_Append[20] = ScriptPubKey_Append[20] & 0x0;
	ScriptPubKey_Append[21] = ScriptPubKey_Append[21] & 0x0;

	for(int i = 22-1; i >= 0; i--)
	{
		printf("%02X",ScriptPubKey_Append[i]);
	}
	printf("\n");

	printf("Address: %s\n",output);


	printf("\n\n");
	printf("               Private Key Size = %d bytes, %d bits \n",sizeof(privkey),sizeof(privkey)*8);
	printf("(Uncompressed) Public  Key Size = %d bytes, %d bits \n",sizeof(public_key.data),sizeof(public_key.data)*8);
	printf("(Compressed)   Public  Key Size = %d bytes, %d bits \n",sizeof(compressed_pubkey),sizeof(compressed_pubkey)*8);
	printf("          ScriptPubKey Key Size = %d bytes, %d bits \n",sizeof(ScriptPubKey),sizeof(ScriptPubKey)*8);
	printf("   ScriptPubKey Key Append Size = %d bytes, %d bits \n",sizeof(ScriptPubKey_Append),sizeof(ScriptPubKey_Append)*8);
	printf("\n\n");

	return 0;
}

