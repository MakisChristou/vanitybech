#include <stdio.h>

// I have 0 idea what I am doing 
#define USE_BASIC_CONFIG
#define ECMULT_GEN_PREC_BITS 2

#include "src/basic-config.h"
#include "src/secp256k1.c"


#include "externs.h"
#include "segwit_addr.h"

/* Number of secp256k1 operations per batch */
#define STEP 3072

int main()
{
	secp256k1_context *sec_ctx;

	align8 u8 sha_block[64], rmd_block[64], ScriptPubKey[20], ScriptPubKey_Append[21];
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


	// printf("\n\n               Private Key = ");

	// //Print Binary Contents of Private Key
	// //privkey[4]
	// for(int i = 3; i >=0 ; i--)
	// {
	// 	printf("%X",privkey[i]);
	// }

	
	// printf("\n\n(Uncompressed) Public Key  = ");
	// //Print Binary Contents of Public Key
	// //public_key.data[64]
	// for(int i = 63; i >= 0; i--)
	// {
	// 	printf("%02X",public_key.data[i]);
	// }


	unsigned char compressed_pubkey[33];
	
	size_t  var = 33;   		/* actual variable declaration */
	size_t  *outputlen;        /* pointer variable declaration */
	outputlen = &var;  		/* store address of var in pointer variable*/

	secp256k1_ec_pubkey_serialize(sec_ctx,compressed_pubkey,outputlen,&public_key,SECP256K1_EC_COMPRESSED);
	

	// printf("\n\n(Compressed)   Public Key  = ");
	// //Print Binary Contents of public
	// for(int i = 32; i >= 0; i--)
	// {
	// 	printf("%02X",compressed_pubkey[i]);
	// }

	// printf("\n\n");


	int valid_private_key = secp256k1_ec_seckey_verify(sec_ctx,&privkey);

	// if(valid_private_key == 0)
	// {
	// 	printf("Invalid Private Key!\n");
	// }
	// else if(valid_private_key == 1)
	// {
	// 	printf("Valid Private Key!\n");
	// }
	// else
	// {
	// 	printf("Something terrible has happened!\n");
	// }
	



	// 32 byte 256bit message to be signed
	// const unsigned char hashed_message[32] = "hello";

	// secp256k1_ecdsa_signature signature;

	// // Sign Message
	// secp256k1_ecdsa_sign(sec_ctx,&signature,hashed_message,&privkey,NULL,NULL);



	// // Verify valid sinature
	// int valid_signature = secp256k1_ecdsa_verify(sec_ctx,&signature,hashed_message,&public_key);
    

	// if(valid_signature == 0)
	// {
	// 	printf("Invalid Signature!\n");
	// }
	// else if(valid_signature == 1)
	// {
	// 	printf("Valid Signature!\n");
	// }
	// else
	// {
	// 	printf("Something terrible has happened!\n");
	// }




	/* Hash Compressed public key */
    sha256_hash(rmd_block, compressed_pubkey);
    rmd160_hash(ScriptPubKey, rmd_block);

	// printf("\n\n");
	// printf("ScriptPubKey          = ");


	for(int i = 19; i >= 0; i--)
	{
		// printf("%02X",ScriptPubKey[i]);
		ScriptPubKey_Append[i] = ScriptPubKey[i];
	}

	// printf("\n");

	// printf("ScriptPubKey_Append = ");
	ScriptPubKey_Append[20] = ScriptPubKey_Append[20] & 0x0;

	// for(int i = 20; i >= 0; i--)
	// {
	// 	printf("%02X",ScriptPubKey_Append[i]);
	// }


	// printf("\n\n");
	// printf("               Private Key Size = %d bytes, %d bits \n",sizeof(privkey),sizeof(privkey)*8);
	// printf("(Uncompressed) Public  Key Size = %d bytes, %d bits \n",sizeof(public_key.data),sizeof(public_key.data)*8);
	// printf("(Compressed)   Public  Key Size = %d bytes, %d bits \n",sizeof(compressed_pubkey),sizeof(compressed_pubkey)*8);
	// printf("          ScriptPubKey Key Size = %d bytes, %d bits \n",sizeof(ScriptPubKey),sizeof(ScriptPubKey)*8);
	// printf("   ScriptPubKey Key Append Size = %d bytes, %d bits \n",sizeof(ScriptPubKey_Append),sizeof(ScriptPubKey_Append)*8);
	// printf("\n\n");


	char output[93];
	const char *hrp = "bc";

	const uint8_t *witprog; //ripemd(sha256(pub))

	witprog = ScriptPubKey_Append;
	size_t witprog_len = 20;


	int convert_bench32 = segwit_addr_encode(output,hrp,0,witprog, witprog_len);


	if(convert_bench32 == 0)
	{
		printf("Bench32 convertion failed\n");
	}
	else if(convert_bench32 = 1)
	{
		printf("Bench32 convertion sucessful\n");
	}
	else
	{
		printf("Something terrible has happened!\n");
	}


	// F
	printf("%s\n",output);

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



	printf("Address:       %s\n",output);
	printf("Private Key = ");

	//Print Binary Contents of Private Key
	//privkey[4]
	for(int i = 3; i >=0 ; i--)
	{
		printf("%X",privkey[i]);
	}
	printf("\n");

	printf("\n\n(Compressed)   Public Key  = ");
	//Print Binary Contents of public
	for(int i = 32; i >= 0; i--)
	{
		printf("%02X",compressed_pubkey[i]);
	}

	printf("\n");

	printf("(Uncompressed) Public Key  = ");
	//Print Binary Contents of Public Key
	//public_key.data[64]
	for(int i = 63; i >= 0; i--)
	{
		printf("%02X",public_key.data[i]);
	}

	printf("\n");

	announce_result(1,privkey);

	printf("\n\n");
	printf("               Private Key Size = %d bytes, %d bits \n",sizeof(privkey),sizeof(privkey)*8);
	printf("(Uncompressed) Public  Key Size = %d bytes, %d bits \n",sizeof(public_key.data),sizeof(public_key.data)*8);
	printf("(Compressed)   Public  Key Size = %d bytes, %d bits \n",sizeof(compressed_pubkey),sizeof(compressed_pubkey)*8);
	printf("          ScriptPubKey Key Size = %d bytes, %d bits \n",sizeof(ScriptPubKey),sizeof(ScriptPubKey)*8);
	printf("   ScriptPubKey Key Append Size = %d bytes, %d bits \n",sizeof(ScriptPubKey_Append),sizeof(ScriptPubKey_Append)*8);
	printf("\n\n");

	return 0;
}

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
