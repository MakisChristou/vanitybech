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


	printf("\n\n               Private Key = ");

	//Print Binary Contents of Private Key
	//privkey[4]
	for(int i = 3; i >=0 ; i--)
	{
		printf("%X",privkey[i]);
	}

	
	printf("\n\n(Uncompressed) Public Key  = ");
	//Print Binary Contents of Public Key
	//public_key.data[64]
	for(int i = 63; i >= 0; i--)
	{
		printf("%02X",public_key.data[i]);
	}


	unsigned char compressed_pubkey[33];
	
	size_t  var = 33;   		/* actual variable declaration */
	size_t  *outputlen;        /* pointer variable declaration */
	outputlen = &var;  		/* store address of var in pointer variable*/

	secp256k1_ec_pubkey_serialize(sec_ctx,compressed_pubkey,outputlen,&public_key,SECP256K1_EC_COMPRESSED);
	

	printf("\n\n(Compressed)   Public Key  = ");
	//Print Binary Contents of public
	for(int i = 32; i >= 0; i--)
	{
		printf("%02X",compressed_pubkey[i]);
	}

	printf("\n\n");


	int valid_private_key = secp256k1_ec_seckey_verify(sec_ctx,&privkey);

	if(valid_private_key == 0)
	{
		printf("Invalid Private Key!\n");
	}
	else if(valid_private_key == 1)
	{
		printf("Valid Private Key!\n");
	}
	else
	{
		printf("Something terrible has happened!\n");
	}
	



	// 32 byte 256bit message to be signed
	const unsigned char hashed_message[32] = "hello";

	secp256k1_ecdsa_signature signature;

	// Sign Message
	secp256k1_ecdsa_sign(sec_ctx,&signature,hashed_message,&privkey,NULL,NULL);



	// Verify valid sinature
	int valid_signature = secp256k1_ecdsa_verify(sec_ctx,&signature,hashed_message,&public_key);
    

	if(valid_signature == 0)
	{
		printf("Invalid Signature!\n");
	}
	else if(valid_signature == 1)
	{
		printf("Valid Signature!\n");
	}
	else
	{
		printf("Something terrible has happened!\n");
	}




	/* Hash Compressed public key */
    sha256_hash(rmd_block, compressed_pubkey);
    rmd160_hash(ScriptPubKey, rmd_block);

	printf("\n\n");
	printf("ScriptPubKey          = ");


	for(int i = 19; i >= 0; i--)
	{
		printf("%02X",ScriptPubKey[i]);
		ScriptPubKey_Append[i] = ScriptPubKey[i];
	}

	printf("\n");

	printf("ScriptPubKey_Append = ");
	ScriptPubKey_Append[20] = ScriptPubKey_Append[20] & 0x0;

	for(int i = 20; i >= 0; i--)
	{
		printf("%02X",ScriptPubKey_Append[i]);
	}


	printf("\n\n");
	printf("               Private Key Size = %d bytes, %d bits \n",sizeof(privkey),sizeof(privkey)*8);
	printf("(Uncompressed) Public  Key Size = %d bytes, %d bits \n",sizeof(public_key.data),sizeof(public_key.data)*8);
	printf("(Compressed)   Public  Key Size = %d bytes, %d bits \n",sizeof(compressed_pubkey),sizeof(compressed_pubkey)*8);
	printf("          ScriptPubKey Key Size = %d bytes, %d bits \n",sizeof(ScriptPubKey),sizeof(ScriptPubKey)*8);
	printf("   ScriptPubKey Key Append Size = %d bytes, %d bits \n",sizeof(ScriptPubKey_Append),sizeof(ScriptPubKey_Append)*8);
	printf("\n\n");


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

	
	


	return 0;
}
