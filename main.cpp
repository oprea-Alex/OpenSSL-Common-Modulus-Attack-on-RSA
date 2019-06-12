#include <stdlib.h>
#include<stdio.h>
#include <string.h>
#include <openssl\bn.h>

#pragma comment (lib,"ws2_32.lib")
#pragma comment (lib,"crypt32")



FILE _iob[] = { *stdin, *stdout, *stderr };
extern "C" FILE * __cdecl __iob_func(void) { return _iob; }



static int _read_from_file(const char *filename, unsigned char **data, unsigned int *len)
{
	if (data == NULL || len == NULL)
		return 0;

	FILE *fp = fopen(filename, "rb");
	if (fp == NULL)
		return 0;

	fseek(fp, 0, SEEK_END);
	*len = (unsigned int)ftell(fp);
	fseek(fp, 0, SEEK_SET);

	*data = (unsigned char *)malloc(*len);

	fread(*data, 1, *len, fp);
	fclose(fp);

	return 1;
}

static int _write_to_file(const char *filename, unsigned char *data, unsigned int len)
{
	if (data == NULL)
		return 0;

	FILE *fp = fopen(filename, "wb");
	if (fp == NULL)
		return 0;

	fwrite(data, 1, len, fp);

	fclose(fp);

	return 1;
}

int extended_gcd(int a, int b, int *x, int *y)
{
	if (a == 0)
	{
		*x = 0;
		*y = 1;
		return b;
	}

	int _x, _y;
	int gcd = extended_gcd(b % a, a, &_x, &_y);

	*x = _y - (b / a) * _x;
	*y = _x;

	return gcd;
}

void get_public_exponents(BIGNUM*& e1, BIGNUM*& e2, BIGNUM*& a, BIGNUM*& b) {

	int bezout1, bezout2;
	int exp1 = 5, exp2 = 7;
	int g = extended_gcd(exp1, exp2, &bezout1, &bezout2);


	BN_set_word(a, (unsigned int)bezout1);
	BN_set_word(b, (unsigned int)abs(bezout2));

	BN_set_word(e1, (unsigned int)exp1);
	BN_set_word(e2, (unsigned int)exp2);
}


void get_ciphertexts(BIGNUM*& c1, BIGNUM*& c2) {

	unsigned int ciph1Len = 0;
	unsigned char* ciph1 = 0;
	_read_from_file("cipher1.in", &ciph1, &ciph1Len);

	unsigned int ciph2Len = 0;
	unsigned char* ciph2 = 0;
	_read_from_file("cipher2.in", &ciph2, &ciph2Len);

	BN_hex2bn(&c1, (const char*)ciph1);
	BN_hex2bn(&c2, (const char*)ciph2);
}

void get_modulus(BIGNUM*& mod) {

	unsigned int nLen = 0;
	unsigned char* modulus = 0;
	_read_from_file("modulus.in", &modulus, &nLen);

	BN_hex2bn(&mod, (const char*)modulus);
}

BIGNUM* exploit_and_get_message(BIGNUM* c1, BIGNUM* c2, BIGNUM* modulus, BIGNUM* a, BIGNUM* b) {

	//the exploit based on common modulus
	//obtain the plaintext m from (c1^a * c2^b) mod n

	BIGNUM* c1PowA = BN_new();
	BIGNUM* c2PowB = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *i = BN_new();
	BN_mod_inverse(i, c2, modulus, ctx);
	BN_exp(c1PowA, c1, a, ctx);
	BN_exp(c2PowB, i, b, ctx);



	BIGNUM* message = BN_new();
	BN_mod_mul(message, c1PowA, c2PowB, modulus, ctx);

	BN_free(c1PowA);
	BN_free(c2PowB);
	BN_free(i);

	return message;
}


void main() {


	BIGNUM *a = BN_new();
	BIGNUM *b = BN_new();
	BIGNUM* e1 = BN_new();
	BIGNUM* e2 = BN_new();
	get_public_exponents(e1, e2, a, b);

	BIGNUM* c1 = BN_new();
	BIGNUM* c2 = BN_new();
	get_ciphertexts(c1, c2);

	BIGNUM* modulus = BN_new();
	get_modulus(modulus);

	BIGNUM* m = exploit_and_get_message(c1, c2, modulus, a, b);



	FILE* fp_msg = fopen("file.out", "wb");
	BN_print_fp(fp_msg, m);//The plaintext is written in HEX and wil need a HEX->ASCII conversion for further read.
	fclose(fp_msg);



	BN_free(a);
	BN_free(b);
	BN_free(e1);
	BN_free(e2);
	BN_free(c1);
	BN_free(c2);
	BN_free(modulus);
	BN_free(m);

	getchar();
}