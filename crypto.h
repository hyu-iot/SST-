#ifndef CRYPTO
#define CRYPTO

#include "common.h"

// Crypto spec !

#define DIST_KEY_EXPIRATION_TIME_SIZE 6
#define MAC_KEY_SIZE 32
#define CIPHER_KEY_SIZE 16

typedef struct
{
    unsigned char mac_key[MAC_KEY_SIZE];
    unsigned char cipher_key[CIPHER_KEY_SIZE];
    unsigned char absvalidity[DIST_KEY_EXPIRATION_TIME_SIZE];
    long int start_time;
}distribution_key;

typedef struct
{
    unsigned char key_id[8];
    unsigned char abs_validity[6];
    unsigned char rel_validity[6];
    unsigned char mac_key[32];
    unsigned char cipher_key[16];
    unsigned char nonce[8];
}sessionkey; 

void print_Last_error(char *msg);
int public_encrypt(unsigned char * data,int data_len, unsigned char *encrypted);
int private_decrypt(unsigned char * enc_data,int data_len, unsigned char *decrypted, char *key);
void make_degest_msg(unsigned char *dig_enc, unsigned char *encrypted ,int encrypted_length);
int encrypt_sign(unsigned char *message, size_t size);
void sign_verify(unsigned char * dig, int dig_size, unsigned char *ret, int ret_size);
void dist_key_decrypt(unsigned char * buffer, int index, distribution_key D);
void sess_key_decrypt(unsigned char *buf, int index, sessionkey S, distribution_key D);


#endif