
#include "crypto.h"



void print_Last_error(char *msg)
{
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}

int public_encrypt(unsigned char * data,int data_len, unsigned char *encrypted) 
{
    FILE *pemFile = fopen("../SST-/sst/iotauth/entity/auth_certs/Auth101EntityCert.pem", "rb");
    X509 *cert = PEM_read_X509(pemFile, NULL, NULL, NULL );
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (pkey == NULL){
        print_Last_error("public key getting fail");
    }
    int id = EVP_PKEY_id(pkey);
    if ( id != EVP_PKEY_RSA ) {
        print_Last_error("is not RSA Encryption file");
    }
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if ( rsa == NULL ) {
        print_Last_error("EVP_PKEY_get1_RSA fail");
    }
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,1);
    return result;
}

int private_decrypt(unsigned char * enc_data,int data_len, unsigned char *decrypted, char *key)
{

    FILE *keyfile = fopen("../SST-/sst/iotauth/entity/credentials/keys/net1/Net1.ClientKey.pem", "rb"); 
    RSA *rsa = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,1);
    return result;
}


void make_degest_msg(unsigned char *dig_enc, unsigned char *encrypted ,int encrypted_length)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, encrypted, encrypted_length); 
    SHA256_Final(dig_enc, &ctx);     
}
// Auth hello
int encrypt_sign(unsigned char *message, size_t size)
{
    unsigned char encrypted[2048];
    unsigned char sigret [1024];
    unsigned char dig_enc[SHA256_DIGEST_LENGTH];
    unsigned int  sigret_Length;

    int encrypted_length= public_encrypt(message,100,encrypted);
    printf("enc length: %d \n",encrypted_length);
    make_degest_msg(dig_enc, encrypted, encrypted_length);
    FILE *keyfile = fopen("../SST-/sst/iotauth/entity/credentials/keys/net1/Net1.ClientKey.pem", "rb"); 
    RSA *rsa = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);
    int sign_result = RSA_sign(NID_sha256, dig_enc,SHA256_DIGEST_LENGTH,
        sigret, &sigret_Length, rsa);
    if(sign_result ==1)
    {
        printf("Sign length: %d\n", sigret_Length);
        printf("Sign success \n");
    }
    
    int buf_len = put_in_buf(message, encrypted_length + sigret_Length);
    memcpy(message+1+buf_len,encrypted, encrypted_length);
    memcpy(message+1+buf_len+encrypted_length ,sigret, sigret_Length);
    return 1+ buf_len +encrypted_length +sigret_Length;
}

void sign_verify(unsigned char * dig, int dig_size, unsigned char *ret, int ret_size)
{
    FILE *pemFile = fopen("../SST-/sst/iotauth/entity/auth_certs/Auth101EntityCert.pem", "rb");
    X509 *cert = PEM_read_X509( pemFile, NULL, NULL, NULL );
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (pkey == NULL){
        print_Last_error("public key getting fail");
    }
    int id = EVP_PKEY_id(pkey);
    if ( id != EVP_PKEY_RSA ) {
        print_Last_error("is not RSA Encryption file");
    }
    RSA *rsa1 = EVP_PKEY_get1_RSA(pkey);
    if ( rsa1 == NULL ) {
        print_Last_error("EVP_PKEY_get1_RSA fail");
    } 

    int verify_result = RSA_verify(NID_sha256, dig ,dig_size,
        ret, ret_size, rsa1);
    if(verify_result ==1)
        printf("auth signature verified \n\n");
}

void dist_key_decrypt(unsigned char * buffer, int index, distribution_key D)
{
    
    unsigned char ret_data[256];
    unsigned char ret_signiture[256];
    unsigned char dig_enc[SHA256_DIGEST_LENGTH];
    slice(ret_data, buffer, index, index+256);
    slice(ret_signiture,buffer,index+256,index+512);
    // verify the signiture data
    make_degest_msg(dig_enc , ret_data,sizeof(ret_data));
    sign_verify(dig_enc,SHA256_DIGEST_LENGTH, ret_signiture, sizeof(ret_signiture));
 
    // decrypt the encrypted data
    FILE *keyfile = fopen("../SST-/sst/iotauth/entity/credentials/keys/net1/Net1.ClientKey.pem", "rb"); 
    RSA *rsa = PEM_read_RSAPrivateKey(keyfile, NULL, NULL, NULL);
    int  dec_length = RSA_private_decrypt(sizeof(ret_data),ret_data,buffer,rsa,1);
    if(dec_length != -1)
    {
        printf("Decryption Success");
    }
    else
    {
        printf("error!");
    }
    printf("decrypted length: %d\n", dec_length);
    printf(" -- decrypted value -- \n");
    print_buf(buffer, dec_length);

    slice(D.absvalidity,buffer,0,DIST_KEY_EXPIRATION_TIME_SIZE);
    slice(D.cipher_key,buffer,DIST_KEY_EXPIRATION_TIME_SIZE+1,
            DIST_KEY_EXPIRATION_TIME_SIZE+1+CIPHER_KEY_SIZE);
    slice(D.mac_key,buffer,DIST_KEY_EXPIRATION_TIME_SIZE+2+CIPHER_KEY_SIZE,
            DIST_KEY_EXPIRATION_TIME_SIZE+2+CIPHER_KEY_SIZE+MAC_KEY_SIZE);

}

void sess_key_decrypt(unsigned char *buf, int index, sessionkey S, distribution_key D)
{

}