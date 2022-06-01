
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

void dist_key_decrypt(unsigned char * buffer, int index, distribution_key *D)
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

    slice(D->absvalidity,buffer,0,DIST_KEY_EXPIRATION_TIME_SIZE);
    slice(D->cipher_key,buffer,DIST_KEY_EXPIRATION_TIME_SIZE+1,
            DIST_KEY_EXPIRATION_TIME_SIZE+1+CIPHER_KEY_SIZE);
    slice(D->mac_key,buffer,DIST_KEY_EXPIRATION_TIME_SIZE+2+CIPHER_KEY_SIZE,
            DIST_KEY_EXPIRATION_TIME_SIZE+2+CIPHER_KEY_SIZE+MAC_KEY_SIZE);
    print_buf(D->mac_key,32);

}

void sess_key_decrypt(unsigned char *buf, int size, sessionkey S[], distribution_key *D)
{
    unsigned char received_tag[MAC_KEY_SIZE];
    unsigned char result[MAC_KEY_SIZE];
    unsigned int result_len = MAC_KEY_SIZE;
    unsigned char *symmetric_data = malloc(size-MAC_KEY_SIZE);
    unsigned char iv[IV_SIZE];
    unsigned char *symmetric_enc = malloc(size-MAC_KEY_SIZE-IV_SIZE);

    slice(symmetric_data,buf,0,size-MAC_KEY_SIZE);
    slice(received_tag, buf, size-MAC_KEY_SIZE, size);
    HMAC(EVP_sha256(), D->mac_key , MAC_KEY_SIZE,
         symmetric_data, size-MAC_KEY_SIZE, result, &result_len);

    if(strncmp((char *)result, (char *) received_tag, result_len) == 0 )
    {
        printf("Hmac success!!! \n");
    }

    AES_KEY enc_key_128;
    slice(iv,symmetric_data,0,IV_SIZE);
    slice(symmetric_enc,symmetric_data,IV_SIZE,size-MAC_KEY_SIZE);
    free(symmetric_data);
    if(AES_set_decrypt_key(D->cipher_key, CIPHER_KEY_SIZE*8, &enc_key_128) < 0){
        printf("AES Decrypt Error!");  
    };
    AES_cbc_encrypt( symmetric_enc, buf,size-MAC_KEY_SIZE-IV_SIZE, &enc_key_128, iv, 0);
    free(symmetric_enc);
    print_buf(buf,256);
    //buf 8 : entity nonce
    int payload_len = payload_length(buf,NONCE_SIZE);
    int buf_len = payload_buf_length(payload_len);
    printf("payload len: %d, buf len: %d\n",payload_len,buf_len );
    printf("Crypto spec: ");
    print_string(buf,NONCE_SIZE+buf_len,NONCE_SIZE+buf_len+payload_len);
    
    int key_num =0;
    for(int i=0; i<KEY_BUF; i++)
    {
        key_num |= buf[NONCE_SIZE + key_num + buf_len+ payload_len + i] <<8*(3-i);
    }
    int index = NONCE_SIZE + buf_len+ payload_len + KEY_BUF;
    printf("key num : %d\n", key_num);
    get_sessionkey(buf, index, key_num, S);
}

void get_sessionkey(unsigned char *buf, int index, int key_num, sessionkey S[])
{
    printf("index : %d\n", index);
    int cur_index_par =0;
    cur_index_par += index;
    for(int i=0;i<key_num;i++)
    {
        slice(S[i].key_id,buf,cur_index_par,cur_index_par+KEY_ID_SIZE);
        long int key_id = read_variable_UInt(buf,cur_index_par , KEY_ID_SIZE);
        printf("key id : %ld\n", key_id);
        cur_index_par += KEY_ID_SIZE;
        slice(S[i].abs_validity,buf,cur_index_par,cur_index_par+KEY_EXPIRATION_TIME_SIZE);
        cur_index_par += KEY_EXPIRATION_TIME_SIZE;
        slice(S[i].rel_validity,buf,cur_index_par , cur_index_par+ KEY_EXPIRATION_TIME_SIZE);
        cur_index_par += KEY_EXPIRATION_TIME_SIZE+1;
        slice(S[i].cipher_key,buf,cur_index_par,cur_index_par+CIPHER_KEY_SIZE);
        cur_index_par += CIPHER_KEY_SIZE+1;
        slice(S[i].mac_key,buf,cur_index_par,cur_index_par+MAC_KEY_SIZE);
        cur_index_par += MAC_KEY_SIZE;
    }
}