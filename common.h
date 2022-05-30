#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/aes.h> 
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/hmac.h>
#include <pthread.h>

// //message type//
// #define AUTH_HELLO: 0,
// #define ENTITY_HELLO: 1,
// #define AUTH_SESSION_KEY_REQ: 10,
// #define AUTH_SESSION_KEY_RESP: 11,
// #define SESSION_KEY_REQ_IN_PUB_ENC: 20,
// #define SESSION_KEY_RESP_WITH_DIST_KEY: 21,    // Includes distribution message (session keys)
// #define SESSION_KEY_REQ: 22,        // Distribution message
// #define SESSION_KEY_RESP: 23,        // Distribution message
// #define SKEY_HANDSHAKE_1: 30,   //client 가 auth에게 보낼때
// #define SKEY_HANDSHAKE_2: 31,
// #define SKEY_HANDSHAKE_3: 32,
// #define SECURE_COMM_MSG: 33,
// #define FIN_SECURE_COMM: 34,
// #define SECURE_PUB: 40,
// #define MIGRATION_REQ_WITH_SIGN: 50,
// #define MIGRATION_RESP_WITH_SIGN: 51,
// #define MIGRATION_REQ_WITH_MAC: 52,
// #define MIGRATION_RESP_WITH_MAC: 53,
// #define AUTH_ALERT: 100


void nonce_generator(unsigned char * nonce_buf, int size_n) ;
void slice(unsigned char * des_buf, unsigned char * buf, int a, int b );
int payload_buf_length(int b);
int payload_length(unsigned char * message, int b);
void print_buf(unsigned char * print_buffer, int n);

#endif