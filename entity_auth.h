#ifndef ENTITY_AUTH
#define ENTITY_AUTH

#include "common.h"
#include "crypto.h"

int Entity_Auth(unsigned char * message, size_t size);
int Handshake1(unsigned char * msg, size_t size);
int Handshake2(unsigned char * msg, size_t size);
void send_message(int my_sock);
void *receive_message(void *multiple_arg) ; 

#endif