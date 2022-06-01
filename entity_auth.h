#ifndef ENTITY_AUTH
#define ENTITY_AUTH

#include "common.h"
#include "crypto.h"

int Entity_Auth(unsigned char * message, size_t size);
int Entity_Entity(unsigned char * msg, size_t size);

#endif