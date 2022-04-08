#include <stdio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>

#define type(x) _Generic((x),                                                     \
        _Bool: "_Bool",                  unsigned char: "unsigned char",          \
         char: "char",                     signed char: "signed char",            \
    short int: "short int",         unsigned short int: "unsigned short int",     \
          int: "int",                     unsigned int: "unsigned int",           \
     long int: "long int",           unsigned long int: "unsigned long int",      \
long long int: "long long int", unsigned long long int: "unsigned long long int", \
        float: "float",                         double: "double",                 \
  long double: "long double",                   char *: "char *",                 \
       void *: "void *",                         int *: "int *",                  \
      default: "unknown")

struct topic
{
    char  group[10];
    char  pubTopic[10];
    char  subTopic[10];
};

struct sessionKeyReq
{
    unsigned char Auth_nonce[8] ;
    unsigned char Entity_nonce[8] ;
    int NumKeys ;
    char Sender [10] ;
    char Purpose [10] ;
};

struct topic Topic;  // Topic declaration;
struct sessionKeyReq SessionKeyReq; // SessionkeyReq declaration;

void sender()
{
    strcpy(SessionKeyReq.Sender,"net1.client");
}

void purpose()
{
    strcpy(Topic.group , "group");
    strcpy(Topic.pubTopic , "pubTopic");
    strcpy(Topic.subTopic , "subTopic");
}

void nonce_generator()  // nonce generator;
{
    unsigned char buffer[8];
    int length = 8;
    RAND_bytes(buffer,length);
    printf("Random Entity Number = ");
    for(int i=0;i<8; i++)
        {
        printf("%x ", buffer[i]);
        SessionKeyReq.Entity_nonce[i] = buffer[i];
        }
    printf("\n");
}    


void serializeSessionkeyReq()
{
    SessionKeyReq.NumKeys = 1;
    if(SessionKeyReq.Auth_nonce == NULL || SessionKeyReq.Entity_nonce == NULL || 
    SessionKeyReq.NumKeys == Null || SessionKeyReq.Purpose == NULL ||  SessionKeyReq.Sender == NULL)
    {
        printf("'Error: SessionKeyReq nonce or replyNonce '
            + 'or purpose or numKeys is missing.'");
    }
    
}

int main(int argc, char* argv[])
{
    nonce_generator();
    purpose();


    return 1;
}
