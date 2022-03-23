#include<stdio.h>
#include<stdlib.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<unistd.h>
#include<string.h>
#include <openssl/rand.h>
#include <openssl/err.h>



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

#define AUTH_ID_LEN 4
#define NUMKEY 4
#define NONCE_SIZE 8

struct topic
{
    char  group[10];
    char  pubTopic[10];
    char  subTopic[10];
};

struct sessionKeyReq
{
    unsigned char Entity_nonce[NONCE_SIZE] ;
    unsigned char Auth_nonce[NONCE_SIZE] ;
    unsigned char NumKeys[4] ;
    char Sender [20] ;
    char Purpose [10] ;
};

struct topic Topic;  // Topic declaration;
struct sessionKeyReq SessionKeyReq; // SessionkeyReq declaration;
unsigned char message[15];
unsigned char auth_id[AUTH_ID_LEN];

void sender()
{
    strcpy(SessionKeyReq.Sender,"net1.client");
}

void purpose()
{
    strcpy(SessionKeyReq.Purpose , "group");

}
void numkey()
{
    memset(SessionKeyReq.NumKeys,0,sizeof(SessionKeyReq.NumKeys));
    SessionKeyReq.NumKeys[3] = 1;
}

void AuthID()
{
    for(int i =0 ; i<AUTH_ID_LEN; i++)
    {       
        auth_id[i] = message[i+2]; 
    }
}
void AuthNonce()
{
    for(int j = 0; j<sizeof(message)-(AUTH_ID_LEN+2)-1;j++)
    {
        SessionKeyReq.Auth_nonce[j] = message[AUTH_ID_LEN+2+j];
    }
}
void nonce_generator()  // nonce generator;
{
    unsigned char buffer[NONCE_SIZE];
    int length = NONCE_SIZE;
    RAND_bytes(buffer,length);
    printf("Random Entity Number = ");
    for(int i=0;i<NONCE_SIZE; i++)
        {
        printf("%x ", buffer[i]);
        SessionKeyReq.Entity_nonce[i] = buffer[i];
        }
    printf("\n");
}    


void serializeSessionkeyReq() 
{
    unsigned char buf [NONCE_SIZE*2 + NUMKEY]; //buf[20]
    if(SessionKeyReq.Entity_nonce == NULL || SessionKeyReq.Auth_nonce == NULL || 
    SessionKeyReq.Sender == NULL || SessionKeyReq.Purpose == NULL ||  SessionKeyReq.NumKeys == NULL)
    {
        printf("Error: SessionKeyReq nonce or replyNonce or purpose or numKeys is missing.");
    }
    
    else
    {
        memcpy(buf,SessionKeyReq.Entity_nonce, NONCE_SIZE); //Entity_nonce
        memcpy(buf+NONCE_SIZE,SessionKeyReq.Auth_nonce,NONCE_SIZE); //Auth_nonce
        memcpy(buf+NONCE_SIZE*2,SessionKeyReq.NumKeys,NUMKEY); // Key_num 4byte
        

        for(int i=0; i<sizeof(buf);i++)
            printf(" %x ", buf[i]);
    }
    printf("\n");
}


void TcpCommunication(int argc, char* argv[]) // TCP Connection(client)
{
    int my_sock;
    struct sockaddr_in serv_addr;
    int str_len;
    if(argc != 3)
    {
        printf("%s <IP> <PORT>\n", argv[0]);
        exit(1);
    }
    my_sock = socket(PF_INET,SOCK_STREAM,0); //1번
    if(my_sock == -1)
        printf("socket error \n");
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr=inet_addr(argv[1]);
    serv_addr.sin_port=htons(atoi(argv[2]));

    if(connect(my_sock,(struct sockaddr*)&serv_addr,sizeof(serv_addr))==-1) //2번
        printf("connect error\n");
    memset(message,0x00,sizeof(message));
    str_len = read(my_sock,message,sizeof(message)-1); //3번
    if(str_len==-1)
        printf("read error\n");
    if(message[0] == 0)
        printf("Received AUTH_HELLO Message!!! \n");
        printf("Receiving message from Auth : ");
    for(int i=0; i<str_len ; i++)
    {
        printf("%x ",message[i]);
    }
    close(my_sock); //4번
}
int main(int argc, char* argv[])
{
        TcpCommunication(argc, argv);
        AuthID();
        AuthNonce();
        numkey();
        printf("\n");
        nonce_generator();
        purpose();

        if(message[0] == 0)   //Auth_Hello 받았을 때!
        {
            serializeSessionkeyReq();
        }
            
    
}

