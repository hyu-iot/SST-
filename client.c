#include<stdio.h>
#include<stdlib.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<unistd.h>
#include<string.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/aes.h> 
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>



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
#define SESSION_KEY_REQ_IN_PUB_ENC 20

int padding = RSA_PKCS1_PADDING;

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
    char Sender_len [1] ;
    char Purpose [20] ;
    char Purpose_len [1] ;
};

struct topic Topic;  // Topic declaration;
struct sessionKeyReq SessionKeyReq; // SessionkeyReq declaration;
unsigned char message[15];
unsigned char auth_id[AUTH_ID_LEN];
char sender_req[20] = "net1.client";
char purpose_req[20] = "{\"group\":\"Servers\"}";

void sender()
{
    strcpy(SessionKeyReq.Sender,sender_req);
    memset(SessionKeyReq.Sender_len, sizeof(SessionKeyReq.Sender),1);
}

void purpose()
{
    strcpy(SessionKeyReq.Purpose , purpose_req);
    memset(SessionKeyReq.Purpose_len,sizeof(SessionKeyReq.Purpose),1);
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

unsigned char buf [NONCE_SIZE*2 + NUMKEY + 1 + 20 + 1 + 20]; //buf[20+]
// unsigned char buf [8196]; //buf[20+]

void serializeSessionkeyReq() 
{
    // unsigned char buf [NONCE_SIZE*2 + NUMKEY + 10 + 20]; //buf[20+]
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
        memcpy(buf+NONCE_SIZE*2+NUMKEY,SessionKeyReq.Sender_len,1); // Key_num 4byte
        memcpy(buf+NONCE_SIZE*2+NUMKEY+1,SessionKeyReq.Sender,20); // Key_num 4byte
        memcpy(buf+NONCE_SIZE*2+NUMKEY+1+20,SessionKeyReq.Purpose_len,1); // Key_num 4byte
        memcpy(buf+NONCE_SIZE*2+NUMKEY+1+20+1,SessionKeyReq.Purpose,20); // Key_num 4byte
        
    printf("-- Serialize한 내용 -- \n");
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

RSA * createRSA(unsigned char * key,int public)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1); // 읽기 전용 메모리 만들기 BIO
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    
    /* PEM형식인 키 파일을 읽어와서 RSA 구조체 형식으로 변환 */
    
    if(public) // PEM public 키로 RSA 생성
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    }
    else // PEM private 키로 RSA 생성
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }
    
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }
 
    return rsa;
}

int public_encrypt(unsigned char * data,int data_len, unsigned char *encrypted) 
{
    char publickey[] = "-----BEGIN PUBLIC KEY-----\n"\
                        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAskwWR+7ve/hG/+DDszfN\n"\
                        "DpfUl8hy52udLAUofQZgNkCxH3xkmqoTrlYD/kZBMgpVNU6MWvNZsNsoI9uWHVf3\n"\
                        "2AHa66rThjNu63zuhKeAoKfI0DWtVXD3f6eZJPy2T3spZFNCS5U++ghVKb1HYR9n\n"\
                        "5ctOus8i27w0b+iuAkUuNUHsNicZTf7+/5REdID6hG0TJaHP+a6I+JPR/POoDeeT\n"\
                        "G0FK5F+bhoy5Zf8om42QDMvBP0JexYIKclOngnKQ9QjrfuoF7a8oE8F9p1YqbfJb\n"\
                        "IUt21Hel584Qbx9DlF5FvWXxMxdZ5dEkXIYcbagLvvoKqhxbjIPJeOoGIEA9JwdW\n"\
                        "+wIDAQAB\n"\
                        "-----END PUBLIC KEY-----\n";

    RSA * rsa = createRSA(publickey,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result; // RSA_public_encrypt() returns the size of the encrypted data 
}

int private_decrypt(unsigned char * enc_data,int data_len, unsigned char *decrypted)
{
    char privatekey[] = "-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEpAIBAAKCAQEAskwWR+7ve/hG/+DDszfNDpfUl8hy52udLAUofQZgNkCxH3xk\n"\
"mqoTrlYD/kZBMgpVNU6MWvNZsNsoI9uWHVf32AHa66rThjNu63zuhKeAoKfI0DWt\n"\
"VXD3f6eZJPy2T3spZFNCS5U++ghVKb1HYR9n5ctOus8i27w0b+iuAkUuNUHsNicZ\n"\
"Tf7+/5REdID6hG0TJaHP+a6I+JPR/POoDeeTG0FK5F+bhoy5Zf8om42QDMvBP0Je\n"\
"xYIKclOngnKQ9QjrfuoF7a8oE8F9p1YqbfJbIUt21Hel584Qbx9DlF5FvWXxMxdZ\n"\
"5dEkXIYcbagLvvoKqhxbjIPJeOoGIEA9JwdW+wIDAQABAoIBAQCVinl5la5pJMCv\n"\
"5h1dmGS1Y6TcNTQiY0Ds5dqimhFiD3o/dT6P9iwRoXUx9EzEIqR61EmmEsrcKcQN\n"\
"5yONsvVdx5iM5rcIrOTQP/Vxb2fT10X3U73wlpIPEEvDGO3z1dHOooJNEH1Eim6b\n"\
"VnSiwguLUazTw91xvPWiEt63arypzx1kQtHkYgzZrEP9E54B+K7sofuWANTSONT8\n"\
"7XGHoW0s0NrHZLk/HHQjGx8vB1itqmE1xdPoon1tWSrCDLnPYGZsRsLp19/wHOza\n"\
"m4xGmono3WJuv6oKSKZhtxBW6G+FF1TS4KIhaYLpsKxA+sbrGF5vaPqTj4eNUWno\n"\
"/CMwe5HRAoGBANY6Ublb7TW98xJ1bo4z/hM1NUbGdgp2mRnN+rGrep9bgrZ0dRaI\n"\
"JlGWK4yZuxzELqirGOgvBElomCYmjxU1fHyr2HMigdkEyY+rMv4RywQ+nnLFvwus\n"\
"T1ENKCdO+VHhHQ95v1RL2D3vC9Lmk+NEEGcMCe+MoH4E1zilx6SGY8wZAoGBANUQ\n"\
"NVfdOTbP8FWa1EeiiNzJ6uJGw/3bl8X3NnvYSNEWg+UDPUg4jF3ILsVUu/YeGedr\n"\
"eas0TthUgziKWRT11DGyytwx9yiw/RhDAsvGfay927Mbj5mo6CKrueTkCdIG8SR7\n"\
"ONwNmNh6XJ/4MQBivC0mVaCaCTgMB1SfjEXMaN4zAoGAXMZ46gtTmXifshjFPjRq\n"\
"Dit23SXJrRJbj39S2Gro+eaJnzakFpPz9FVSmttg2z5i7ozahoMGGjx/19XPFWJK\n"\
"fTt2y7XgAfo+yEdeGAXgo//yYsYczJNc7j8CarOa6cjR6wfQwlLuXTQPLNDKrxuk\n"\
"9tuR2fpO7wRtqIyy/x9sTNECgYEAk0nOJnxnBe4/jV4oK5E/nan0NxKGgKJiTFc2\n"\
"keyVgf1XlmRj4947osU1F/MYsO5kJ+fTRzg03TWnNNnm9Sdv1h9sP0ZHPxkDDded\n"\
"QjNoQ5dIHowJ/EaYmwctzf6aj1d/MiIAz5aSt+v2xhtz/HlE7s1WWlzBzL37/1MA\n"\
"TGwffqMCgYARNBQV/FJTpQYch49l8RggZ6NYOIvMZKEflccqgFx6npZ2Wpdmh2Vs\n"\
"hlhWtI2OzrMFPvU83mF4E9i4zQ/UL7Gu2ryFk2T/8FF6/SVK70cP/k7nxGYgDirs\n"\
"vTJxVddWab8n74UzD0oVdSsDJ3DVRk/7RipAFE0y3xNBKtBDcAy21g==\n"\
"-----END RSA PRIVATE KEY-----\n";

    RSA * rsa = createRSA(privatekey,0); 
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}

void printLastError(char *msg)
{
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}

void enc_print(int encrypted_length, unsigned char *encrypted)
{
        printf("\n");

        printf("encrypted length: %d \n", encrypted_length);
        printf("-- encrypted 된 값 -- \n");
        for(int i=0 ; i<sizeof(buf); i++)
        {
            printf(" %x ", encrypted[i]);
        }
        if(encrypted_length == -1) // RSA_public_encrypt() returns -1 on error
        {
            printLastError("Public Encrypt failed ");
            exit(0);
        }
        printf("\n");
        printf("\n");
}
void dec_print(int decrypted_length, unsigned char *decrypted)
{
        printf("\n");

        printf("decrypted length: %d \n", decrypted_length);
        printf("-- decrypted 된 값 -- \n");
        for(int i=0 ; i<sizeof(buf); i++)
        {
            printf(" %x ", decrypted[i]);
        }
        printf("\n");
        printf("\n");
}

void make_degest_msg(unsigned char *dig_enc, unsigned char *encrypted ,int encrypted_length)
{

    SHA256_CTX ctx;
    
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, encrypted, encrypted_length); 
    SHA256_Final(dig_enc, &ctx);    

    // printf("size of digest message : %ld\n",sizeof(dig_enc));
    // printf("message digest: ");
    // for(int i = 0; i<sizeof(dig_enc); i++)
    //     printf("%x ", dig_enc[i]);    
}


char signkey[] = "-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEowIBAAKCAQEA3vjKYGtSzxNhdh/lkM1Ma5bwsxlnqnPr8vG+VCdI6AGCpEjc\n"\
"2L5Fty4lKpUWO/uHZNjX+w5TF9WXL479QbMDjXnEr5+Ro5Hr2s5cxy6DCVl7kM3s\n"\
"LWoeMlMxtuwZ/mIF0/z5jb+5o++pvAVODJk5UccQS/BzDdrxr5lHCEI6CtuP0zsP\n"\
"PpN3z1ZmCQUeJQsHHPMKPanQrCl6f6C7/nbDo6ogEa58P3Xr1RtmgxsIWYRfOeDr\n"\
"g/BTQUP6Z8K9aezJ/hbP770TFeOssGUtqFO4vHeV7THGo8y06BF7kioHGh78LWz5\n"\
"wO52fbbVZ266xzTPEPHn9oIS/3uCzA8R5onDKQIDAQABAoIBAAQSjTe3nhqUIwqS\n"\
"SJIdfdDVP+41f5Q4a83TJoPI9+bs6CLyBb6bsxBGcn1VncNYs79eyosWVuQvjYRb\n"\
"2zpQ97aky7fddT6Eksc7T6x/p/sKvFwHttGZh5WpuVW6+DqSNcMKctBo+Q4KeZIq\n"\
"kqNeRRK+TQjmCmPtZM6tQQPgmcjK8xW9XtsTi+fsp5njAek+ATYe0LQ0CZu/LMF3\n"\
"i31Ronc2swsT+e9TjBAt0QJlKEHcSLRo4N0bnjiRD3LQ1/pH+IO226yDVp3q1tmK\n"\
"hiRt98GDqCH6PwAEG1jdYf9ycbbANpz1rWvLjS3N4lrvmPzBfHDY8nrnGlcwRkTk\n"\
"uv6aAbUCgYEA/rEBNByUAvg9FMobqMlepYjs9uYzABXlryd0lOR1J2vU9ELvDa91\n"\
"/w1u1KxDrZGJ74sow/svMKi7h57i7iVVddCfRzMLdA2SLoNBdixtEJwpfU47ttPU\n"\
"EH9kYUbXugbTRwO3jRibU2szj8ELejFhpT9RpXHL+HLpFhk43LYDbesCgYEA4B4Q\n"\
"qn07xV4kwPugkprITQUnef6M4iuXTynppisW1EixZnR9xYrDh+SScAC5Rgg8nU1I\n"\
"4nUwfXNCgqMrxuaAD5fkvNdsulpYma8XYU4cFYYEmeAcIpOjOzEg1a3R8iPHdZts\n"\
"oL2A6Qm7DrlumoxQO+0hyzZPm+B9lN6uBkgMyjsCgYAXK28amIb2hjK4U3KUtkz/\n"\
"7ibwhxyYo2VTu9klOmtV/L9QwU4SBqZLX6N3gXxeq+DKg/Rfb9hpKtB0lAW8+HR/\n"\
"1UzII2KlWh60UIiCAaSiYDJ+DcHs7fRa09wD5Xf2mmxaB4KJOXXX7uav6zXqFdf2\n"\
"On5o+KM/pOSDeCPuIDjLpQKBgQCySxjFGRX44PlqUYQfvWVF6KjMI5aew0D/aH+J\n"\
"g1QJE7+Vm20HP2pobI2W7ux1602VcoteJQ6rbotl9Dt6Y5tTTGpbVSIZapB7ytBV\n"\
"x9cNxG1aoPChDUTZbS8K7tpLwO0IAdq8UaYBPo2CnECCUMfvtKmiyZUxk7k0OqbF\n"\
"NoJ+SwKBgEwjrJxpWt4ypDvLDkZ94tDhwa5errqePzuLAFyW5x/TyPJKEGFyoUZb\n"\
"UvqBNlf8JpqrQguxm8EMXqT6s6M9jGIReqViTg6GGWBnkipac51R7FY0M2cFDfuR\n"\
"0jBRyAf2JF4VPJYy1ENFaFywO4JgAhpi0KFMJhXh7FspFxLyeF6v\n"\
"-----END RSA PRIVATE KEY-----\n";


int main(int argc, char* argv[])
{
        // TcpCommunication(argc, argv);

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
        

        AuthID();
        AuthNonce();
        numkey();
        sender();
        printf("\n");
        nonce_generator();
        purpose();

        if(message[0] == 0)   //Auth_Hello 받았을 때!
        {
            serializeSessionkeyReq();
        }
        

        unsigned char encrypted[2048] = {};
        unsigned char decrypted[2048] = {};
        unsigned char sigret [1000] = {};
        unsigned int  sigret_Length ;
        unsigned char dig_enc[SHA256_DIGEST_LENGTH];
        // Based on this comment you can encrypt at most 214 bytes using 256 byte RSA key.
        // strlen(plainText로 하면 0인 부분에서 끊겨서 제대로 된 encrypt가 되지 않음)
        // enc 실행
        
        int encrypted_length= public_encrypt(buf,sizeof(buf),encrypted);
        enc_print(encrypted_length,encrypted);        
        
        // enc 잘됐는지 확인!!
        int decrypted_length = private_decrypt(encrypted,encrypted_length,decrypted);
        dec_print(decrypted_length, decrypted);  

        //strlen 을 하게되면 sizeof 보다 넘어갈 시에 \n이 없다면 계속 불러옴!!

        //////////////////sign part////////////////////////
        // make digest message
        make_degest_msg(dig_enc, encrypted, encrypted_length);

        RSA * rsa = createRSA(signkey,0); 

        // // sign!
        int sign_result = RSA_sign(NID_sha256, dig_enc,SHA256_DIGEST_LENGTH,
              sigret, &sigret_Length, rsa);
        if(sign_result ==1)
            printf("sign success \n");

        // // verify!   
        int verify_result = RSA_verify(NID_sha256, dig_enc,SHA256_DIGEST_LENGTH,
              sigret, sigret_Length, rsa);
        if(verify_result ==1)
            printf("verify success\n\n");

        /// enc+sign length 구해서 buffer에 저장
        unsigned char extra_buf[5];
        unsigned int num = encrypted_length + sigret_Length;
        int n = 1;
        while(num > 127)
        {
            extra_buf[n-1] = 128 | num & 127;
            n += 1;
            num >>=7;
        }
        extra_buf[n-1] = num;


        // Total message buffer 설정하고 msg_type부터 넣기!
        unsigned char buffer [1 + n + encrypted_length + sigret_Length ];
        buffer[0] = SESSION_KEY_REQ_IN_PUB_ENC;
        memcpy(buffer+1, extra_buf, n);
        memcpy(buffer+1+n,encrypted, encrypted_length);
        memcpy(buffer + 1 + n + encrypted_length,sigret, sigret_Length);


        printf("sizeof buffer: %ld \n", sizeof(buffer));
        // printf("buffer 의 내용!! \n");
        // for(int i =0 ; i<sizeof(buffer); i++)
        //     printf("%x ", buffer[i]);
        printf("\n");
        

        write(my_sock, buffer,sizeof(buffer));


        close(my_sock); //4번


}