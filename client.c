#include<stdio.h>
#include<stdlib.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<unistd.h>
#include<string.h>
#include<stdint.h>
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
#define DIST_KEY_EXPIRATION_TIME_SIZE 6
#define SESSION_KEY_ID_SIZE 8
#define SESSION_KEY_EXPIRATION_TIME_SIZE 6
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
char sender_req[] = "net1.client";
char purpose_req[] = "{\"group\":\"Servers\"}";

int read_variable_UInt(unsigned char * buf,int offset, int byteLength)
{
    int num =0;
    unsigned long int sum =1LU;
    for(int i =0; i<byteLength;i++)
    {
        num |= buf[offset+i]<< 8*(byteLength-1-i);
    }
    return num;
    
}

void make_time(unsigned char * buf, int index, int byte_length)
{
    unsigned long int num_valid =1LU;
    for(int i =0; i<byte_length;i++)
        {
        unsigned long int num =1LU << 8*(byte_length-1-i); //LU 안써주면 인식을 못함.
        num_valid |= num*buf[index+i];
    }
    printf("abs_valid : %ld\n", num_valid);
    num_valid = num_valid/1000; // 받은 자료는 milisecond로 되어있어서 변환

    struct tm *it; 
    it =localtime(&num_valid); 

    printf("%04d-%02d-%02d %02d:%02d:%02d\n",it->tm_year +1900 , it->tm_mon + 1, it->tm_mday , it->tm_hour, it->tm_min, it->tm_sec
    );
}
void print_buf(unsigned char * buffer, int n)
{
    for(int i=0 ; i<n; i++)
        printf("%x ", buffer[i]);
    printf("\n");
}

void slice(unsigned char * des_buf, unsigned char * buf, int a, int b )
{
    for(int i=0;i<b-a;i++)
    {
        des_buf[i] = buf[a+i];
    }
}
void sender()
{
    strcpy(SessionKeyReq.Sender,sender_req);
    memset(SessionKeyReq.Sender_len, strlen(SessionKeyReq.Sender),1);
}

void purpose()
{
    strcpy(SessionKeyReq.Purpose , purpose_req);
    memset(SessionKeyReq.Purpose_len,strlen(SessionKeyReq.Purpose),1);
}

void numkey()
{
    memset(SessionKeyReq.NumKeys,0,sizeof(SessionKeyReq.NumKeys));
    SessionKeyReq.NumKeys[3] = 3;
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
        memcpy(buf+NONCE_SIZE*2+NUMKEY+1,SessionKeyReq.Sender,strlen(SessionKeyReq.Sender)); // Key_num 4byte
        memcpy(buf+NONCE_SIZE*2+NUMKEY+1+strlen(SessionKeyReq.Sender),SessionKeyReq.Purpose_len,1); // Key_num 4byte
        memcpy(buf+NONCE_SIZE*2+NUMKEY+1+strlen(SessionKeyReq.Sender)+1,SessionKeyReq.Purpose,strlen(SessionKeyReq.Purpose)); // Key_num 4byte
        
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
char publickey[] = "-----BEGIN PUBLIC KEY-----\n"\
                        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxhChIBXNUdx7v/Js++Ki\n"\
                        "vH6Jok1+Hwo6E07yZBS7UPR0Mp3Rl1u1a3geVcm93apUF187ul5BTuCmynUtKrsd\n"\
                        "qOjnrco+TMNoHhM4+fHgO5PbAgnzKwXSnGzJgw/Z5OSUTyK6zypONKNsvMY01rm7\n"\
                        "2KaYN7k1N9HbNMLxaye0/qS56iEXCOct3iR/xUR7ChYl2xaci7AFIA+9PyfirSEt\n"\
                        "mxikQ4PL6PB053VHcts6N/zE4rMa0BTB89Q2BuHnvyWSyhKbSW+mgkeHjAnxjGrb\n"\
                        "gzo72Pm55FSwgFXKeLpK85p0jaZEEjQ+Ui/qC6mWP7R67UxrjKieng38aLos4GUK\n"\
                        "xwIDAQAB\n"\
                        "-----END PUBLIC KEY-----\n";
            
char privatekey[] = "-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEowIBAAKCAQEAxhChIBXNUdx7v/Js++KivH6Jok1+Hwo6E07yZBS7UPR0Mp3R\n"\
"l1u1a3geVcm93apUF187ul5BTuCmynUtKrsdqOjnrco+TMNoHhM4+fHgO5PbAgnz\n"\
"KwXSnGzJgw/Z5OSUTyK6zypONKNsvMY01rm72KaYN7k1N9HbNMLxaye0/qS56iEX\n"\
"COct3iR/xUR7ChYl2xaci7AFIA+9PyfirSEtmxikQ4PL6PB053VHcts6N/zE4rMa\n"\
"0BTB89Q2BuHnvyWSyhKbSW+mgkeHjAnxjGrbgzo72Pm55FSwgFXKeLpK85p0jaZE\n"\
"EjQ+Ui/qC6mWP7R67UxrjKieng38aLos4GUKxwIDAQABAoIBADLUg7VLQxUWI4Ag\n"\
"RA3knOUJCGNpxctLgZoA8b3zgBsHkWaIEAjrFUUOX6KekqZ3lvskipyKofIPP17H\n"\
"8Z58xODbXNHCDHkA0RCe2El05JoFmPgN+6T36pQQayrCf6X5b4JbpFuUPNvPcRGF\n"\
"QHw20FmKb5glZN39cmc4/GIGn7GVurv7qC2JF5m3raLvMcXyJR+6xpKrV+VX5rv5\n"\
"JOUx7BBx6GF2LxY9o71RbKUNy084wEQ2alRzGgQ7KnkM/208Wn+B0vCP0XDT6v3H\n"\
"Xo+EZW1pgX3+IU9kvgW2HIPbZUEpdPuxKSkoZ33ok76VxfNy0OTy5y5qZLQtyS26\n"\
"4UWuiIkCgYEA9tVz30pJns5agaQ1iogz5HJ36sGEuwjacCETpmTZjxYFyun1kjip\n"\
"WuT9TDkaJ6I4kz+p2Xq1AB77gOy1WUcaN1l6mF1pR5TUNgJxjB7MM3n1+N/aAv82\n"\
"Z06UoiZLnyz4Ef3JMNNgSeJsheeYPbcMfIlwfqIlenELAsGRz4Ez3y0CgYEAzWuN\n"\
"LOOg58WZJLw1FmPWywmsbzEMXgEcTq/pgzD20qVP13y81quYCATqr7zrysXNdLsm\n"\
"n42EbrCeN9TCeZUS7Q9jap2vy13SHe2XS43vMN/1TBFQzBMRwLePKy8bIxlhIYFy\n"\
"fE9wx+kmEsxL2MQwSp6s95DaP6QL8zjOLlStakMCgYBEu1FFpwDzCJDpMpl6Fs0k\n"\
"Wr+LjhFwp1l0CbHYDpMKJd69DwLDkaWO2t6xf+EJkkFgt0SLe4C1JOtxjfg9gPAK\n"\
"446gqLotJYMl+u41T0obN2XHxEWHuhsjDx2SPUmnbDUzhVClmOZiDHudmcypurPu\n"\
"ZbL+gBYhjyK6xL3eYyLXjQKBgQDK8NhWYsQSdkrn2fBwoE4R5QqwBzr6nApFStFd\n"\
"xL/0N1F7yEYfpwLZ2VGqMPCaMXTbQBHWS09ss5x79/vxde9uuGc1a3fDaHsvCg0Q\n"\
"nbaTCI8kiW7TTnuZcz9EIJOkx2wIWASs/yaiuZndtGuySZCUB9NF+ZtEiGMt9Q7t\n"\
"AscYVQKBgCRIkf2VdpwywLMm63Xde++VtuAMNsDY3Z0kO1mnbd5EBZdCdLkaU4Rc\n"\
"maOXLO+GxhFoncrD7dQwmqJkRo8o9iAnKKhgDycPs5OTxVjRTFc2IJw6QWqBKO9H\n"\
"UK+coIjyTzKlLYcXc49Uxj91IVmMP3E95JhlHGu0zPriTS/OBzfE\n"\
"-----END RSA PRIVATE KEY-----\n";


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
    RSA * rsa = createRSA(publickey,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result; // RSA_public_encrypt() returns the size of the encrypted data 
}

int private_decrypt(unsigned char * enc_data,int data_len, unsigned char *decrypted, char *key)
{

    RSA * rsa = createRSA(key,0); 
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
        for(int i=0 ; i<decrypted_length; i++)
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
}


char signkey[] = "-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEogIBAAKCAQEAwOIkSI/ljx7btBFPqhl4MmRycoUhfprNumtYhEgwVq/xdjCm\n"\
"O/mL6DNxuCwT29/FkeGm0iFzpvOSzWC4ULw2UYz5Ydp1Bh1b/6fByAgUTbHD19rg\n"\
"EkVbicnERtrBlb63rXme9kaOF0xhWxRRmIFhXBmivzVGcIwrD55Uv3Ou7tT7fmMw\n"\
"rY1Mj5bWU4ya4B4N9ysCL1lanMVy1drsuijoRZMjCOlQFNSj7BmpqHCnAWoXKKrT\n"\
"0TZ7pFYeu/ryr4JgLvXnr37RHVR0gagItuMaaxt2feAQ/INX7Sc3MpmMa6Wwmv0L\n"\
"8dJAHlL0fqsxaDMGtip20gcWxlVsKmkKjYdP/QIDAQABAoIBABl4Qy5JwhhqDLz0\n"\
"ZD6j6llNJke1CL09F9l7/05IcgmgZhQjTHAy/aSF1ohpWZ35KI+g6nRo8mqjU0lH\n"\
"ck9G6y1NnkirnjRWgCV8M3yEhJnV1XSVdG01N2c0e3SXwmRRsNN5ceI3Yt/0uA5c\n"\
"2oF25DJTOEhjco++EpmXYL1/OyRSRFYiRA9UmTPjGyOU2X4uG3jlyXa++JQQ6MYP\n"\
"iCHmH1Mdighnb008RttF9m55X+RMAw9IPqCigzaKCOEmOkNDA97PlVdslIolN2uf\n"\
"fsWkMQzTktMpuDMlieyVyCd5zu38isdoq2Si1+ICQ20TNDQjRUEzScSCv6Jr8grs\n"\
"tWYpEoECgYEA+9EKvvcDvZyBqL6elsojPp6/r8iIu1+hnbParj5aGbwNVReZuzyh\n"\
"ChOUZfxlikygV7AQfdf5xM0LjvvFQZkBlNOMaZ/HCBmbWTHirzIH9I7qbU4N/puE\n"\
"zOj3P40fn1tZqySHAKDMv4c29JTYyvm/eih8hjXm3MavgyJSrKZ1Y60CgYEAxBZ2\n"\
"BSj/wEcGxV/rcK3sU0ABtFxFXxM1UfBalLOXZMaNwe8jN7OXhnQYlwU1WA6KsuPi\n"\
"/bwllflkQXFP6yRtiGOm5kcJukLqss3hUoEKhG6pYnFMYaHYWdkQ4nzkK+a4gR2d\n"\
"L8gcQ83j7fKAEOaRkBbdAVvrF/HvQley9nWUp5ECgYAmi+lJMiawb7SpUASWsHqU\n"\
"q1hMYDYN+KWUrmNbKNBCADdKP0KZFr7P/A9LTUd91Bz3T0w290iUh46tZHzdfb5w\n"\
"ObHUuVCOPN062hgJGW9+UCIyeTBLOSMq+r5eTAv7KNChEgZYYkT1TI1tAxvsdi6J\n"\
"VIk7QiUExqU3PZnKM/DkQQKBgBhaHcAYTmLHr1yVw/yTbPUNzuhiSS88iHOroOQ0\n"\
"xYl7ayF5nGsPf7Lv+hnPSMetzqXWzVrrodNVTJEgDGfMd1nn3lNc4SVjqBgan3AK\n"\
"nI7D239hSLYbTm4iGgm2rvOQzLskPWAwvungyPzFEAiJSeyWGk5P5wtrPWaE07Ht\n"\
"+k8xAoGABHF+kzJbKAZ4RLUYkBLB1vd7Dlb/VFJEjgbJ0ntWOxcUY2DIqkmKITOU\n"\
"1TjBqhaMMP1IcEP9Uo27XJH2wjfg063n48/BUWCic7P92QwqH2sWdZEtM8bMhy9/\n"\
"eroDJM9GZbJe8Ezn2wkFCiiyRNfo5Tm9S3BXwi+qMHT8PUTygFY=\n"\
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
        int decrypted_length = private_decrypt(encrypted,encrypted_length,decrypted,privatekey);
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
        ///////sigret_Length =256;
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
        printf("buffer 의 내용!! \n");
        for(int i =0 ; i<sizeof(buffer); i++)
            printf("%x ", buffer[i]);
        printf("\n");
        
        write(my_sock, buffer,sizeof(buffer));


        unsigned char message[2000];
        
        memset(message,0x00,sizeof(message));
        str_len = read(my_sock,message,sizeof(message)-1); //3번
        if(str_len==-1)
            printf("read error\n");
        ////////
        
        if(message[0] == 21)
        {   
            printf("\nreceived session key response with distribution key attached! \n");
            printf("Receiving message from Auth : \n");
            int num =0;
            int message_length;
            printf("\n\n");
            for (int i =0; i<sizeof(message)&& i<5; i++)
            {
                num |= (message[1+i]& 127) <<(7 * i);
                if((message[1+i]&128) == 0 )
                {
                    i+= 1;
                    message_length = i;
                    printf("num = %d, payload_len = %d \n", num,i);
                    break;
                }
            }
            unsigned char payload[num];
            for(int i = 0; i<num; i++)
            {
                payload[i] = message[i+1+message_length];
            }
            //distributionkeybuf 512개
            unsigned char distribution_key[512];
            memcpy(distribution_key, payload,sizeof(distribution_key));
            //sessionkeyBuf
            int session_key_len = num-sizeof(distribution_key); 
            unsigned char session_key[session_key_len];
            // 이 길이는 sessionkeyreq에서 key의 개수에따라 다름 ex) 1개 -176, 3개 - 320
            printf("sessionkey_buf 길이 : %ld\n", sizeof(session_key)); 
            for(int i = 0 ; i<session_key_len; i++)
            {
                session_key[i] = payload[i+sizeof(distribution_key)]; 
            }
            unsigned char ret_data[256];
            unsigned char ret_signiture[256];

            memcpy(ret_data,distribution_key,256);
            for(int i = 0 ; i<256; i++)
            {
                ret_signiture[i] = distribution_key[256+i];
            }
            //////Verify 하려면 무조건 다시 digest 시켜줘야 함!!!
            RSA * rsa1 = createRSA(publickey,1); 

            unsigned char dig_enc[SHA256_DIGEST_LENGTH];
            make_degest_msg(dig_enc , ret_data,sizeof(ret_data) );
            int verify_result = RSA_verify(NID_sha256, dig_enc ,sizeof(dig_enc),
              ret_signiture, sizeof(ret_signiture), rsa1);
            if(verify_result ==1)
                printf("auth signature verified \n\n");

            unsigned char dec_buf[100] = {};
            // dec 길이는 56 나옴
            RSA * rsa = createRSA(signkey,0); 
            int decrypted_length = private_decrypt(ret_data,sizeof(ret_data),dec_buf,signkey);
            dec_print(decrypted_length, dec_buf);

            // parseDistributionKey 나누기!!

            int cipher_key_size,mac_key_size, cur_index;
            unsigned char absValidity[DIST_KEY_EXPIRATION_TIME_SIZE];
            cur_index = DIST_KEY_EXPIRATION_TIME_SIZE;

            memcpy(absValidity, dec_buf,cur_index);
            
            // unsigned to int         
            cipher_key_size =(int)dec_buf[cur_index];

            printf("cipher_key_size %d\n", cipher_key_size);  //   16나옴
            unsigned char cipher_key_value[cipher_key_size];
            cur_index +=1;
            slice(cipher_key_value,dec_buf,cur_index,cipher_key_size+cur_index);
            cur_index += cipher_key_size;
            mac_key_size =(int)dec_buf[cur_index];
            // printf("%d ", mac_key_size); //  20나옴
            unsigned char mac_key_value[mac_key_size];
            cur_index +=1;
            for(int i=0; i<mac_key_size;i++)
            {
                mac_key_value[i] = dec_buf[i+cur_index];
                printf("%x ", mac_key_value[i]);
            }

            printf("\n");

            // session_key, absValidity, cipher_key_value, mac_key_value;
            //symmetricDecryptAuthenticate 
            int mac_size = 32; // sha256일 때, 32 , SHA1 일 때, 20
            unsigned char symmetric_data[session_key_len -mac_size];
            unsigned char received_tag[mac_size];
            printf("symm_data len: %ld , receiv_tag len: %ld \n", sizeof(symmetric_data),sizeof(received_tag));
            slice(symmetric_data,session_key,0,session_key_len - mac_size);
            slice(received_tag,session_key,session_key_len - mac_size,session_key_len);

            // Hmac
            //mac_key_value 이용
            unsigned char  result[32];
            unsigned int result_len = 32;
            unsigned char hmac[32];
            HMAC(EVP_sha256(),mac_key_value , sizeof(mac_key_value), symmetric_data, sizeof(symmetric_data), result, &result_len);

            printf("size of result : %ld\n", sizeof(result));
            printf("size of received tag : %ld\n", sizeof(received_tag));
            
            slice(hmac,result,0,sizeof(hmac));
            if(strncmp((char *)hmac, (char *) received_tag, sizeof(hmac)) == 0 )
            {
                printf("Hmac success!!! \n");
            }

            // IV , CBC mode
            int iv_size =16;
            AES_KEY enc_key_128;
            unsigned char iv[iv_size]; //16
            unsigned char enc_symmetric_cipher[sizeof(symmetric_data)-iv_size];
            printf("size of encrypted message : %ld\n", sizeof(enc_symmetric_cipher));

            unsigned char dec[1000];
            slice(iv,symmetric_data,0,iv_size);
            slice(enc_symmetric_cipher,symmetric_data,iv_size,sizeof(symmetric_data));
            // cipher_key_value는 aes_128_key, iv는 iv - 둘 다 buffer size 16
            //

            if(AES_set_decrypt_key(cipher_key_value, sizeof(cipher_key_value)*8, &enc_key_128) < 0){
            // print Error  
            }; 
            AES_cbc_encrypt( enc_symmetric_cipher, dec,
                     sizeof(enc_symmetric_cipher), &enc_key_128,
                     iv, 0);
            

            //parseSessionKeyResp(buf) == dec_data
            unsigned char dec_data[256];
            slice(dec_data, dec, 0, sizeof(dec_data));
            ///replynonce 가져가는 부분!!!!
            unsigned char resp_reply_nonce[NONCE_SIZE];
            slice(resp_reply_nonce, dec_data,0,NONCE_SIZE);
            // unsigned char resp_ret;

            int resp_num =0;
            int resp_message_length;
            printf("\n");
            
            for (int i =0; i<sizeof(dec_data)&& i<5; i++)
            {
                resp_num |= (dec_data[NONCE_SIZE +i]& 127) <<(7 * i);
                if((dec_data[NONCE_SIZE+i]&128) == 0 )
                {
                    i+= 1;
                    resp_message_length = i;
                    printf("num = %d, payload_len = %d \n", resp_num,resp_message_length);
                    break;
                }
            }
            //dec_data는 entity_nonce 8개 , 그 후 개수 39개를 나타내는 버퍼 1개, crypto spec 39개 0 0 0 3 => 3개
            printf("\n\n");
            for(int i =0 ; i<sizeof(dec_data);i++)
                printf("%d ", dec_data[i]);
            printf("\n\n");
            //NONCE_SIZE + resp_message_length(9)부터 NONCE_SIZE + resp_message_length+strLen 까지

            // cryptoSpec 선언하는 부분!!!!
            int strLen = resp_num; // 39
            unsigned char resp_str[strLen];
            printf("crypto spec : ");
            for (int i; i<strLen;i++)
            {
                printf("%c", (dec_data[9+i]));
                resp_str[i] = dec_data[9+i];
            }
            printf("\n");

            int resp_session_length = 0;
            for(int i=0; i<4; i++)
            {
                resp_session_length |= dec[NONCE_SIZE + resp_message_length+ strLen+i] <<8*(3-i);
            }
            printf("length: %d\n\n" ,resp_session_length);
            // parseSessionkey(buf) 에서 parse_sessionkey 가 buf에 해당
            unsigned char parse_sessionkey[sizeof(dec_data) - 52]; // 256 - 52
            slice(parse_sessionkey,dec_data,52, sizeof(dec_data));
            // int cur_index_par =0;
            int offset = 8;
            int relval_length =6;

            int cur_index_par =0;
            for(int i = 0; i<resp_session_length;i++)
            {
                printf("%d 번째! \n", i+1);
                long int key_id = read_variable_UInt(parse_sessionkey,cur_index_par , offset);
                printf("key id : %ld\n", key_id);

                cur_index_par += offset;
                make_time(parse_sessionkey, cur_index_par,SESSION_KEY_EXPIRATION_TIME_SIZE);
                cur_index_par += SESSION_KEY_EXPIRATION_TIME_SIZE;

                long int relvalidity = read_variable_UInt(parse_sessionkey, cur_index_par, relval_length);
                printf("Relvalidity : %ld \n", relvalidity);
                cur_index_par += relval_length; // 8 + 6 + 6;
                int cipher_keysize = parse_sessionkey[cur_index_par];
                printf("cipher_keysize : %d \n", cipher_keysize);
                cur_index_par += 1; // 8 + 6 + 6 + 1;
                
                unsigned char cipher_key_value_par[cipher_keysize];
                slice(cipher_key_value_par, parse_sessionkey, cur_index_par, cur_index_par+ cipher_keysize);

                cur_index_par += cipher_keysize;
                int mac_keysize = parse_sessionkey[cur_index_par];
                printf("mac_keysize : %d\n", mac_keysize );
                cur_index_par += 1;
                unsigned char mac_key_value_par[mac_keysize];
                slice(mac_key_value_par,parse_sessionkey, cur_index_par, cur_index_par+mac_keysize);
                cur_index_par += mac_keysize;
                printf("\n\n");

            }
            
            //resp_reply_nonce랑 SessionKeyReq.Entity_nonce랑 맞춰봐야함
            // resp_reply_nonce SessionKeyReq.Entity_nonce
            printf("replyNonce in sessionKeyResp: ");
            for(int i =0; i<NONCE_SIZE;i++)
                printf("%x ", resp_reply_nonce[i]);
            printf("\n");
            if(strncmp((char *)resp_reply_nonce, (char *) SessionKeyReq.Entity_nonce, NONCE_SIZE) == 0 )
            {
                printf("Nonce가 일치했습니다. \n");
            }
            else
                printf("auth nonce NOT verified\n");
            
            printf("auth nonce verified\n\n");


            printf("updating distribution key: \n");

            // absValidity, cipher_key_value, mac_key_value;
            printf("cipher_key_value ");
            print_buf(cipher_key_value, sizeof(cipher_key_value));
            printf("mac_key_value ");
            print_buf(mac_key_value, sizeof(mac_key_value));
            print_buf(absValidity, SESSION_KEY_EXPIRATION_TIME_SIZE);
            make_time(absValidity,0,SESSION_KEY_EXPIRATION_TIME_SIZE);
            printf("\nDistribution update success!!\n\n");

        }

        

        // close(my_sock); //4번
}