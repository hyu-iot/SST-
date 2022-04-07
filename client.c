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
        memcpy(buf+NONCE_SIZE*2+NUMKEY,SessionKeyReq.Purpose_len,1); // Key_num 4byte
        memcpy(buf+NONCE_SIZE*2+NUMKEY+1,SessionKeyReq.Purpose,20); // Key_num 4byte
        memcpy(buf+NONCE_SIZE*2+NUMKEY+1+20,SessionKeyReq.Sender_len,1); // Key_num 4byte
        memcpy(buf+NONCE_SIZE*2+NUMKEY+1+20+1,SessionKeyReq.Sender,20); // Key_num 4byte
        
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
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuAJDrpSYEr0RBFy//uab\n"\
    "c/umf7AodGPHt5mjpKxaJql4Exj1uXkBQoOJVU1P1ZTluO2QZ+bHxoZg0RKbrzOq\n"\
    "upjCKfidVMQ0wn4u1nc5//Kh29ku6K9/YCcRHK2q+YDLg8JQivYVMCp7aYCQY3RC\n"\
    "jj65H2CFOhaJHRl80jk+4/gGCqONrgkou5oD/tykOjwPvLRzkm05IwYNULuVtvFO\n"\
    "5+QZnsebx/LrOboryXWGigOuA2wfmA4o3r41ndGbEYyh6dGjt8gw6iRmTbn+8dyT\n"\
    "jvFH3sgYYUhKZXy0jxqvVSQlg8QIh2/cy0mLSrwWVdA5Ck25MabAXfwYA8amwJLK\n"\
    "+wIDAQAB\n"\
    "-----END PUBLIC KEY-----\n";

    RSA * rsa = createRSA(publickey,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result; // RSA_public_encrypt() returns the size of the encrypted data 
}

int private_decrypt(unsigned char * enc_data,int data_len, unsigned char *decrypted)
{
    char privatekey[] = "-----BEGIN RSA PRIVATE KEY-----\n"\
            "MIIEpgIBAAKCAQEAuAJDrpSYEr0RBFy//uabc/umf7AodGPHt5mjpKxaJql4Exj1\n"\
            "uXkBQoOJVU1P1ZTluO2QZ+bHxoZg0RKbrzOqupjCKfidVMQ0wn4u1nc5//Kh29ku\n"\
            "6K9/YCcRHK2q+YDLg8JQivYVMCp7aYCQY3RCjj65H2CFOhaJHRl80jk+4/gGCqON\n"\
            "rgkou5oD/tykOjwPvLRzkm05IwYNULuVtvFO5+QZnsebx/LrOboryXWGigOuA2wf\n"\
            "mA4o3r41ndGbEYyh6dGjt8gw6iRmTbn+8dyTjvFH3sgYYUhKZXy0jxqvVSQlg8QI\n"\
            "h2/cy0mLSrwWVdA5Ck25MabAXfwYA8amwJLK+wIDAQABAoIBAQCn3Jj1yGS6o3PE\n"\
            "sQANfz5NHkMTtRYSp3voR+Z7MSfEoVECywBPRM4baXd9M9wikYTHoSDdSDDzMF9e\n"\
            "G0WfHNkhBH4MX9rXG26uBwKfb4Cfty5lKsmaR49BniIEMYIJvq7p8fgb7MYDfJ28\n"\
            "7yXJNKQKs7mZoCmphilrPHccKFDxESPda5+Yffsvqx9cnlHDA7DWTmChhLT9DYWW\n"\
            "LpfQ9/dRhccwd0HwVnjySOc0LSDAAShwmz6FtImokkSEyeMBcZsFTimRTnhY0Wcz\n"\
            "ldbq+3w2zXHzLdu1PGd1BwD9CQTI5zmaQYIafjcn+xAKSuv42LdffajCvPVzafqt\n"\
            "HW0WiTXxAoGBAOE/YIh8bMtuEcEBvvpYbtfh3NZLrnZ5fYgC7KRrywT8QWeqPBbF\n"\
            "cdO6aejDDwWICDJ58NyQiu2Ye9T7kjUuyXILFwoFS9uUPFaQORZrkTvf2kRlN8Yq\n"\
            "VYCTfzT2Py/EdrEBS7gOLBBr2qxY0pWJ9XgvArneJ/yJTWAxJa0GYysPAoGBANEh\n"\
            "jboqSCyixpov728lLz/hFIIRwTUelzsQoJPl1M1enjaTDUlJetw/yY3gkoSvc+FW\n"\
            "PJHFJ7h9oATQ4FBrRJ6Ud2m7s0N3PyojcYizKKL1jhC81XZMUsckaDIaNvp5aNJw\n"\
            "w4DvyZxExdZDkrllXh0dSCLN+hnjOfUv1DztnpFVAoGBANc8WGITg2Jgq1Zi9LsE\n"\
            "BecETKH5b5yGOw3cvYPf/P+mjFkisoiP41UOrGVe/tuqQSr6ms4o0Jh5PNsoCW4I\n"\
            "ZzYyorFQnkwUOhP9fI+P+hfcsBTrI4CYs1tJliRlqbtbYI+DTXdzE2gdp7dIqPF8\n"\
            "ArP1OAWj41HNYcKpM/dCQ0DBAoGBAKwUdfAndnf0AINCyjukVzqy1BMq1NYGs93Q\n"\
            "ErFfvji2kGzLl3UkV0n/2rM5hJZVYH6cXP59Qe/WvuL3lHvXqADsnU2NOzZaWskr\n"\
            "nPIkqV1dvGYdW3AZ4Usns+z2ESMM36m5S8U+iaBiHn/t3j9bH5PJUmABKLhAdqI/\n"\
            "lt4DkCR5AoGBAKYWdNIGOcczuAGRt2pDnLq88mZIIqHAYu1iJk9t5oVozDphPoSf\n"\
            "Vq6gDIMfPfZB69bCgavM05+RmQiGXoq6Ak59Ybhi1RFIDsRY8Ovs0lgvy7e7gGkJ\n"\
            "l4EWLKu/XbXPN43me7ZUIoNSUuVRw+nihLMGgcw75oFxaiB3IQoEY0T/\n"\
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
    "MIIEowIBAAKCAQEAuqLRIRF0d6zb2ZsQ0BwEDk9o83t3EoKnsWfN96hdaqD8SIGX\n"\
    "qLNs0FhxW6BB+JyQVRDXPN2GI65FOszAzJGHyzzrhMZmkVGbB311A00NjypF9/Vw\n"\
    "0G8lQG5Wv3TvFF1eiyZ0PSGcpjYfEVDEqa7D7c1Y2uDB8aG65eh2+aaQWxcaH7rm\n"\
    "maO4upOLcqH7awTozHFJuBbGBLnegrZ86MFpmEzpCuYuFfMLUp5bnOA+G74y94jd\n"\
    "f5eiz1IGR3HeVacue5rmJCWKdWXOE95yWNgj04tpFY9sYEyocRT35JiovdsxZaF/\n"\
    "884zGR5BNIVp6fh+PdBPAdtqKqmvgBLwtafaPQIDAQABAoIBAQCfj9+3o9KtFk4H\n"\
    "prkjEzCsg1u4/o94ddekppjC6WCkbuoBmznr8ypOna6cpVCBmmkTMQizcrjh/HYX\n"\
    "pUIYIzuzmGvK4kyCZQBj0PCfV9sF0SBss5w1tzBj+3GS0ggsov7XfJLYSMpCl/bL\n"\
    "uP/KCi5cOrmCt7FYQesl8C73lV3JYWr7SC0f2bPkgP2W0aS59s6xvo1dCgYIpkRk\n"\
    "RVH7DT46Dt+PWLb+83cxwyqSXgXU/6HfTxxsN8/O7BPzsvzWpfD38m5ZOeZFqaRs\n"\
    "IqiZVptccCIYMhcInnq00sWGJ8+llmMi5c7LKl9CESsmbTQFTi8f+CPDIvlODI6C\n"\
    "51wCz+JBAoGBAOEbwrPp2QsFeYYEQYXJhLA44kqhfWuPmq+RK0rybAlDgO15HBwS\n"\
    "nJIUShIFxfHhpLdNmiuPtbDkstDM7gmguLOz2Ka4gOxBtgxtJEZbc8fj4KDGqY31\n"\
    "oN69qMYxwH9XRiBnmY9FoWg7aglRKtdEt9lUslEp+3mip9UqwOZ7mmT5AoGBANQ/\n"\
    "fSmhfwR0AgZF0R+d9RxdcBiOwcQBzKKqCl31tzXqf78VlbxWR+zg9w0iuAuk8WsS\n"\
    "+AIEHOvYdMcAaxnh/xXFENnj4RO31LzFypbivX8q2yNbeuTrb7DLQb8ovtKz1Z9t\n"\
    "0g4U9mttWc0/+9QSLRPtUJlNM+ywTBGe06q5oyRlAoGAdqDzjW6aA7Xh4d9STFfz\n"\
    "hg6kKmJKPynRgd5F61wv1P3u7raZOq4QNudcVX0XYK3h6PuLWJOGU29iUKj+dLJv\n"\
    "Q7xuWwX2YwsKDihiKnW9YUTUtsWaywX7vgZC8Bd9812hxifyg89VDSHqcniE1CcR\n"\
    "oAWDZ0RxkxtFyQ+b0pqmtbkCgYA8U0s8wOT8HAjTRZa5mMio5jnNEQ4rqqNB/Hhz\n"\
    "2jnXfi4O3pCvdgp9Xjd5qUuMK7ZeS4bn88lQkzYltY27TouU4Wz3sRgw5Yf2m3UI\n"\
    "S6u2cDTWqNKWLACTzEGElo0eD/UAmlMgo36ia/MhLjViQkRDrKjC2bmPZVBJlc3t\n"\
    "cVPYLQKBgAg/557Smldia0TYW4mnymRVSPP9+b1SDnxQzFxSkVG84Sm+pLGNmcAr\n"\
    "ZNjuQaXkLZjr70qMpj1wrOodQ3QGL7RbbeD7Kq41sC89xjt50hxDiO7CYfd1O/c/\n"\
    "wKTmUsMPxYIYGVQfpM5IFyBAaaUxsvWIFEDegNjBoxSXSOhqkCyJ\n"\
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