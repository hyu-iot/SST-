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

unsigned char buf [NONCE_SIZE*2 + NUMKEY + 10 + 20]; //buf[20+]
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
        memcpy(buf+NONCE_SIZE*2+NUMKEY,SessionKeyReq.Purpose,10); // Key_num 4byte
        memcpy(buf+NONCE_SIZE*2+NUMKEY+10,SessionKeyReq.Sender,20); // Key_num 4byte
        
    printf("-- Serialize한 내용 -- \n");
        for(int i=0; i<sizeof(buf);i++)
            printf(" %x ", buf[i]);
    }
    printf("\n");
}

void publicEncryptAndSign()
{
    if(sizeof(buf)<= 245)
    {
        
    }
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
        // printf("error1 \n");

        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    }
    else // PEM private 키로 RSA 생성
    {
        // printf("error2 \n");

        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }
    
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }
 
    return rsa;
}

int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted) 
{
    RSA * rsa = createRSA(key,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result; // RSA_public_encrypt() returns the size of the encrypted data 
}

int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
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
 


int main(int argc, char* argv[])
{
        TcpCommunication(argc, argv);
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
            
        char publickey[] = "-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxMP57hzB14ux8WVkggYV\n"\
"uTP/ExFtXECuyLcf0hfHIPCjdw4xDN5EdlJOx1KzRovry5konJslOnDtPZuwiodq\n"\
"VBgjCEFzDVODMqK+m7I/0SKEYquvbOui5GuI6TavBtiLAPExjnpveIIG1jGiVEa8\n"\
"yWU8JmspsmGLO1Sk5A13JL4sxw0IIAApXboymmcKK2r5sRFTMMhudyhyyADN8r0j\n"\
"zmVKCCDC09cHD64E1yQPZuAEFTcCj4Y/GkwzOgmA2/Y3r9YTBbxWzskBGROb0jKg\n"\
"vyStPoJ2YV7/fVVJl8ezNbcwnUZzlkYP0Y0Y0q9FCJqDg9Sv8psUxtw3q6qO79mx\n"\
"0QIDAQAB\n"\
"-----END PUBLIC KEY-----\n";

        char privatekey[] = "-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEowIBAAKCAQEAxMP57hzB14ux8WVkggYVuTP/ExFtXECuyLcf0hfHIPCjdw4x\n"\
"DN5EdlJOx1KzRovry5konJslOnDtPZuwiodqVBgjCEFzDVODMqK+m7I/0SKEYquv\n"\
"bOui5GuI6TavBtiLAPExjnpveIIG1jGiVEa8yWU8JmspsmGLO1Sk5A13JL4sxw0I\n"\
"IAApXboymmcKK2r5sRFTMMhudyhyyADN8r0jzmVKCCDC09cHD64E1yQPZuAEFTcC\n"\
"j4Y/GkwzOgmA2/Y3r9YTBbxWzskBGROb0jKgvyStPoJ2YV7/fVVJl8ezNbcwnUZz\n"\
"lkYP0Y0Y0q9FCJqDg9Sv8psUxtw3q6qO79mx0QIDAQABAoIBAQCkKbWd2dRIFz7Q\n"\
"3f0rFhSNvjn0GLgbHcQ1pcMgr8HtU5euPuLhj5ei+CzN08vK8fY6mX/umOpIhesJ\n"\
"WZnDGhO2MaUYwDJTTffKCUnp8J+ZxqiZAhCMWVRAKw/BM2R327athI4KB1B1RFab\n"\
"4jFDCvl7NcEndIUHVKarS4V+11UuCxsxuSAHfqBk41MgulI8wqqivyiEfZe9f0VG\n"\
"TgJNUsx2vJPCVF8147T8EJWl9ctqUVrTqDg3kSfL64nMosS+A9fU3jyVrbUEG3dp\n"\
"Liv8vl2o2PKIFVsZxCdlSl02+S27lnNP36lfAL2a+RZupfN5OqcnjUPIgB//nHSy\n"\
"e84OCceBAoGBAP5m6LzQ9q8qMOX2v1dOAzqcomX4X9b4FaTdlu70nnuwL9UJZauy\n"\
"dkV4d5iXo59wjqCYdwbc16rtY3Awth0Pc+ThhtwWjnHmIUFwJuV2UnRnfq7nzp9P\n"\
"yfmQDt9feAEwpf2FQD9toqJjh7YP8AE0uMZCLYW6J0AQ6yAsLAScBfnZAoGBAMYA\n"\
"YomJ1HgAyQVOA+taLzzu/Oyo/+4lGaocLT8Kmyai0M+1WGDN7ozCs1uFhK6f/Qh7\n"\
"68dfmVD7/GPSxz46KGJAxgksWjNx3y0JZMVdba3DwuS5Oui0fVYc1eLshJki4/CI\n"\
"nIHneXI5tgK8K/+FkiAhCVlBrSUjeosQIuSpbsS5AoGAaMYbTkBFiIi40M0Zqqwv\n"\
"ekEuRQ7Q8ekEiPzV/53xc4Fxgay4GcmLGjtuDgNN2QlzRELmqoXjsLrJ/FejeT52\n"\
"/anAb/4+NjyQL7Iv4ssjVFuXehNwLn6e8VBaP7bC5sKRamMpvbW6iGSzbNENiIGd\n"\
"I9H3i57KMYGGRJ7Mli1n7KkCgYBrlqv0ZmOALZUNf93bVe7TIl1mz1H5+kjeyV7A\n"\
"oae6r7/dDYIPX/ben7FL6to09RRONt/gPw8VFUeIinDfXESzVtUFCQeeaqLFWxRZ\n"\
"tjGxuOy+0fOznNd6IkMKglBu0amf+utoHvo72iYPiGYz+0VyleD5khleU8/znnoH\n"\
"XBWnaQKBgFA3ZOpiQLmOj/PHBeZVfwPXU1JVgJS7YEEVfYSkTSA1RBdX4/hs3vq9\n"\
"haIQ+m4bdPh7V2zk1bwnBQTnEBU9oJiRqV/HtAC109dOcUmzg8xQvF8hvgqMxxce\n"\
"qC+uTA7C4jiGWESVy3a8ilPtUOqFBBsT3OmpFCn4ZOvE9fXyquCy\n"\
"-----END RSA PRIVATE KEY-----\n";


//// sign에 들어가는 key ////
    char signkey[]= "-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEogIBAAKCAQEAyTZHyM+u3GzBfM/KoSRTZn8nX6JEuqbdneaRj85S6ORwGuur\n"\
"qKWBgxVSUqThgWfvqs0EhcxJVs5I0l/DGZvVeR8KidKCKsK6+NOQexmIjAN65A6S\n"\
"0Um5CpYPa5fJvgDLVNv09FtnlfXtTqQpU7wK3f6uMok42qLDBwLFqojpWcBOVgGu\n"\
"+T6W7LsLlwHiz0jkvVAIKXbR6/mNSRZt95FJAtC4MsYBeM9CfNxaNvPyn+dFCOcW\n"\
"PTjpVfET19EyrKdPx2hFwbbjMjo1nrLEfsiZ92tAyUPt46iEX2GICqfA5cBP228w\n"\
"LY4EJVGLQORZLiGHc04Srfl/xWGnCRuul+vkwwIDAQABAoIBAH3sqZpEV6P9sE3j\n"\
"YWXd7RANbd/NFwRVYAbtAJYmQv8b0AkZCtI92kLmOiIcrECngne7XSQ7SH66FRsL\n"\
"8Xb6buwhgB/nDa2jNw54oUhZH3q4xtUpRbsTT2oPpdDpKsnth1MxYSj4d2iDg6Oe\n"\
"23pbCdYLCIv6EwnJqRKfKoPisV+H/Krw0X7CsICXS7WbyQDk8yZiM/y5RUuYUayQ\n"\
"ouAGbakv+UD5FzyL2KUT9kFXd5QBcCQWOutXYVMQlOqFbp/kA8Q9JpMMLgVr5+Lu\n"\
"abi4lTKx4e0sWZMutZD+YyCXqoAjO3BeCYwhdsPngMCMWb0xQrW8i2eggiS1S6sw\n"\
"H5HkfKECgYEA9sppgmHstYn/KRiOqkTL/ise5H52n76V26lqOZdcZUiK4gqSlX/O\n"\
"oEeK1R7XVX8Jlz0PtHP/R3cNVauPPCYpNJz6hMDRDYpiWfiAuPeTk/t+IabJEIbZ\n"\
"ybhoHVzw7gW7hO4cj/9aTC8LregHLU2yibazMszd/2+Gg9TTuNuM57ECgYEA0Lh0\n"\
"xnZM73cLoDPKflyZjKb31SyAEWQTHOSVnqKfLH6sgihcaliK2/zHL1BQI4uA/wV6\n"\
"+YqLf90RUbyRZi+XwUwdga/yDiUQIWmsxRjNsAkG467TxzOS2Tzviq3yRkpCTNx/\n"\
"paQOY1xdio7XQKbSy5XZY8N/ayf9ZtKp2UYhJLMCgYAeAyuloYcJ5MhVFRl0d31f\n"\
"YZsWKpL+hkzvM8EpU9D2uEW7i5GcALj+IPUvSdriGNrvu4tHZLvs0vuaKYz3waRN\n"\
"M7H7pv9FaEjhrCjrVaBq5LDIIuJc0il2MKjouT7Lk4LkfZiXonQ2w5nmAkutJL/L\n"\
"o55TVTrCL6vqKF2/I2QVYQKBgE/9IOOeGsX6/X2b25Kpsj7xDjGoKDyB+cEs6Rou\n"\
"gInw0fPfu+sVm8HLEhrT0KKOqBUT6JkRu3x5IFYOyjo7KxFtNjGpWD6Lfa8QbKHs\n"\
"a4d3Lii7q3XAEhsm+zZOi3bcpqQGLPUx9kGl+ENNkri4NjjHaNSO65oJbVemjGk0\n"\
"Myd5AoGAUPDR7bds4yTCQ6yfq8uAXwabSHkUgIrpZRRl8gzFXncjEVC81KkkJeej\n"\
"E0PuvUcE0tOhrY562xYfE32pxW4BRiZMAZxSXiyQjyozRnj/40I3ydbo+yQ2SuQf\n"\
"3bma+SijmXZR2iCuIuyZBGcHONRIPn7Yf/AT/y/9VNP/eJ4ktQM=\n"\
"-----END RSA PRIVATE KEY-----\n";

        unsigned char plainText[256];
        // printf("buf 길이!! ? %ld \n", sizeof(buf));
        memcpy(plainText,buf,sizeof(buf));
        // for(int i=0; i<sizeof(buf);i++ )
        // {
        //     printf(" %x ", plainText[i]);
        // }
        // printf("\n");
        // printf("%ld \n", strlen(publickey));  
        // printf("%ld \n", sizeof(publickey));  
         
        unsigned char encrypted[2048] = {};
        unsigned char decrypted[2048] = {};

        // printf("%ld \n", strlen(publickey));   

        // for(int i=0 ; i<sizeof(plainText); i++)
        //     {
        //         printf(" %x ", plainText[i]);
        //     }
        //     printf("\n");

        // Based on this comment you can encrypt at most 214 bytes using 256 byte RSA key.
        // strlen(plainText로 하면 0인 부분에서 끊겨서 제대로 된 encrypt가 되지 않음)
        int encrypted_length= public_encrypt(plainText,sizeof(buf),publickey,encrypted);
        printf("\n");
        printf("\n");
        printf("\n");

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
        // printf("계속 바뀜.... %ld \n", strlen(encrypted));

        int decrypted_length = private_decrypt(encrypted,sizeof(plainText),privatekey,decrypted);
        printf("\n");
        printf("\n");
        printf("\n");

        printf("-- decrypted 된 값 -- \n");
        for(int i=0 ; i<sizeof(buf); i++)
        {
            printf(" %x ", decrypted[i]);
        }
        printf("\n");
    
}

