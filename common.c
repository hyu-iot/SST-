#include "./common.h"



void nonce_generator(unsigned char * nonce_buf, int size_n)  // nonce generator;
{
    int x = RAND_bytes(nonce_buf,size_n);
    if(x == -1)
    {
        printf("Failed to create Random Nonce");
        exit(1);
    }
}   

void slice(unsigned char * des_buf, unsigned char * buf, int a, int b )
{
    for(int i=0;i<b-a;i++)
    {
        des_buf[i] = buf[a+i];
    }
}

int payload_buf_length(int b)
{   
    int n = 1;
    while(b > 127)
    {
        n += 1;
        b >>=7;
    }
    return n;
}

int payload_length(unsigned char * message, int b)
{
    int num = 0;
    for (int i =0; i<b&& i<5; i++)
    {
        num |= (message[1+i]& 127) <<(7 * i);
        if((message[1+i]&128) == 0 )
        {
            i+= 1;
            break;
        }
    }
    return num;
}

void print_buf(unsigned char * print_buffer, int n)
{
    for(int i=0 ; i<n; i++)
        printf("%x  ", print_buffer[i]);
    printf("\n");
}