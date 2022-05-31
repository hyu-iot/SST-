#include "common.h"



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
// buffer에서 길이 구할 때!
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

// buffer 만들어야 할 때!

int put_in_buf(unsigned char *buffer, int a)
{
    int n = 1;
    while(a > 127)
    {
        buffer[n] = 128 | a & 127;
        n += 1;
        a >>=7;
    }
    buffer[n] = a;
    return n;
}
void print_buf(unsigned char * print_buffer, int n)
{
    for(int i=0 ; i<n; i++)
        printf("%x  ", print_buffer[i]);
    printf("\n");
}

// payload를 버퍼로 옮길 때!!
void num_key_to_buffer(unsigned char * buffer, int index, int n)
{
        for(int i=0 ; i < NUMKEY; i++)
        {
            buffer[index+i] |=  n >> 8*(NUMKEY-1-i);
        }
}

void Nonce_sort(unsigned char *buffer, size_t size)
{
    int payload_len = payload_length(buffer,size);
    int buf_len = payload_buf_length(payload_len);
    slice(buffer,buffer,5+buf_len,5+buf_len+NONCE_SIZE); // msg type + buf_len + ID
    memcpy(buffer+8,buffer,8);
}

int save_senpup(unsigned char *buffer, int index, 
            unsigned char * s, size_t num_s, unsigned char * p, size_t num_p)
{
    unsigned char n_s[1]; 
    unsigned char n_p[1];
    memset(n_s,num_s,1);
    memset(n_p,num_p,1);
    memcpy(buffer+index, n_s, 1);
    memcpy(buffer+index+1 , s, num_s);
    memcpy(buffer+index+1+num_s , n_p, 1);
    memcpy(buffer+index+1+num_s+1 , p, num_p);
    return index+2+num_s+num_p;
}