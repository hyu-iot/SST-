
#include "secure_comm.h"

// unsigned char message[1024];

void TCP_connection(int argc, char* argv[], unsigned char  *message,size_t size)
{
        int my_sock;
        struct sockaddr_in serv_addr;
        int str_len;
        if(argc != 3)
        {
            printf("%s <IP> <PORT>\n", argv[0]);
            exit(1);
        }
        my_sock = socket(PF_INET,SOCK_STREAM,0); 
        if(my_sock == -1)
            printf("socket error \n");
        memset(&serv_addr,0,sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr=inet_addr(argv[1]);
        serv_addr.sin_port=htons(atoi(argv[2]));
        if(connect(my_sock,(struct sockaddr*)&serv_addr,sizeof(serv_addr))==-1) //2��
            printf("connect error\n");
        while(1)
        {
        str_len = read(my_sock,message,size-1); // message
        if(str_len==-1)
            printf("read error\n");
        printf("str_len : %d\n",str_len);
        print_buf(message,str_len);

        Entity_Auth(message, size);
        

        }


}