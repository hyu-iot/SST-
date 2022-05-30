
#include "secure_comm.h"


void TCP_connection(int argc, char* argv)
{
        int my_sock;
        struct sockaddr_in serv_addr;
        int str_len;
        printf("Error;\n");
        unsigned char *message = NULL;
        message = (unsigned char*)malloc(100);
        if(argc != 3)
        {
            printf("%s <IP> <PORT>\n", argv[0]);
            exit(1);
        }
        my_sock = socket(PF_INET,SOCK_STREAM,0); 
        printf("Error;\n");
        
        if(my_sock == -1)
            printf("socket error \n");
        memset(&serv_addr,0,sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr=inet_addr(argv[1]);
        serv_addr.sin_port=htons(atoi(argv[2]));
        printf("Error;\n");

        if(connect(my_sock,(struct sockaddr*)&serv_addr,sizeof(serv_addr))==-1) //2��
            printf("connect error\n");
        memset(message,0x00,sizeof(message));
        str_len = read(my_sock,message,sizeof(message)-1); // message
        printf("Error;\n");
        if(str_len==-1)
            printf("read error\n");
        print_buf(message,str_len);
        printf("Error;\n");
}