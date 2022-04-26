
#include <stdio.h>




char sender_req[15] = "net1.client";
char purpose_req[19] = "{\"group\":\"Servers\"}";
char aa[10] = "  a n \n n";

int main()
{
    for(int i=0 ; i<sizeof(aa); i++)
        printf("%x ",aa[i]);
}