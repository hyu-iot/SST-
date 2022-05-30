#include "entity_auth.h"


void Entity_Auth(unsigned char * msg, size_t size)
{
    if(msg[0] == AUTH_HELLO)
    {
        //To do: msg[1]에 관하여 몇개인지 조사하기! 총4바이트 기준! 함수 짜야함
        print_buf(msg, );
    }
    else if(msg[0] == SESSION_KEY_RESP_WITH_DIST_KEY)
    {

    }

}
