#include "entity_auth.h"



distribution_key dist_key; 
sessionkey sess_key[10];
nonce entity_nonce;

int Entity_Auth(unsigned char * msg, size_t size)
{
    if(msg[0] == AUTH_HELLO)
    {
        print_buf(msg, 14);
        unsigned char sender[] = "net1.client";
        unsigned char purpose[] = "{\"group\":\"Servers\"}";
        int num_key = 3;

        Nonce_sort(msg,size);
        nonce_generator(msg,NONCE_SIZE);
        slice(entity_nonce.nonce,msg,0,8);
        print_buf(entity_nonce.nonce,8);
        num_key_to_buffer(msg, NONCE_SIZE*2,num_key);
        int msg_len = save_senpup(msg,NONCE_SIZE*2+NUMKEY, sender,strlen(sender),purpose,strlen(purpose));

        int total_len = encrypt_sign(msg,msg_len);
        msg[0] = SESSION_KEY_REQ_IN_PUB_ENC;
        return total_len;
    }
    else if(msg[0] == SESSION_KEY_RESP_WITH_DIST_KEY)
    {
        printf("\nreceived session key response with distribution key attached! \n");
        int payload_len = payload_length(msg,1);
        int buf_len = payload_buf_length(payload_len);
        printf("payload len: %d, buf len: %d\n",payload_len,buf_len );
        unsigned char *s1 = malloc(payload_len - DIST_ENC_SIZE);
        slice(s1,msg,DIST_ENC_SIZE+1+buf_len,1+buf_len+payload_len);
        dist_key_decrypt(msg, 1+buf_len,  &dist_key);
        sess_key_decrypt(s1, payload_len - DIST_ENC_SIZE, sess_key, &dist_key);
        if(strncmp((char *)s1, (char *) entity_nonce.nonce, NONCE_SIZE) == 0 )
        {
            printf("Nonce is consistent. \n");
        }
        else
            printf("auth nonce NOT verified\n");
        return 0;
        free(s1);
    }
}

int Entity_Entity(unsigned char * msg, size_t size)
{
    msg[0] = ENTITY_HELLO; //1
    

}
