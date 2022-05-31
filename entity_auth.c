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
        int payload_len = payload_length(msg,size);
        int buf_len = payload_buf_length(payload_len);

        unsigned char *s1 = malloc(payload_len - 512);
        // memcpy(s1,msg,)

        dist_key_decrypt(msg, 1+buf_len,dist_key);
        print_buf(entity_nonce.nonce,8);

        // TODO: malloc indexing 필요해보임. sessionkey를 나눠야함. 동적할당으로!
        // sess_key_decrypt()
        


        free(s1);


        return 0;
    }

}
