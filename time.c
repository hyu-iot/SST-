#include <stdio.h>                                
#include <time.h>


int main(void){
  // time_t t = time(NULL);
  // struct tm tm = *localtime(&t);
  printf("%ld\n", time(NULL)*1000);
  // printf("now: %d-%d-%d %d:%d:%d\n",
  //        tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
  //        tm.tm_hour, tm.tm_min, tm.tm_sec);
  
  return 0;
}