#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include "md5.h"

void compute_md5(void* data, int data_len, unsigned char* md5str) {
  MD5_CTX ctx;
  unsigned char digest[16] = {'\0'};
  int i = 0, pos = 0;
  MD5Init(&ctx);
  MD5Update(&ctx, data, data_len);
  MD5Final(digest, &ctx);
  for (i=0; i<16; ++i) {
    pos += sprintf(md5str + pos, "%0.2X", digest[i]);
  }
}

int main(void) {
  MD5_CTX ctx;
  unsigned char digest[16] = {'\0'};
  int i;
  char arr[]="abc\0def";
  MD5Init(&ctx);
  MD5Update(&ctx, arr, 5);
  MD5Final(digest, &ctx);
  for (i=0;i<16;i++) {
    printf("%0.2X", digest[i]);
  }

  printf("\n");
  //printf("%s\n", digest);

  MD5Init(&ctx);
  MD5Update(&ctx, arr, 5);
  MD5Final(digest, &ctx);
  for (i=0;i<16;i++) {
    printf("%0.2X", digest[i]);
  }
  printf("\n");
  //printf("%s\n", digest);
  
  unsigned char result[32] = {'\0'};
  compute_md5(arr, 5, result);
  printf("%s\n", result);
  compute_md5(arr, 5, result);
  printf("%s\n", result);
  compute_md5(arr, 5, result);
  printf("%s\n", result);

  return 0;
}
