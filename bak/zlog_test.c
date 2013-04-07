#include <stdio.h> 

#include "zlog.h"

int main(int argc, char** argv)
{
  int rc;
  zlog_category_t *c;
  
  rc = zlog_init("./zlog.conf");  /* 路径要和上面创建的一致，可以不放在/etc下 */
  if (rc) {
    printf("init failed\n");
    return -1;
  }
  
  c = zlog_get_category("my_cat");
  if (!c) {
    printf("get cat fail\n");
    zlog_fini();
    return -2;
  }
  
  ZLOG_INFO(c, "hello, zlog");
  
  zlog_fini();
  
  return 0;
}
