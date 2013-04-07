#include <stdio.h>
#include "log4c.h"
#include "logger.h"

int main()
{
  if (log4c_init()) {
    fprintf(stderr, "log4c_init() failed\n");
    return 1;
  }

  log4c_category_t* mylog = log4c_category_get("mylog");
  printf("hello world\n");
  LOG_DEBUG(mylog, "hello world!\tline:%d in file:%s, %s", __LINE__, __FILE__, "abc");



  if (log4c_fini()){
    fprintf(stderr, "log4c_fini() failed\n");
    return 1;
  }

  return 0;
}
