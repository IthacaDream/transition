#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

extern "C"
{
#include <ccn/ccn.h>
#include <ccn/ccn_private.h>
#include <ccn/ccnd.h>
#include <ccn/bloom.h>
#include <ccn/charbuf.h>
#include <ccn/coding.h>
#include <ccn/digest.h>
#include <ccn/hashtb.h>
#include <ccn/reg_mgmt.h>
#include <ccn/schedule.h>
#include <ccn/signing.h>
#include <ccn/keystore.h>
#include <ccn/uri.h>
}


int main()
{
  
  struct ccn* ccnh_workers = ccn_create();
  int res = ccn_connect(ccnh_workers, NULL);
  if (res < 0) {
    printf("ccn_connect error\n");
    ccn_destroy(&ccnh_workers);
    exit(0);
  }
  
  char uri[128] = { '\0' };
  sprintf(uri, "ccnx:%s", "/demo/hello");
  struct ccn_charbuf* name = ccn_charbuf_create();
  res = ccn_name_from_uri(name, uri);
  if (res < 0) {
    printf("uri to name error. URI: %s\n", uri);
    ccn_charbuf_destroy(&name);
    exit(0);
  }

  struct ccn_charbuf *resultbuf = ccn_charbuf_create();
  struct ccn_parsed_ContentObject pcobuf = { 0 };
  struct ccn_charbuf *interest_template = NULL;
  int timeout_ms = 3000;
  
  res = ccn_get(ccnh_workers, name, interest_template, timeout_ms,
                resultbuf, &pcobuf, NULL, 0);
  
  ccn_charbuf_destroy(&name);
  
  const unsigned char *ptr = resultbuf->buf;
  size_t length = resultbuf->length;
  
  res = ccn_content_get_value(resultbuf->buf, resultbuf->length,
                              &pcobuf, &ptr, &length);
  if (res != 0) {
    printf("content get value failed!\n");
    exit(0);
  }
  
  printf("data: %s\n", ptr);
  
  return 0;
}
