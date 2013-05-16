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


/*
enum ccn_upcall_res nop(struct ccn_closure *selfp,
                           enum ccn_upcall_kind kind,
                           struct ccn_upcall_info *info) {
  // do nothing
  printf("Data comes back!\n");
}
*/

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
  sprintf(uri, "ccnx:%s", "/demo1/hello1");
  //sprintf(uri, "ccnx:%s", "/demo/hello");

  struct ccn_charbuf* name = ccn_charbuf_create();
  res = ccn_name_from_uri(name, uri);
  if (res < 0) {
    printf("uri to name error. URI: %s\n", uri);
    ccn_charbuf_destroy(&name);
    exit(0);
  }

  //struct ccn_closure *cl = calloc(1, sizeof(*cl));
  //cl->p = &nop;  // ccn_handler
  //cl->data = NULL;
  //cl->intdata = 3;  // only send interest once
  //cl->refcount = 0; // calloc already done
  // TODO: try to set cl==NULL // not a good idea
  // to send Interest
  res = ccn_express_interest(ccnh_workers, name, NULL, NULL); 

  if (res != 0) {
    printf("express interest failed!\n");
    exit(0);
  }
  
  //sleep(10);
  
  /*  
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

  printf("res=%d\n", res);
  printf("data:%s\n", ptr);
  */
  return 0;
}
