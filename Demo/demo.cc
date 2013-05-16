#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>

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

const int URI_PREFIX_MAX_LEN = 32;


void* waiting_loop(struct ccn *h) {
  //vmain event loop
  int res = ccn_run(h, -1); 
  if (res < 0) {
    printf("interest listening handler setup failed\n");
    ccn_destroy(&h);
    exit(0);
  }
}


enum ccn_upcall_res incoming_interest(struct ccn_closure *selfp,
                                      enum ccn_upcall_kind kind,
                                      struct ccn_upcall_info *info) {
  printf("[TEST] Recieve Interest\n");
  
}


int main()
{

  struct ccn* listening_ccn_h = ccn_create();
  if (NULL == listening_ccn_h) {
    printf("ccn_connect error\n");
    exit(0);
  }
  
  int res = ccn_connect(listening_ccn_h, NULL);
  if (res < 0) {
    printf("ccn_connect error, res = %d\n", res);
    ccn_destroy(&listening_ccn_h);
    exit(0);
  }

  char uri_prefix[URI_PREFIX_MAX_LEN] = {'\0'};
  sprintf(uri_prefix, "/%s/%s", "demo1", "hello1");
  struct ccn_charbuf *name = ccn_charbuf_create();
  
  //Convert a ccnx-scheme URI to a ccnb-encoded Name.
  res = ccn_name_from_uri(name, uri_prefix);
  if (res < 0) {
    printf("uri to ccn name failed, uri=%s\n", uri_prefix);
    ccn_charbuf_destroy(&name);
    ccn_destroy(&listening_ccn_h);
    exit(0);
  }

  struct ccn_closure in_interest = { 0 }; // don't forget to init
  in_interest.p = &incoming_interest;     //set callback function
  
  // Register to receive interests on a prefix
  res = ccn_set_interest_filter(listening_ccn_h, name, &in_interest);
  if (res < 0) {
    printf("ccn_set_interest_filter\n");
    ccn_charbuf_destroy(&name);
    ccn_destroy(&listening_ccn_h);
    exit(0);
  }
  ccn_charbuf_destroy(&name);

  pthread_t pts;
  //receiver/listening pthread
  res = pthread_create(&pts, NULL, waiting_loop, listening_ccn_h); 
  if (res < 0) {
    printf("creating thread for interest handler, failed\n");
    ccn_destroy(&listening_ccn_h);
    exit(0);
  }


  struct ccn* ccnh_workers = ccn_create();
  res = ccn_connect(ccnh_workers, NULL);
  if (res < 0) {
    printf("ccn_connect error\n");
    ccn_destroy(&ccnh_workers);
    exit(0);
  }
  
  const int MAX_URI_LEN = 512;      
  char uri[MAX_URI_LEN] = { '\0' };
  sprintf(uri, "ccnx:/%s/%s", "demo","hello");
  
  name = ccn_charbuf_create();
  res = ccn_name_from_uri(name, uri);
  if (res < 0) {
    printf("uri to name error. URI: %s\n", uri);
    ccn_charbuf_destroy(&name);
    exit(0);
  }

  //DATA to be sent
  char* pdata = "hello world";
  int data_len = strlen(pdata);
  
  struct ccn_charbuf* temp = ccn_charbuf_create();
  struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;
  enum ccn_content_type content_type = CCN_CONTENT_DATA;
  sp.type = content_type; // NONSENSE !

  res = ccn_sign_content(ccnh_workers, temp, name, &sp, pdata, data_len);
  if (res != 0) {
    printf("fail to encode ContentObject");
    ccn_charbuf_destroy(&temp);
    exit(0);
  }
  ccn_charbuf_destroy(&name);

  // publish to Content Store
  res = ccn_put(ccnh_workers, temp->buf, temp->length);
  if (res < 0) {
    printf("ccn_put failed\n");
    ccn_charbuf_destroy(&temp);
    exit(0);
  }
  if (sp.template_ccnb) ccn_charbuf_destroy(&sp.template_ccnb);

  ccn_charbuf_destroy(&temp);

  // waiting && waiting
  while(true) {
    sleep(10);
  }
  
  return 0;
}
