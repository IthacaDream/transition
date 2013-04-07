/**
 * This is a CCN tunnel program. It receives packets from applications via
 * a tun device, forwards them to a remote endpoint via CCN using the
 * following handshake mechanism:
 *  -this tunnel program, R1, sends interest to a remote tunnel program, R2,
 *    with name /R2/TUNCCN/TIMESTAMP/R1/TUNCCN/hash(iphdr, payload)
 *  -R2 sends back data packet confirming that it will request the data (WS:
 *   no need)
 *  -R2 sends interest packets with name /R1/TUNCCN/hash(tcp hdr, payload)
 *  -R1 responds with data - data is original packet from application i.e. ip
 *    hdr, tcp hdr, payload
 *  -R2 passes the data to its tun device which is then received by apps
 */


#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <stdarg.h>
#include <assert.h>

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

#include <iostream>
#include <string>
#include <cstring>
#include <cctype>

#include <log4cpp/Category.hh>
#include <log4cpp/PropertyConfigurator.hh>

#include "md5.h"
#include "tunccn.h"

unsigned char tun_uri_prefix[TUN_URI_MAX_PREFIX_LEN];
unsigned int localIp;

FILE* logfile;
//FILE* record_log_file;

struct ccn* g_ccn_h; // the client handle, using to connect to local ccnd
struct ccn* ccnhs[MAX_RDR_THREADS];

int tun_fd;
int g_packet_count;
int g_log_id;

pthread_mutex_t tcMutex;

typedef struct {
  int threadIndx;
  struct iphdr *ipPkt;
} RdrArgs;

// not a good way
int rdrs_free[MAX_RDR_THREADS];
log4cpp::Category *log;

int tc_exit(int rc) {
  if (logfile) {
    fclose(logfile);
  }
  exit(rc);
}



/*compute md5 digest
 *@param data data_len
 *@md5str the result

void compute_md5(void* data, int data_len, unsigned char* md5str) {
  MD5_CTX ctx;
  unsigned char digest[16] = { '\0' };
  int i = 0, pos = 0;
  MD5Init(&ctx);
  MD5Update(&ctx, data, data_len);
  MD5Final(digest, &ctx);
  for (i = 0; i < 16; ++i) {
    pos += sprintf(md5str + pos, "%1.2X", digest[i]);
  }
}
 */

/*
 *查看可用
 *弱爆了
 *有时间改一下
 */
int reserveThreadIndx() {
  unsigned int i = -1, res = 0;
  while (!rdrs_free[(++i) % MAX_RDR_THREADS])
    ;
  res = i % MAX_RDR_THREADS;

  rdrs_free[res] = 0; //now it's busy
  return res;
}

unsigned int atoui(const char *pstr) {
  assert(pstr != NULL);
  int sign, c;
  unsigned int total = 0;

  while (isspace((int) (unsigned char) *pstr))
    ++pstr;
  c = (int) (unsigned char) *pstr++;
  sign = c;
  if (c == '-' || c == '+')
    c = (int) (unsigned char) *pstr++;

  while (isdigit(c)) {
    total = total * 10 + (c - '0');
    c = (int) (unsigned char) *pstr++;
  }

  return total;
}

//for test
void copy_ippacket(struct iphdr *lhs, struct iphdr *rhs) {
  lhs->ihl = rhs->ihl;
  lhs->version = rhs->version;
  lhs->tos = rhs->tos;
  lhs->tot_len = rhs->tot_len;
  lhs->id = rhs->id;
  lhs->frag_off = rhs->frag_off;
  lhs->ttl = rhs->ttl;
  lhs->protocol = rhs->protocol;
  lhs->check = rhs->check;
  lhs->saddr = rhs->saddr;
  lhs->daddr = rhs->daddr;
}

//for testn
void is_same_ippacket(struct iphdr *lhs, struct iphdr *rhs) {
  if (lhs->ihl != rhs->ihl)
    log->debug("ihl not equal");
  if (lhs->version != rhs->version)
    log->debug("version not equal");
  if (lhs->tos != rhs->tos)
    log->debug("tos not  equal");
  if (lhs->tot_len != rhs->tot_len)
    log->debug("tot_len not equal");
  if (lhs->id != rhs->id)
    log->debug("id not equal");
  if (lhs->frag_off != rhs->frag_off)
    log->debug("frag_off not equal");
  if (lhs->ttl != rhs->ttl)
    log->debug("ttl not equal");
  if (lhs->protocol != rhs->protocol)
    log->debug("protocol not equal");
  if (lhs->check != rhs->check)
    log->debug("check not equal");
  if (lhs->saddr != rhs->saddr)
    log->debug("saddr not equal");
  if (lhs->daddr != rhs->daddr)
    log->debug("daddr not equal");
}

/* get localhost ip addr
 * @param outip the local ip
 * @return -1 if failed
 */
int get_local_ip(char* outip) {
  int i = 0;
  int sockfd;
  struct ifconf ifconf;
  char buf[512];
  struct ifreq *ifreq;
  char* ip;

  ifconf.ifc_len = 512;
  ifconf.ifc_buf = buf;

  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    return -1;
  }

  ioctl(sockfd, SIOCGIFCONF, &ifconf); //get all ifconfig
  close(sockfd);

  ifreq = (struct ifreq*) buf;
  for (i = (ifconf.ifc_len / sizeof(struct ifreq)); i > 0; --i) {
    ip = inet_ntoa(((struct sockaddr_in*) &(ifreq->ifr_addr))->sin_addr);

    if (strcmp(ip, "127.0.0.1") == 0) {
      ++ifreq;
      continue;
    }
    strcpy(outip, ip);
    return 0;
  }

  return -1;
}

/* connect to the local tun device
 *
 */
int tun_alloc(char *dev, int flags) {
  struct ifreq ifr;
  int fd, tfd, err;
  char *clonedev = "/dev/net/tun";
  
  tun_uri_prefix[0] = '\0';

  /* Arguments taken by the function:
   *
   * char *dev: the name of an interface (or '\0'). MUST have enough
   *   space to hold the interface name if '\0' is passed
   * int flags: interface flags (eg, IFF_TUN etc.)
   */
  
  /* open the clone device */
  if ((fd = open(clonedev, O_RDWR)) < 0) {
    log->error("COULD NOT OPEN %s", clonedev);
    return fd;
  }

  /* preparation of the struct ifr, of type "struct ifreq" */
  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
   *        IFF_TAP   - TAP device
   *
   *        IFF_NO_PI - Do not provide packet information
   *
   *        If flag IFF_NO_PI is not set each frame format is:
   *             Flags [2 bytes]
   *             Proto [2 bytes]
   *             Raw protocol(IP, IPv6, etc) frame.
   */

  if (*dev) {
    /* if a device name was specified, put it in the structure; otherwise,
     * the kernel will try to allocate the "next" device of the
     * specified type */
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  /* try to create the device */
  if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
    close(fd);
    return err;
  }

  /* if the operation was successful, write back the name of the
   * interface to the variable "dev", so the caller can know
   * it. Note that the caller MUST reserve space in *dev (see calling
   * code below) */
  strcpy(dev, ifr.ifr_name);

  if (ioctl(fd, TUNSETNOCSUM, 1) < 0) {//TODO: why?
    log->error("ioctl TUNSETNOCSUM error");
    tc_exit(1);
  }
  //
  // get local IP
  /*
   * commented by Will Song
   * It not works well on my machine.
   *
   tfd = socket(AF_INET, SOCK_DGRAM, 0);//IPPROTO_UDP); TODO: why?
   if ((err = ioctl(tfd, SIOCGIFADDR, &ifr)) < 0) {//Get interface address
   if (DEBUG)
   log->debug("COULD NOT OPEN %s", TUN_DEV);
   close(tfd);
   return err;
   }

   sprintf(tun_uri_prefix, "/%s/%s",
   inet_ntoa(((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr),
   TUN_URI_TUNCCN_ID);
   localIp = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;
   //  set_tun_uri_prefix();
   */

  char lip[16] = { '\0' };
  if (get_local_ip(lip) == -1) {
    log->error("get local ip ERROR");
    return -1;
  }

  sprintf(tun_uri_prefix, "/%s/%s", TUN_URI_TUNCCN_ID, lip);
  localIp = inet_addr(lip);

  return fd;
}

/**
 * djb2 hash function
 * DESCRIPTION: from http://www.cse.yorku.ca/~oz/hash.html
 *  this algorithm (k=33) was first reported by dan bernstein many years ago
 *  in comp.lang.c. another version of this algorithm (now favored by
 *  bernstein) uses xor: hash(i) = hash(i - 1) * 33 ^ str[i]; the magic of
 *  number 33 (why it works better than many other constants, prime or not) has
 *  never been adequately explained.
 */
unsigned long tc_hash(uint8_t *data, int len) {
  unsigned long hash = 5381;
  int c, i;
  for (i = 0; i < len; ++i) {
    c = *data++;
    hash = ((hash << 5) + hash) + c; // times 33
  }
  return hash;
}


//int tc_put(struct ccn *lccn_h, struct iphdr *ip_packet, const char *puri) {
int tc_put(struct ccn *lccn_h, void* pdata, size_t data_len, const char *puri) {
  long expire = -1;
  size_t blocksize = 8 * 1024;
  int status = 0;
  int res;
  int bytesWritten = 0;
  ssize_t read_res;
  enum ccn_content_type content_type = CCN_CONTENT_DATA;
  const char *postver = NULL;
  const char *key_uri = NULL;
  int verbose = 0;
  int timeout = -1;

  //TODO: adding the ccnx: prefix is hacked for now
  char uri[MAX_TUNCCN_URI_LEN] = { '\0' };
  int locLogId = g_log_id++;
  sprintf(uri, "ccnx:%s", puri);
  //TODO: optional feature - dynamically add entry to routing table

  //log->debug("[TRACE] ENTER tc_put (%d) %s", locLogId, uri);
  //log->debug("[TRACE] put data: uri=%s", uri);
  //ccnx:/local_ip/hash(ip)
  //这个前缀和要发送的IP包唯一对应，当这样的interest到达时，就可以得到对应的Data

  struct ccn_charbuf* name = ccn_charbuf_create();
  res = ccn_name_from_uri(name, uri);
  if (res < 0) {
    log->error("bad ccn URI: %s", uri);
    log->debug("EXIT tc_put");
    return (1);
  }

  // 要发送的数据
  struct ccn_charbuf* temp = ccn_charbuf_create();

  struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;
  sp.type = content_type;

  //这里的name相当于是本地IP的URI,算完签名有什么用? 接收后还有处理吗?
  //RE: 不是给对方接收的，数据放在本地的CS里，当匹配name时，interest就会被响应
  //签名没什么用？但这里直接把buf里的数据放到temp里了，接下来再发出去？
  //RE: 签名就是加了数据的name，以响应对应的interest，所谓的发出去，不过是放在CS里
  // Create the signed content object, ready to go
  res = ccn_sign_content(lccn_h, temp, name, &sp, pdata, data_len);

  if (res != 0) {
    log->debug("[ERROR] in tc_put Failed to encode ContentObject");
    log->debug("EXIT tc_put");
    return (res);
  }

  //do send
  //put to content store
  res = ccn_put(lccn_h, temp->buf, temp->length);
  if (res < 0) {
    log->debug("[ERROR] ccn_put failed (res == %d, size=%d)", res,
        bytesWritten);
    log->debug("EXIT tc_put");
    return (res);
  }

  bytesWritten = temp->length;

  /*
   if (verbose) {
   struct ccn_charbuf *uriTmp = ccn_charbuf_create();
   uriTmp->length = 0;
   ccn_uri_append(uriTmp, name->buf, name->length, 1);
   if (DEBUG)
   log->debug("wrote %s", ccn_charbuf_as_string(uriTmp));
   ccn_charbuf_destroy(&uriTmp);
   }
   */

  ccn_charbuf_destroy(&name);
  ccn_charbuf_destroy(&temp);

  //TODO: I don't know why?
  //ccn_charbuf_destroy(&sp.template_ccnb);

  log->debug("[TRACE] EXIT tc_put (%d) res=%d, bytesWritten=%d ",
      locLogId, res, bytesWritten);

  return (0);
}

int tc_get(struct ccn *lccn_h, struct ccn_charbuf *resultbuf, const char *uri,
    struct ccn_parsed_ContentObject *pcobuf, int timeout) {

  struct ccn_charbuf *name = ccn_charbuf_create();
  struct ccn_charbuf *templ = NULL; //TODO: could probably keep templ around
  int res;
  int opt;
  int allow_stale = 0;
  int content_only = 0;
  const unsigned char *ptr;
  size_t length;
  int resolve_version = 0;
  const char *env_timeout = getenv("CCN_LINGER");

  if (env_timeout != NULL) {
    log->debug("[TRACE] env_timeout NOT NULL, is: %s", env_timeout);
  }

  int timeout_ms = 3000;

  int locLogId = g_log_id++;

  log->debug("[TRACE] ENTER tc_get (%d) '%s'", locLogId, uri);

  if (timeout >= 0)
    timeout_ms = timeout;

  //  name = ccn_charbuf_create();
  res = ccn_name_from_uri(name, uri);

  if (res < 0) {
    log->debug("bad ccn URI (1): %s", uri);
    log->debug("EXIT tc_get");
    return (1);
  }

  if (env_timeout != NULL && (res = atoi(env_timeout)) > 0) {
    timeout_ms = res * 1000;
  }

  /**************what is this*****************/
  /*
   if (allow_stale || env_timeout != NULL) {
   templ = ccn_charbuf_create();
   ccn_charbuf_append_tt(templ, CCN_DTAG_Interest, CCN_DTAG);
   ccn_charbuf_append_tt(templ, CCN_DTAG_Name, CCN_DTAG);
   ccn_charbuf_append_closer(templ); // </Name>
   if (allow_stale) {
   ccn_charbuf_append_tt(templ, CCN_DTAG_AnswerOriginKind, CCN_DTAG);
   ccnb_append_number(templ, CCN_AOK_DEFAULT | CCN_AOK_STALE);
   ccn_charbuf_append_closer(templ); // </AnswerOriginKind>
   }
   if (env_timeout != NULL) {

   // Choose the interest lifetime so there are at least 3
   // expressions (in the unsatisfied case).

   unsigned char buf[3] = { 0 };
   unsigned lifetime;
   int i;
   if (timeout_ms > 60000)
   lifetime = 30 << 12;
   else {
   lifetime = timeout_ms * 2 / 5 * 4096 / 1000;
   }
   for (i = sizeof(buf) - 1; i >= 0; i--, lifetime >>= 8)
   buf[i] = lifetime & 0xff;
   ccnb_append_tagged_blob(templ, CCN_DTAG_InterestLifetime, buf,
   sizeof(buf));
   }
   ccn_charbuf_append_closer(templ); // </Interest>
   }
   */
  /***********************************************/

  /*
   if (resolve_version != 0) {
   res = ccn_resolve_version(lccn_h, name, resolve_version, 500);
   if (res >= 0) {
   ccn_uri_append(resultbuf, name->buf, name->length, 1);
   if (DEBUG)
   log->debug("== %s", ccn_charbuf_as_string(resultbuf));
   resultbuf->length = 0;
   }
   }
   */

  res = ccn_get(lccn_h, name, templ, timeout_ms, resultbuf, pcobuf, NULL, 0);

  //if (res >= 0) {
  //    ptr = resultbuf->buf;
  //    length = resultbuf->length;
  //    if (content_only)
  //        ccn_content_get_value(ptr, length, &pcobuf, &ptr, &length);
  //    if (length > 0)
  //        res = fwrite(ptr, length, 1, stdout) - 1;
  // }

  ccn_charbuf_destroy(&templ);
  ccn_charbuf_destroy(&name);

  log->debug("[TRACE] EXIT tc_get (%d) res=%d bytesRead=%d", locLogId,
      res, resultbuf->length);

  return 0;
}


void* tc_ccn_wait() {
  int res = ccn_run(g_ccn_h, -1); //main event loop
  if (res < 0) {
    log->debug("[ERROR]  interest handler setup failed");
    tc_exit(1);
  }
}


/**
 * returns a pointer to the index of the start of the return interest
 *  i.e. an interest request has a name of the form:
 *    /R2/TUNCCN/TIMESTAMP/R1/TUNCCN/hash(tcp hdr, payload)
 *  a pointer to the / right before R1 will be returned which is the name
 *  of the content that the remote system wants us to request
 */
void *getReturnInterestIndx(const char *uri, char* ret_uri, int* length) {
  int numCompsFound = 0;
  int index = 0;
  int uri_len = strlen(uri);

  for (; index < uri_len && numCompsFound < RET_INTEREST_COMP_INDEX; ++index) {
    if (uri[index] == URI_DELIMITER)
      ++numCompsFound;
  }
  if (numCompsFound == RET_INTEREST_COMP_INDEX) {
    int ret_uri_start = index - 1;
    int cnt = 0;
    for (; index < uri_len && cnt < 2; ++index) {
      if (uri[index] == URI_DELIMITER)
        ++cnt;
    }
    if (2 == cnt) {
      //copy return-uri to ret_uri, not including the last '/'
      memmove(ret_uri, &uri[ret_uri_start], index - ret_uri_start - 1);
      int ret_len_start = index;
      for (; index < uri_len; ++index) {
        if (uri[index] == URI_DELIMITER)
          break;
      }
      if (index < uri_len) {
        char tmp[10] = { '\0' };
        *length = atoi(&uri[ret_len_start]);
        log->debug("[DEBUG] length from uri =%d", *length);
        return &uri[index + 1]; //remaining data
      } else {
        return NULL;
      }

    } else {
      return NULL;
    }
  } else {
    return NULL;
  }

  //return (numCompsFound == RET_INTEREST_COMP_INDEX) ? &uri[i - 1] : NULL;
}

void getUri(unsigned char *uri, struct ccn_upcall_info *info) {
  const unsigned char *ptr = info->interest_ccnb;
  int curMaxCpy = MAX_TUNCCN_URI_LEN;
  int curLen;

  do {
    while (*ptr++ != 0xFA);
    strcat(uri, "/");
    //strncat(uri, "/", curMaxCpy);
    curMaxCpy--;
    if (curMaxCpy > 0) {
      //log->debug("ptr=%s", ptr);
      strncat(uri, ++ptr, curMaxCpy);
      log->debug("ptr=%s", ptr);
      curLen = strlen(ptr);
      //log->debug("curLen=%d", curLen);
      ptr += curLen;
      curMaxCpy -= curLen;
      //log->debug("[DEBUG] uri=%s, curMaxCpy=%d", uri, curMaxCpy);
    }
  } while (((*ptr++ != '\0') || (*ptr != '\0')) && (curMaxCpy > 0));
  /*
   do {
   ++ptr;
   while (*ptr != 0xFA) {
   ++ptr;
   log->debug("++ptr");
   }
   //log->debug("[DEBUG] in getUri: %c, %u",*ptr, *ptr);
   strcat(uri, "/");
   //log->debug("[DEBUG] uri=%s, curMaxCpy=%d", uri, curMaxCpy);
   --curMaxCpy;
   if (curMaxCpy > 0) {
   ++ptr;
   log->debug("ptr=%s", ptr);
   curLen = strlen(ptr);

   strncat(uri, ptr-3, curLen);

   curMaxCpy -= curLen;
   ptr += curLen;

   //log->debug("ptr=%s", ptr);
   log->debug("[DEBUG] uri=%s, curMaxCpy=%d", uri, curMaxCpy);
   }

   //TODO?
   } while (((*ptr != '\0') || (*(ptr+1) != '\0')) && (curMaxCpy > 0));
   */
  strcat(uri, "/");
}

/*
void printBuf(const unsigned char *buf, unsigned int bufSize) {
  int i, j;
  for (i = 0; i < bufSize; i += 16) {
    fprintf(record_log_file, "%04x:  ", i);
    for (j = 0; j < 16 && (i + j) < bufSize; j++) {
      fprintf(record_log_file, "%02X", buf[i + j]);
      if (j % 2)
        fprintf(record_log_file, " ");
    }
    fprintf(record_log_file, "");
  }
  fprintf(record_log_file, "");

  fflush(record_log_file);
}
*/
/**
 * Handles a remote interest request so send return interest to get
 *  data and send the data to the tunnel.
 *  Start out by pulling the CCN name out of the packet.
 *  Then make sure the prefix matches that of this tunnel
 *  and assume that it is a remote interest request (no one should
 *  be writing any other CCN content to the tunnel)
 */
enum ccn_upcall_res incoming_interest(struct ccn_closure *selfp,
    enum ccn_upcall_kind kind, struct ccn_upcall_info *info) {
  unsigned char incomingUri[MAX_TUNCCN_URI_LEN] = { '\0' };
  //struct ccn_charbuf *cob = selfp->data;
  time_t curtime;
  int i;
  struct ccn_parsed_ContentObject pcobuf = { 0 };

  time(&curtime);
  if (DEBUG)
    log->debug("\n[DEBUG] %s>>>>> CCN data received...",
        ctime(&curtime));

  //TODO
  getUri(incomingUri, info);

  if (DEBUG)
    log->debug("[DEBUG] incomingUri = %s", incomingUri);
  fflush(logfile); //flush
  //检查incomingUri前缀是否匹配本地
  if ((kind == CCN_UPCALL_INTEREST)
      && strncmp(tun_uri_prefix, incomingUri, strlen(tun_uri_prefix)) == 0) {

    if (DEBUG)
      log->debug("[DEBUG] successfully pulled CCN name");

    char retInterestUri[1024] = { '\0' };
    unsigned char alldata[64 * 1024] = { '\0' };
    int encode_unit;
    unsigned char* pdata = (unsigned char*) getReturnInterestIndx(incomingUri,
        retInterestUri, &encode_unit);

    if (NULL == pdata || '\0' == retInterestUri[0]) {
      log->debug("[WARNING] Unable to find return interest name, dropping");
    } else {
      log->debug("[DEBUG] encode_unit = %d", encode_unit);

      //log->debug("[DEBUG] pdata=%s", pdata);
      unsigned int* c2int = (unsigned int*) alldata;
      int cnt = 0;
      char *pos = NULL;
      log->debug("[begin]");
      while (1) {
        pos = strchr((char*)pdata, (int)'/');
        if (NULL == pos)
          break;
        *pos = '\0';
        unsigned int val = atoui(pdata);
        c2int[cnt] = val;
        log->debug("%u/", c2int[cnt]);
        ++cnt;
        pdata = pos + 1;
      }
      log->debug("[end]");

      if (cnt != encode_unit) {
        log->debug("[ERROR] cnt != encode_unit");
      }
      /*
       int i = 0;
       for (i = 0; i< encode_unit; ++i) {
       --pdata[i];
       }
       */
      //memmove(alldata, pdata, encode_unit);
      int alldata_len = encode_unit * sizeof(int);
      //int alldata_len = encode_unit;

      log->debug("[TRACE] handled header, alldata_len=%d", alldata_len);

      struct ccn_charbuf *resultbuf = ccn_charbuf_create();

      // get the data that the remote app is sending and pass it to
      // the local app via the tunnel
      int res;
      int tmpIndx = reserveThreadIndx();

      //从interest来源处get
      //所谓的get就是发interest要数据
      char uri[MAX_TUNCCN_URI_LEN] = { '\0' };
      sprintf(uri, "ccnx:%s", retInterestUri);
      res = tc_get(ccnhs[tmpIndx], resultbuf, uri, &pcobuf, -1);
      rdrs_free[tmpIndx] = 1; //available

      if (res >= 0) {
        int bytesWritten;

        log->debug(
            "[TRACE] data received from remote app, passing to local app");

        const unsigned char *ptr = NULL;
        unsigned int length = 0;
        ptr = resultbuf->buf;
        length = resultbuf->length;

        //这个。。。
        //能否直接发数据包，不用经过sign及get的操作?
        ccn_content_get_value(resultbuf->buf, resultbuf->length, &pcobuf, &ptr,
            &length);
        //ptr即IP包, length即长度

        if (NULL == ptr) {
          log->debug("!!ptr == NULL!!");
        } else {
          log->debug("[ccn_content_get_value]: length=%d", length);
        }

        if (DEBUG)
          log->debug("## receiving %d...", g_packet_count++);
        if (ptr != NULL) {
          //printBuf(ptr, length);

          memmove(alldata + alldata_len, ptr, length);
          alldata_len += length;
        }

        //struct iphdr ip_pack;

        log->debug("[TRACE] before write to TUN, alldata_len=%d",
            alldata_len);

        struct iphdr* ip_header = (struct iphdr*) alldata;
        int total_len = ntohs(ip_header->tot_len);

        log->debug("ip version=%d, ip header len = %d",
            ip_header->version, ip_header->ihl);
        log->debug("ip len = %d", total_len);

        struct in_addr ipaddr;
        ipaddr.s_addr = ip_header->daddr;
        log->debug("recv dest=%s", inet_ntoa(ipaddr));
        ipaddr.s_addr = ip_header->saddr;
        log->debug("recv src=%s", inet_ntoa(ipaddr));

        //cpy_ippacket(ip_header, (struct iphdr*)ptr);
        //is_same_ippacket(ip_header, (struct iphdr*)ptr);
        //is_same_ippacket((struct iphdr*)alldata, (struct iphdr*)ptr);

        /*
         if (length != total_len) {
         log->debug("\n[WARNING] !! length=%d != ip_header len=%d", length, total_len);
         }

         if (memcmp(alldata, ptr, total_len) != 0 ) {
         log->debug("\n[WARNING] !! alldata not equal ptr, total_len = %d", total_len);
         }


         unsigned char encode_header[512] = {'\0'};
         unsigned char headbuf[128] = {'\0'};

         //get ip and tcp header

         memmove(headbuf, alldata, total_len);
         c2int = (unsigned int*)headbuf;
         int encode_header_len = 0;
         int i = 0;
         encode_unit = total_len / sizeof(int);
         for (i = 0; i < encode_unit; ++i) {
         int len = sprintf(encode_header + encode_header_len, "%u/", c2int[i]);
         encode_header_len += len;
         }
         log->debug("[CHECK]%s[/CHECK]", encode_header);
         */

        //把从CCN中收到的数据写到TUN
        pthread_mutex_lock(&tcMutex);
        //bytesWritten = write(tun_fd, ptr, length);
        bytesWritten = write(tun_fd, alldata, alldata_len);
        pthread_mutex_unlock(&tcMutex);

        if (bytesWritten == -1) {
          log->debug("error in writing to tun, return -1");
        }

        if (bytesWritten != alldata_len) {
          char errMsg[1024];
          log->debug("error in writing to tun (%d of %d bytes)",
              bytesWritten, alldata_len);
        }

        log->debug("[DEBUG] sent %d bytes to local app via tunnel",
            bytesWritten);
      } else {
        log->debug("[ERROR]  no data received from remote app (rc=%d)",
            res);
      }
      ccn_charbuf_reset(resultbuf);
    }
  }
  //收到interest，但不和本地IP匹配
  else {
    log->debug(
        "[WARNING] content name does not match tunnel prefix...dropping this data");
    log->debug("          uri='%s'", incomingUri);
  }
  fflush(logfile); //flush
}

/**
 * Calculate cksum for IP and ICMP packets.
 */
/*
 * commented by Will Song
 * I found it useless.
 *
 uint16_t cksum(uint8_t *packet, int len) {
 uint8_t *data = packet;
 uint32_t sum;

 for (sum = 0; len >= 2; data += 2, len -= 2) {
 sum += data[0] << 8 | data[1];
 }
 if (len > 0) {
 sum += data[0] << 8;
 }
 while (sum > 0xffff) {
 sum = (sum >> 16) + (sum & 0xffff);
 }
 sum = htons(~sum);
 return sum ? sum : 0xffff;
 }
 */

int isIpPacket(struct iphdr *pkt) { //TODO: not a good idea
  //PERF faster but less accurate to compare ip_packet->daddr to local IP
  //return (pkt->saddr == localIp) ? 1 : 0;
  //return (pkt->daddr == inet_addr("192.168.4.10")) ? 1 : 0;

  /*I can filter the ip packet by configuring TUN
   * by Will Song
   *
   */
  return 1;

  //  return (pkt->check == cksum((uint8_t*) pkt, sizeof(struct iphdr))) ? 1 : 0;
}

enum ccn_upcall_res tc_nop(struct ccn_closure *selfp, enum ccn_upcall_kind kind,
    struct ccn_upcall_info *info) {
}

int tc_request_interest(struct ccn *lccn_h, struct iphdr *ip_packet) {

  static unsigned short seq = 0;

  int locLogId = g_log_id++;
  struct ccn_parsed_ContentObject pcobuf = { 0 };
  int res;
  unsigned char* pbuf = (unsigned char*) ip_packet;
  log->debug("[TRACE] ENTER tc_request_interest (%d)", locLogId);
  int tcphdr_start = ip_packet->ihl * 4; //also ip data start
  int ip_len = ntohs(ip_packet->tot_len); //network to host short

  struct tcphdr* tcp_packet = (struct tcphdr*) &pbuf[tcphdr_start];
  unsigned short offset = tcp_packet->doff;
  int tcp_data_start = tcphdr_start + offset * 4;

  size_t data_len = ip_len - tcp_data_start;

  log->debug("[DEBUG] tcp_data_start = %d, ip_len = %d, data_len = %d",
      tcp_data_start, ip_len, data_len);

  unsigned char* pdata = &pbuf[tcp_data_start];

  struct in_addr ipaddr;
  ipaddr.s_addr = ip_packet->daddr; //get dest ip addr

  log->debug("[TRACE] dest ip addr=%s", inet_ntoa(ipaddr));

  //IP header size: 20~60, TCP header size:20~60, max: 120
  unsigned char encode_header[512] = { '\0' };
  //unsigned char headbuf[128] = {'\0'};

  //get ip and tcp header
  //memmove(headbuf, pbuf, tcp_data_start);
  log->debug("[DEBUG] tcp data start [header len] = %d",
      tcp_data_start);
  unsigned int *c2int = (unsigned int*) pbuf;
  int encode_header_len = 0;
  int i = 0;
  int encode_unit = tcp_data_start / sizeof(int);
  for (i = 0; i < encode_unit; ++i) {
    encode_header_len += sprintf(encode_header + encode_header_len, "%u/",
        c2int[i]);
  }
  /*
   for (i = 0; i < tcp_data_start; ++i) {
   ++headbuf[i];
   }
   */
  log->debug("[DEBUG] encode unit = %d, encode header len: %d",
      encode_unit, encode_header_len);
  // build the URI

  unsigned char uri[FRAMESIZE] = { '\0' }; //the name cant be bigger than the frame
  //PERF would be slightly faster to use integers for the IP addrs
  unsigned char digest[33] = { '\0' };
  //compute_md5(ip_packet, ntohs(ip_packet->tot_len), digest);
  CMD5 md5;
  md5.GenerateMD5((unsigned char*)ip_packet, ntohs(ip_packet->tot_len));
  string md5_str = md5.ToString().substr(22);

  //log->debug("[DEBUG] digest=%s", digest);
  //log->debug("[DEBUG] encode_unit=%d", encode_unit);
  //log->debug("[DEBUG] encode_header=%s", encode_header);
  /*
   sprintf(uri, "ccnx:/TUNCCN/%s/%X/TUNCCN/NULL/%s/%d/%s",
   //inet_ntoa(ipaddr), TUN_URI_TUNCCN_ID, time(NULL), tun_uri_prefix,
   inet_ntoa(ipaddr), time(NULL), //tun_uri_prefix,
   //"/TUNCCN/",
   //tc_hash(pdata, data_len), tcp_data_start, encode_header);
   //tc_hash(ip_packet, ntohs(ip_packet->tot_len)), tcp_data_start, headbuf);
   digest, encode_unit, encode_header);
   */
  //sprintf(uri, "ccnx:/tunccn/%s/%X/tunccn/%s/%d/%s",
  //inet_ntoa(ipaddr), time(NULL), digest, encode_unit, encode_header);
  sprintf(uri, "ccnx:/TUNCCN/%s/%X/TUNCCN/%s/%d/%s", inet_ntoa(ipaddr),
          time(NULL), md5_str.c_str(), encode_unit, encode_header);
  log->debug("[DEBUG] to send interest, uri=%s", uri);
  // like "uri=ccnx:/TUNCCN/192.168.4.10/50B70654/TUNCCN/05C1A3F8/header"

  struct ccn_charbuf* name = ccn_charbuf_create();
  res = ccn_name_from_uri(name, uri);
  if (res < 0) {
    log->debug(
        "[ERROR]  unable to get name for request interest, rc=%d", res);
    ccn_charbuf_destroy(&name);
    return res;
  }

  // send IP packet
  //res = tc_put(lccn_h, ip_packet, getReturnInterestIndx(uri));
  // only send data, because the header already send with interest
  char ret_uri[1024] = { '\0' };
  int tmp;
  if (NULL == getReturnInterestIndx(uri, ret_uri, &tmp)) {
    log->debug("[ERROR] getReturnInterestIndx failed");
    return -1;
  }

  //TODO
  res = tc_put(lccn_h, pdata, data_len, ret_uri);
  //res = tc_put(lccn_h, ip_packet, ntohs(ip_packet->tot_len), ret_uri);
  if (res) {
    log->debug("[ERROR]  IP packet send error");
    ccn_charbuf_destroy(&name);
    return res;
  }

  //TODO:

  //发成功后，还需要做什么?
  //为什么要先put再express_interest?
  struct ccn_closure *cl = calloc(1, sizeof(*cl));
  cl->p = &tc_nop;
  cl->data = NULL;
  cl->intdata = 3; // only send interest once
  //TODO: try to set cl==NULL

  //发送interest，格式为：uri=ccnx:/dest_ip/TUNCCN/timestamp/src_ip/TUNCCN/hash
  log->debug("[TRACE] now, express interest");
  res = ccn_express_interest(lccn_h, name, cl, NULL); //TODO: cl.p do nothing?

  log->debug("[TRACE] EXIT  tc_request_interest (%d) res=%d", locLogId,
      res);

  ccn_charbuf_destroy(&name);

  return res;
}


/*timeval *difft(timeval *time1, timeval *time2)
 {
 timeval *temp = (timeval *) malloc(sizeof(timeval));
 if (time2->tv_usec-time1->tv_usec<0)
 {
 temp->tv_sec = time2->tv_sec-time1->tv_sec-1;
 temp->tv_usec = 1000000000+time2->tv_usec-time1->tv_usec;
 }
 else
 {
 temp->tv_sec = time2->tv_sec-time1->tv_sec;
 temp->tv_usec = time2->tv_usec-time1->tv_usec;
 }

 return temp;
 }
 */


/* 把从TUN上收到数据从CCN发出去
 * 要这么做，先要调用tc_request_interest,
 * 即先发interest过去，请求对方发interest过来取数据
 */
void* handleSend(void *args) {

  int res;

  RdrArgs* rdrargs = (RdrArgs*) args;
  log->debug("[TRACE] sending with thread %d", rdrargs->threadIndx);

  if (isIpPacket(rdrargs->ipPkt)) {
    log->debug("[TRACE] IP packet received from local app...");
    log->debug("[TRACE] ## sending %d...", g_packet_count++);

    //TODO
    //printBuf(rdrargs->ipPkt, ntohs(rdrargs->ipPkt->tot_len));

    //TUN从APP收到数据，（要发给目的IP地址的IP数据包）
    //接下来先向这个目的IP，发interest，让其发interest过来，这样就可以把APP的数据作为响应的DATA发回
    //所以，接下来的本质就是请求interest
    res = tc_request_interest(ccnhs[rdrargs->threadIndx], rdrargs->ipPkt);
    if (res != 0) {
      log->debug(
          "[WARNING] sending interest for IP packet failed (pc=%d) res=%d",
          (g_packet_count - 1), res);
    }
  } else { // not IP packet
    log->debug("[WARNING] unrecognized packet on tun ip=%08X",
        ((RdrArgs *) args)->ipPkt->saddr);
  }

  rdrs_free[rdrargs->threadIndx] = 1; //set this thread available

  log->debug("[TRACE] finishing with thread %d", rdrargs->threadIndx);
}

int main(int argc, char * argv[]) {
  int i;
  int res;
  char tun_name[IFNAMSIZ];
  char *buffer;
  int maxfd, nread, retn;
  int bytesWritten;
  fd_set rset;

  struct ccn_charbuf *temp = NULL;
  struct ccn_charbuf *name = NULL;

  char usage[] = "usage: ./tunccn tun0";

  time_t lasttime;
  time_t curtime;

  g_log_id = 0;
  g_packet_count = 0;

  std::string initFileName = "log.conf";
  log4cpp::PropertyConfigurator::configure(initFileName);
  log = &log4cpp::Category::getInstance(std::string("tunccn"));

  time(&curtime);
  log->info("========= NEW SESSION =========");

  if (argc != 2) { //ignore other args
    printf("%s", usage);
    tc_exit(1);
  }

  // init rdrs_free array
  for (i = 0; i < MAX_RDR_THREADS; ++i) {

    rdrs_free[i] = 1; //1 means available

    ccnhs[i] = ccn_create();
    res = ccn_connect(ccnhs[i], NULL);

    if (res < 0) {
      
      log->error("ccn_connect error");
      tc_exit(1);
    }
  }

  strncpy(tun_name, argv[1], IFNAMSIZ);

  /* connects to the tun device. IFF_TUN means the packet will include
   * IP header, TCP/UDP header, and  the payload.
   */
  tun_fd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI);
  log->info("TUN name: %s, tun_fd=%d", tun_name, tun_fd);

  if (tun_fd < 0) {
    log->error("[ERROR] Allocating interface");
   tc_exit(1);
  }

  maxfd = tun_fd + 1;

  // connect to local ccnd
  g_ccn_h = ccn_create();
  res = ccn_connect(g_ccn_h, NULL);
  if (res < 0) {
    log->error("ccn_connect error, res = %d", res);
    tc_exit(1);
  }

  log->info("tun_uri_prefix: %s", tun_uri_prefix);

  // setup uri for interest handler
  name = ccn_charbuf_create();

  //Convert a ccnx-scheme URI to a ccnb-encoded Name.
  res = ccn_name_from_uri(name, tun_uri_prefix);
  if (res < 0) {
    log->error("bad ccn URI: %s", tun_uri_prefix);
    tc_exit(1);
  }


  struct ccn_closure in_interest;
  in_interest.p = &incoming_interest;

  res = ccn_set_interest_filter(g_ccn_h, name, &in_interest);
  if (res < 0) {
    log->error("ccn_set_interest_filter");
    tc_exit(1);
  }

  //启动主线程
  pthread_t pts;
  res = pthread_create(&pts, NULL, tc_ccn_wait, NULL); //receiver/listening pthread
  if (res < 0) {
    log->error("in main creating thread for interest handler setup failed");
    tc_exit(1);
  }
  
  log->info("main thread created, now Waiting for data into TUN...");

  // main loop
  while (1) {

    FD_ZERO(&rset);
    FD_SET(tun_fd, &rset);
    retn = select(maxfd, &rset, NULL, NULL, NULL);
    if (retn < 1) {
      if (-1 == retn)
        log->error("ERROR in select()");
      if (0 == retn)
        log->warn("select() timeout!");
    } else { // retn > 0

      // if data received from tun, it could be a local app or interest request
      /* the buffer always starts with an IP header */
      struct iphdr *p_ip = (struct iphdr *) malloc(FRAMESIZE);

      //tun 可读时，进行处理
      if (FD_ISSET(tun_fd, &rset)) {
        nread = read(tun_fd, p_ip, FRAMESIZE);
        if (nread > 0) {
          int tmpIndx = reserveThreadIndx();

          time(&curtime);
          log->info("%s>>>>> Received data on tunnel", ctime(&curtime));

          // Check to see if this is an IP packet in which case it is from the
          // local app and needs to be sent remotely
          // TODO: need to create a pool of threads during startup and allocat
          RdrArgs tmpArgs;
          tmpArgs.threadIndx = tmpIndx;
          tmpArgs.ipPkt = p_ip;

          pthread_attr_t pattr;
          pthread_attr_init(&pattr);
          pthread_attr_setdetachstate(&pattr, PTHREAD_CREATE_DETACHED);
          pthread_t pth;

          //创建一个线程处理从TUN上读取到的IP包
          pthread_create(&pth, &pattr, handleSend, &tmpArgs);

        } else {
          log->error("error in reading from tun");
        }
      } //end if(FD_ISSET)
    }
  } //end while

  log4cpp::Category::shutdown();  
  return 0;
}
//will song
