#ifndef __TRANSITION_H__
#define __TRANSITION_H__


#ifdef __GNUC__ 
  #define UNUSED_PARAM __attribute__ ((unused))
#else
  #define UNUSED_PARAM
#endif

const char* TUN_DEV = "tun0";              // default tun device
const char* APPLICATION_ID = "transition"; // the application identify, in line with ccnd.conf
const int URI_PREFIX_MAX_LEN = 32;         // uri prefix is always "/APPLICATION_ID/local_ip_addr/"
const int RET_INTEREST_COMP_INDEX = 4;     // index to the return interest name - see getReturnInterestIndex
const int MAX_URI_LEN = 512;               // 256 is plenty //60/4*10+32+...
const int MAX_RDR_THREADS = 10;            // max thread num
const int MAX_PACKET_SIZE = 65536;         // 64KB, is the max ip package size


//#define MAX_ERROR_MSG_LEN 256
//#define DEBUG 1
//#define RECORD_LOG_FILE "./log/packets.transition"
//#define LOG_FILE_NAME "./log/transition.log"

typedef enum {
  PT_IP = 0,
  PT_TCP = 1
} ProtocalType;

struct settings {
    ProtocalType protocol;
    //others
};


//TODO
typedef struct {
  struct ccn* ccnhs[MAX_RDR_THREADS];
  int rdrs_free[MAX_RDR_THREADS];     // not a good way
}ccn_worker_queue;


#define ts_unlikely(x) __builtin_expect((x),0)
#define ts_likely(x) __builtin_expect((x),1)
#define ts_prefetch(x, ...) __builtin_prefetch(x, __VA_ARGS__)


/*
 * Macros to calculate sub-net data using ip address and sub-net prefix
 */

#define TS_NET_IP_OCTECT(addr,pos) (addr >> (8 * pos) & 255)
#define TS_NET_NETMASK(addr,net) htonl((0xffffffff << (32 - net)))
#define TS_NET_BROADCAST(addr,net) (addr | ~TS_NET_NETMASK(addr,net))
#define TS_NET_NETWORK(addr,net) (addr & TS_NET_NETMASK(addr,net))
#define TS_NET_WILDCARD(addr,net) (TS_NET_BROADCAST(addr,net) ^ TS_NET_NETWORK(addr,net))
#define TS_NET_HOSTMIN(addr,net) net == 31 ? TS_NET_NETWORK(addr,net) : (TS_NET_NETWORK(addr,net) + 0x01000000)
#define TS_NET_HOSTMAX(addr,net) net == 31 ? TS_NET_BROADCAST(addr,net) : (TS_NET_BROADCAST(addr,net) - 0x01000000);


#if __GNUC__ >= 4
  #define TS_EXPORT __attribute__ ((visibility ("default")))
#else
  #define TS_EXPORT
#endif

#endif
