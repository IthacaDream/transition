#ifndef __TRANSITION_H__
#define __TRANSITION_H__

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
  
};

//TODO
typedef struct {
  struct ccn* ccnhs[MAX_RDR_THREADS];
  int rdrs_free[MAX_RDR_THREADS];     // not a good way
}ccn_worker_queue;



#endif
