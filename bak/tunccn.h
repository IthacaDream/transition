#ifndef TUNCCN_H_
#define TUNCCN_H_

#define TUN_DEV "tun0"
#define TUN_URI_TUNCCN_ID "TUNCCN"
#define TUN_URI_MAX_PREFIX_LEN 34
#define URI_DELIMITER '/'
#define RET_INTEREST_COMP_INDEX 4 // index to the return interest name - see getReturnInterestIndex
#define MAX_TUNCCN_URI_LEN 512    // max should be 88 with IP addrs in the form x.x.x.x, so 256 is plenty
#define MAX_RDR_THREADS 100       // max thread num
#define FRAMESIZE 65536           // Buffer should be at least the MTU size of the interface
#define MAX_ERROR_MSG_LEN 256

#define DEBUG 1
#define RECORD_LOG_FILE "./log/packets.tunccn"
#define LOG_FILE_NAME "./log/tunccn.log"



#define MIN(x, y) ((x < y) ? x : y)

#endif
