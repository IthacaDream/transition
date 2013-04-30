#include <iostream>
#include <fstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

using namespace std;

const int BUFFER_SIZE = 1024*1024*5;
const int PORT = 20121;
const char* SERVER_ADDR = "219.223.195.140";

int main ()
{
  struct timeval time_start, time_end;
  long time_used;
  char buffer[BUFFER_SIZE] = {'\0'};
  int data_len = 0;

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (-1 == sockfd) {
    cerr<<"socket create error"<<endl;
    exit(-1);
  }

  sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(PORT);
  addr.sin_addr.s_addr = inet_addr(SERVER_ADDR);
  cout<<"--begin connect--"<<endl;

  gettimeofday(&time_start, NULL);
  int ret = connect(sockfd,(sockaddr*)&addr, sizeof(addr));
  if (ret < 0) {
    cerr<<"connect error"<<endl;
    close(sockfd);
    exit(0);
  }

  cout<<"connected, now recv ..."<<endl;
  ret = recv(sockfd, (void*)&data_len, sizeof(int), 0);
  ret = recv(sockfd, buffer, data_len, MSG_WAITALL);
  gettimeofday(&time_end, NULL);
  close(sockfd);

  cout<<"data_len: "<<data_len<<endl;
  cout<<"recv data len: "<<ret<<endl;
  time_used = 1000000 * (time_end.tv_sec - time_start.tv_sec) +
    time_end.tv_usec - time_start.tv_usec;
  cout<<"time used: "<<time_used
      <<"us, 1 microsecond = 1/1000000S)"<<endl;

  //ok, save
  FILE * fd = fopen("data.tar.gz", "w");
  if (!fd) {
    cerr<<"file open error"<<endl;
  }
  ret = fwrite(buffer, 1, data_len, fd);
  if (ret != data_len) {
    printf("fwrite error! ret=%d != data_len=%d\n", ret, data_len);
  }

  fclose(fd);

  return 0;
}
