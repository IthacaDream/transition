#include <iostream>
#include <fstream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

using namespace std;

const int PORT = 20121;
const int BUFFER_SIZE = 1024*1024*5;

int data_len = 0;
char buf[BUFFER_SIZE] = {'\0'};

void handle_send(void* args) {
  int rt;
  int client_fd = *((int*)args);
  if(client_fd <= 0) {
    cout<<"fd error"<<endl;
    pthread_exit((void*)0);
  }
  rt = send(client_fd, (void*)&data_len, sizeof(int), 0);
  if (rt < 0) {
    cout<<"send msg error"<<endl;
    close(client_fd);
  }
  
  rt = send(client_fd, buf, data_len, 0);
  if (rt < 0) {
    cout<<"send msg error"<<endl;
    close(client_fd);
  }
  
  cout<<"--send done--"<<endl;
  close(client_fd);
  pthread_exit((void*)0);
}


int main(int argc, char* argv[])
{

  if (argc != 2) {
    cerr<<"usage: "<<argv[0]<<" <file>"<<endl;
    exit(-1);
  }
  
  int rt;
  FILE* fd = fopen(argv[1], "r");
  fseek(fd, 0, SEEK_END);
  data_len = ftell(fd);

  cout<<"file size: "<<data_len<<endl;

  fseek(fd, 0, SEEK_SET);
  rt = fread(buf, 1, data_len, fd);
  if (rt != data_len) {
    printf("fread error! rt=%d != data_len=%d\n", rt, data_len);
  }
  fclose(fd);

  int server_sockfd = socket(AF_INET,SOCK_STREAM,0);
  if (server_sockfd < 0) {
    cerr<<"create server sock error!"<<endl;
    exit(0);
  }
  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(PORT);
  server_addr.sin_addr.s_addr = INADDR_ANY;
  bzero(&(server_addr.sin_zero), 8);

  rt = bind(server_sockfd, (sockaddr*)&server_addr, sizeof(server_addr));
  if (-1 == rt) {
    cerr<<"server fd bind error!"<<endl<<"error no : "<<errno<<endl;
    exit(0);
  }
  
  rt = listen(server_sockfd, 5);
  
  if (-1 == rt) {
    cerr<<"server fd listen error!"<<endl<<"error no : "<<errno<<endl;
    exit(0);
  }
  
  int client_fd;
  sockaddr_in client_addr;
  unsigned int addr_len = sizeof(client_addr);

  cout<<"all data is ready. now listening ..."<<endl;

  while (1) {
    client_fd = accept(server_sockfd, (sockaddr*)&client_addr, &addr_len);
    cout<<"--accepted--"<<endl;
    if (client_fd < 0) {
      cerr<<"accept error!"<<endl<<"error no : "<<errno<<endl;
      close(client_fd);
      continue;
    }

    // easy way
    pthread_t pt;
    pthread_attr_t pattr;
    pthread_attr_init(&pattr);
    pthread_attr_setdetachstate(&pattr,PTHREAD_CREATE_DETACHED);
    int ret = pthread_create(&pt,&pattr,(void*(*)(void*))&handle_send,&client_fd);
    if (ret != 0) {
      cerr<<"thread create error"<<endl;
      close(client_fd);
      exit(0);
    }
  }

  close(server_sockfd);
  return 0;
}

