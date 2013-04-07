#include <iostream>
#include "md5.h"
using namespace std;

int main()
{
  CMD5 md5;
  unsigned char *buf = "abc\0ab";
  md5.GenerateMD5(buf, 4);
  string md5_str = md5.ToString();
  cout<<md5_str<<endl;

  return 0;
}
