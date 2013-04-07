#ifndef __MD5_H__
#define __MD5_H__

#pragma warning(disable:4786)

#include <string>
using namespace std;

//##ModelId=403B0C530106
class CMD5
{
private:
#define uint8  unsigned char
#define uint32 unsigned long int

  //##ModelId=403B0C5301A3
  struct md5_context
  {
    //##ModelId=403B0C5301B4
    uint32 total[2];
    //##ModelId=403B0C5301D2
    uint32 state[4];
    //##ModelId=403B0C5301E2
    uint8 buffer[64];
  };
  
	//##ModelId=403B0C530116
	void md5_starts( struct md5_context *ctx );
	//##ModelId=403B0C530118
	void md5_process( struct md5_context *ctx, uint8 data[64] );
	//##ModelId=403B0C530135
	void md5_update( struct md5_context *ctx, uint8 *input, uint32 length );
	//##ModelId=403B0C530146
	void md5_finish( struct md5_context *ctx, uint8 digest[16] );

public:
	//! construct a CMD5 from any buffer
	//##ModelId=403B0C530156
	void GenerateMD5(unsigned char* buffer,int bufferlen);

	//! construct a CMD5
	//##ModelId=403B0C530166
	CMD5();

	//! construct a md5src from char *
	//##ModelId=403B0C530173
	CMD5(const char * md5src);

	//! construct a CMD5 from a 16 bytes md5
	//##ModelId=403B0C530175
	CMD5(unsigned long* md5src);

	//! add a other md5
	//##ModelId=403B0C530183
	CMD5 operator +(CMD5 adder);

	//! just if equal
	//##ModelId=403B0C530185
	bool operator ==(CMD5 cmper);

	//! give the value from equer
	// void operator =(CMD5 equer);

	//! to a string
	//##ModelId=403B0C530194
	string ToString();

	//##ModelId=403B0C5301A2
	unsigned long m_data[4];
};

#endif

