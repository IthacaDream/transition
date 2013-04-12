#include "config.h"  


Config::Config( std::string filename, std::string delimiter,  
                std::string comment )  
    : m_Delimiter(delimiter), m_Comment(comment)  
{
  // Construct a Config, getting keys and values from given file  
  
  std::ifstream in( filename.c_str() );  
      
  if( !in ) throw File_not_found( filename );   
  
  in >> (*this);  
}  


Config::Config()  
    : m_Delimiter( std::string(1,'=') ), m_Comment( std::string(1,'#') )  
{  
  // Construct a Config without a file; empty  
}  



bool Config::KeyExists( const std::string& key ) const  
{  
  // Indicate whether key is found  
  mapci p = m_Contents.find( key );  
  return ( p != m_Contents.end() );  
}  
      

/* static */  
void Config::Trim( std::string& inout_s )  
{  
  // Remove leading and trailing whitespace  
  static const char whitespace[] = " \n\t\v\r\f";  
  inout_s.erase( 0, inout_s.find_first_not_of(whitespace) );  
  inout_s.erase( inout_s.find_last_not_of(whitespace) + 1U );  
}  


std::ostream& operator<<( std::ostream& os, const Config& cf )  
{  
  // Save a Config to os  
  for( Config::mapci p = cf.m_Contents.begin();  
       p != cf.m_Contents.end();  
       ++p )  
        {  
          os << p->first << " " << cf.m_Delimiter << " ";  
          os << p->second << std::endl;  
        }  
  return os;  
}  

void Config::Remove( const std::string& key )  
{  
  // Remove key and its value  
  m_Contents.erase( m_Contents.find( key ) );  
  return;  
}  

std::istream& operator>>( std::istream& is, Config& cf )  
{  
  // Load a Config from is  
  // Read in keys and values, keeping internal whitespace  
  typedef std::string::size_type pos;  
  const std::string& delim  = cf.m_Delimiter;  // separator  
  const std::string& comm   = cf.m_Comment;    // comment  
  const pos skip = delim.length();        // length of separator  
  
  std::string nextline = "";  // might need to read ahead to see where value ends  
  
  while( is || nextline.length() > 0 )  
  {  
    // Read an entire line at a time  
    std::string line;  
    if( nextline.length() > 0 )  
    {  
      line = nextline;  // we read ahead; use it now  
      nextline = "";  
    }  
    else  
    {  
      std::getline( is, line );  
    }  
    
    // Ignore comments  
    line = line.substr( 0, line.find(comm) );  
    
    // Parse the line if it contains a delimiter  
    pos delimPos = line.find( delim );  
    if( delimPos < std::string::npos )  
    {  
      // Extract the key  
      std::string key = line.substr( 0, delimPos );  
      line.replace( 0, delimPos+skip, "" );  
      
      // See if value continues on the next line  
      // Stop at blank line, next line with a key, end of stream,  
      // or end of file sentry  
      bool terminate = false;  
      while( !terminate && is )  
      {  
        std::getline( is, nextline );  
        terminate = true;  
        
        std::string nlcopy = nextline;  
        Config::Trim(nlcopy);  
        if( nlcopy == "" ) continue;  
        
        nextline = nextline.substr( 0, nextline.find(comm) );  
        if( nextline.find(delim) != std::string::npos )  
          continue;  
        
        nlcopy = nextline;  
        Config::Trim(nlcopy);  
        if( nlcopy != "" ) line += "\n";  
        line += nextline;  
        terminate = false;  
      }  
      
      // Store key and value  
      Config::Trim(key);  
      Config::Trim(line);  
      cf.m_Contents[key] = line;  // overwrites if key is repeated  
    }  
  }  
  
  return is;  
}  
bool Config::FileExist(std::string filename)  
{  
  bool exist= false;  
  std::ifstream in( filename.c_str() );  
  if( in )   
    exist = true;  
  return exist;  
}  

void Config::ReadFile( std::string filename, std::string delimiter,  
                       std::string comment )  
{  
  m_Delimiter = delimiter;  
  m_Comment = comment;  
  std::ifstream in( filename.c_str() );  
  
  if( !in ) throw File_not_found( filename );   
  
  in >> (*this);  
}
