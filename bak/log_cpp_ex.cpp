#include <iostream>
#include <log4cpp/Category.hh>
#include <log4cpp/PropertyConfigurator.hh>

//log4cpp::Category

int main(int argc, char* argv[])
{
  std::string initFileName = "log.conf";
  log4cpp::PropertyConfigurator::configure(initFileName);
  log4cpp::Category *log = &log4cpp::Category::getInstance(std::string("tunccn"));
  
  log->debug("Received storm warning");
  log->info("Closing all hatches");
  //log.trace("trace");
  log->warn("warn");
  log->info("info");
  log->error("error");
  
  log4cpp::Category::shutdown();
  
  return 0;
}
