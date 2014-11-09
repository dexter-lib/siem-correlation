/*
 * SIEMServer.h
 *
 *  Created on: Nov 10, 2014
 *      Author: root
 */

#ifndef SRC_SIEM_CORRELATION_ENGINE_SIEMSERVER_H_
#define SRC_SIEM_CORRELATION_ENGINE_SIEMSERVER_H_

#include <Poco/Util/ServerApplication.h>

namespace SIEM
{

using namespace Poco::Util;

class CSIEMServer: public ServerApplication
{
public:
	CSIEMServer();
	virtual ~CSIEMServer();
protected:
    void initialize(Application& self);
    void uninitialize();
    void defineOptions(OptionSet& options);
    void handleOption(const std::string& name, const std::string& value);
    void displayHelp();
    void printProperties(const std::string& base);
    int main(const std::vector<std::string>& args);
private:
};

} /* namespace SIEM */

#endif /* SRC_SIEM_CORRELATION_ENGINE_SIEMSERVER_H_ */
