/*
 * SIEMServer.cpp
 *
 *  Created on: Nov 10, 2014
 *      Author: root
 */

#include "SIEMServer.h"
#include "ZMQReceiveServer.h"
#include "ThriftReceiveServer.h"

#include <Poco/Logger.h>
#include <Poco/PatternFormatter.h>
#include <Poco/FormattingChannel.h>
#include <Poco/ConsoleChannel.h>
#include <Poco/SplitterChannel.h>
#include <Poco/FileChannel.h>
#include <Poco/AutoPtr.h>
#include <Poco/Channel.h>
#include <Poco/Message.h>
#include <Poco/File.h>
#include <Poco/SyslogChannel.h>

#include <boost/shared_ptr.hpp>

#include <signal.h>
#include <stdio.h>

namespace SIEM
{

using Poco::AutoPtr;
using Poco::Channel;
using Poco::ConsoleChannel;
using Poco::SplitterChannel;
using Poco::FileChannel;
using Poco::SyslogChannel;
using Poco::FormattingChannel;
using Poco::Formatter;
using Poco::PatternFormatter;
using Poco::Logger;
using Poco::Message;

using std::string;

const char* ppszSignStr[] =
{
    "other", "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT/SIGIOT",
    "SIGBUS", "SIGFPE", "SIGKILL", "SIGUSR1", "SIGSEGV", "SIGUSR2", "SIGPIPE", "SIGALRM",
    "SIGTERM", "SIGSTKFLT", "SIGCHLD", "SIGCONT", "SIGSTOP", "SIGTSTP", "SIGTTIN", "SIGTTOU",
    "SIGURG", "SIGXCPU", "SIGXFSZ", "SIGVTALRM", "SIGPROF", "SIGWINCH", "SIGIO", "SIGPWR", "SIGSYS"
};

void signal_catch(int sig)
{
    if (sig == SIGHUP  || sig == SIGILL || sig == SIGSEGV  || sig == SIGPWR || sig == SIGSTKFLT || sig == SIGFPE)
    {
        Application::instance().logger().error(Poco::format("Receive signal:%s", string(ppszSignStr[sig])), __FILE__, __LINE__);
        exit(-1);
    }
    else if(sig == SIGINT || sig == SIGTERM || sig == SIGQUIT || sig == SIGTSTP)
    {
        Application::instance().logger().error(Poco::format("Receive signal:%s", string(ppszSignStr[sig])), __FILE__, __LINE__);
        exit(0);
    }
    else
    {
        Application::instance().logger().information(Poco::format("Receive signal:%s", string(ppszSignStr[sig])), __FILE__, __LINE__);
    }
}

void SetupSignal(void)
{
    struct sigaction act;
    act.sa_handler = signal_catch;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGQUIT, &act, NULL);
    sigaction(SIGILL, &act, NULL);
    sigaction(SIGTRAP, &act, NULL);
    sigaction(SIGABRT, &act, NULL);
    sigaction(SIGTRAP, &act, NULL);
    sigaction(SIGBUS, &act, NULL);
    sigaction(SIGFPE, &act, NULL);
    sigaction(SIGKILL, &act, NULL);
    sigaction(SIGUSR1, &act, NULL);
    sigaction(SIGSEGV, &act, NULL);
    sigaction(SIGUSR2, &act, NULL);
    sigaction(SIGPIPE, &act, NULL);
    sigaction(SIGALRM, &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGSTKFLT, &act, NULL);
    sigaction(SIGCHLD, &act, NULL);
    sigaction(SIGCONT, &act, NULL);
    sigaction(SIGSTOP, &act, NULL);
    sigaction(SIGTSTP, &act, NULL);
    sigaction(SIGTTIN, &act, NULL);
    sigaction(SIGTTOU, &act, NULL);
    sigaction(SIGURG, &act, NULL);
    sigaction(SIGXCPU, &act, NULL);
    sigaction(SIGXFSZ, &act, NULL);
    sigaction(SIGVTALRM, &act, NULL);
    sigaction(SIGWINCH, &act, NULL);
    sigaction(SIGIO, &act, NULL);
    sigaction(SIGPWR, &act, NULL);
    sigaction(SIGSYS, &act, NULL);
}

void CSIEMServer::initialize(Application& self)
{
    loadConfiguration();
    ServerApplication::initialize(self);
    ServerApplication::loadConfiguration();
    {
        //load config properties
        Poco::Path appPath(config().getString("application.path"));
        std::string szCnfPath = appPath.makeParent().makeParent().toString();
        szCnfPath += appPath.separator();
        szCnfPath += "conf";
        szCnfPath += appPath.separator();
        szCnfPath += config().getString("application.baseName");
        szCnfPath += ".properties";

        Poco::File cnfFile(szCnfPath);
        if (cnfFile.exists())
        {
            ServerApplication::loadConfiguration(szCnfPath, PRIO_SYSTEM);
        }
    }

    //load log config
    {
        string strDefaultFormat = "[%Y-%m-%d %H:%M:%S.%c][PID:%P,TID:%T,LV:%q][%U:%u]%t";
        //read from properties
        std::string format = config().getString("logger.format", strDefaultFormat);
        std::string level  = config().getString("logger.level", "error");
        bool toConsole     = config().getBool("logger.to.console", true);
        bool toFile        = config().getBool("logger.to.file", true);
        bool toSyslog      = config().getBool("logger.to.syslog", false);

        m_bUseZMQServer    = config().getBool("siemevent.zmq.server");
        m_bUseThriftServer = config().getBool("siemevent.thrift.server");

        AutoPtr<SplitterChannel> splitterChannel(new SplitterChannel());
        if (toConsole)
        {
            AutoPtr<Channel> consoleChannel(new ConsoleChannel());
            splitterChannel->addChannel(consoleChannel);
        }

        if(toSyslog)
        {
            AutoPtr<Channel> syslogChannel(new SyslogChannel("SIEM", \
                    SyslogChannel::SYSLOG_PID, \
                    SyslogChannel::SYSLOG_LOCAL4));
            splitterChannel->addChannel(syslogChannel);
        }

        if (toFile)
        {
            std::string defaultPath = config().getString("application.baseName") + ".log";
            std::string logFilePath = config().getString("logger.to.file.path", defaultPath);

            if (logFilePath != defaultPath && std::getenv("SIEM_ROOT") != NULL)
            {
                std::string root = std::getenv("SIEM_ROOT");
                logFilePath = root + Poco::Path::separator() + logFilePath;
            }
            else
            {
               Poco::Path appPath(config().getString("application.path"));
               logFilePath = appPath.toString() + ".log";
            }

            std::string rotation = config().getString("logger.to.file.rotation", "daily");
            std::string archive = config().getString("logger.to.file.archive", "timestamp");
            AutoPtr<FileChannel> rotatedFileChannel(new FileChannel(logFilePath));
            rotatedFileChannel->setProperty("rotation", rotation);
            rotatedFileChannel->setProperty("archive", archive);
            splitterChannel->addChannel(rotatedFileChannel);
        }
        AutoPtr<Formatter> formatter(new PatternFormatter(format));
        formatter->setProperty("times", config().getString("logger.format.times","local"));
        AutoPtr<Channel> formattingChannel(new FormattingChannel(formatter, splitterChannel));
        ServerApplication::logger().setChannel(formattingChannel);
        ServerApplication::logger().setLevel(level);
    }

    //load directive xml
    Poco::Path appPath(config().getString("application.path"));
    std::string szCnfPath = appPath.makeParent().makeParent().toString();
    szCnfPath += appPath.separator();
    szCnfPath += "data";

    if(!m_ptrSIEMDirectiveHandle->LoadDirectives(szCnfPath))
    {
        ServerApplication::logger().error("Load directive error");
        exit(1);
    }

}

int CSIEMServer::main(const std::vector<std::string>& args)
{
    //show help document
    if(m_bHelpRequest)
    {
        displayHelp();
        return Application::EXIT_OK;
    }

    //handle signal
    SetupSignal();

    //Receive from zmq
    if(m_bUseZMQServer)
    {
        m_pZMQServer = new CZMQReceiveServer();
        m_pZMQServer->Initialize();
        m_pZMQServer->Start();
    }

    //Receive from thrift
    if(m_bUseThriftServer)
    {
        m_pThriftServer = new CThriftReceiveServer();
        m_pThriftServer->Initialize();
        m_pThriftServer->Start();
    }

    m_pSIEMEventHandle->Start();

    if(m_bUseZMQServer)
    {
        m_pZMQServer->Join();
    }

    if(m_bUseThriftServer)
    {
        m_pThriftServer->Join();
    }

    m_pSIEMEventHandle->Join();

    return 0;
}

void CSIEMServer::uninitialize()
{
    ServerApplication::uninitialize();
}

void CSIEMServer::defineOptions(OptionSet& options)
{

}

void CSIEMServer::handleOption(const std::string& name, const std::string& value)
{
    ServerApplication::handleOption(name, value);

    if(name == "help")
    {
        m_bHelpRequest = true;
    }
}

void CSIEMServer::displayHelp()
{

}

void CSIEMServer::printProperties(const std::string& base)
{
    AbstractConfiguration::Keys keys;
    config().keys(base, keys);
    if(keys.empty())
    {
        if(config().hasProperty(base))
        {
            string strMsg;
            strMsg.append(base);
            strMsg.append("=");
            strMsg.append(config().getString(base));
            logger().information(strMsg);
        }
    }
    else
    {
        string strFullKeys = base;
        if(!strFullKeys.empty())
            strFullKeys.append(".");
        for(AbstractConfiguration::Keys::iterator iter = keys.begin();\
            iter != keys.end(); iter ++)
        {
            strFullKeys.append(*iter);
            printProperties(strFullKeys);
        }
    }
}

CSIEMServer::CSIEMServer()
:m_bHelpRequest(false),
 m_bUseZMQServer(false),
 m_bUseThriftServer(false),
 m_pZMQServer(NULL),
 m_pThriftServer(NULL),
 m_pSIEMEventHandle(NULL),
 m_ptrSIEMDirectiveHandle(new CSIEMDirectiveHandle())
{
    m_pSIEMEventHandle = CSIEMEventHandle::Instance();
}

CSIEMServer::~CSIEMServer()
{
    if(m_pZMQServer)
    {
        delete m_pZMQServer;
        m_pZMQServer = NULL;
    }

    if(m_pThriftServer)
    {
        delete m_pThriftServer;
        m_pThriftServer = NULL;
    }

    m_pSIEMEventHandle->Release();

}

} /* namespace SIEM */
