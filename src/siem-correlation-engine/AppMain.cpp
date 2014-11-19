/**
 *   @file   AppMain.cpp
 *   @brief  brief
 *
 *   detail
 *
 *   @internal www.captech.net.cn
 *   author:    zhangpeng
 *   mail:      zhangpeng@captech.net.cn,developer.zhang.peng@gmail.com
 *   Created:   Jul 5, 2014
 *   Revision:  1.0.0
 *   Compiler:  gcc/g++
 *   Company:   Captech Co., Ltd.
 *   Copyright: Copyright (c) 2008, Captech Co., Ltd.
 *
 * =====================================================================================
 */

#include <Poco/AutoPtr.h>

#include "SIEMServer.h"

int main(int argc, char **argv)
{
	Poco::AutoPtr<SIEM::CSIEMServer> server(new SIEM::CSIEMServer());
	server->run(argc, argv);
	return 0;
}