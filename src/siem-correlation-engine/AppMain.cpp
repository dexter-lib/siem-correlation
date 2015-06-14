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

#include <pthread.h>

#include "SIEMServer.h"

::SIEM::SIEMEventVctPtr g_vctSIEMEventPtr(new std::vector< ::SIEM::SIEMEventPtr>());

pthread_spinlock_t g_spin_lock;

int main(int argc, char **argv)
{
    pthread_spin_init(&g_spin_lock, PTHREAD_PROCESS_PRIVATE);
	Poco::AutoPtr<SIEM::CSIEMServer> server(new SIEM::CSIEMServer());
	server->run(argc, argv);
	pthread_spin_destroy(&g_spin_lock);
	return 0;
}
