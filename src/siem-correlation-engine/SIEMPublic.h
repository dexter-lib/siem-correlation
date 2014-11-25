/**
 *   @file   SIEMPublic.h
 *   @brief  brief
 *
 *   detail
 *
 *   @internal www.captech.net.cn
 *   author:    Zhang peng
 *   mail:      zhangpeng@captech.net.cn,Developer.Zhang.Peng@gmail.com
 *   Created:   Nov 25, 2014
 *   Revision:  1.0.0
 *   Compiler:  gcc/g++
 *   Company:   Captech Co., Ltd.
 *   Copyright: Copyright (c) 2008, Captech Co., Ltd.
 *
 * =====================================================================================
 */

#ifndef SIEMPUBLIC_H_
#define SIEMPUBLIC_H_

#include <string>
#include <vector>

#include <stdint.h>

namespace SIEM
{

//use this item please override assign and operater =

template<typename T = std::string>
struct stCacheItem
{
    std::vector<T> Cache;
    uint32_t       nRead;
    uint32_t       nWrite;
    stCacheItem():nRead(0), nWrite(0)
    {}
};


} /* namespace SIEM */
#endif /* SIEMPUBLIC_H_ */
