/**
 *   @file   SIEMTreeContainer.hpp
 *   @brief  brief
 *
 *   detail
 *
 *   @internal www.captech.net.cn
 *   author:    root
 *   mail:      zhangpeng@captech.net.cn,developer.zhang.peng@gmail.com
 *   Created:   Dec 27, 2014
 *   Revision:  1.0.0
 *   Compiler:  gcc/g++
 *   Company:   Captech Co., Ltd.
 *   Copyright: Copyright (c) 2014, Captech Co., Ltd.
 *
 * =====================================================================================
 */

#ifndef SRC_SIEM_CORRELATION_ENGINE_SIEMTREECONTAINER_HPP_
#define SRC_SIEM_CORRELATION_ENGINE_SIEMTREECONTAINER_HPP_

#include <list>
#include <iostream>


namespace SIEM
{

template <typename T>
struct Element
{
    T *pData;
    std::list<struct Element<T> *> *pChild;
    typedef typename std::list<Element<T> *>::iterator LIST_ITER;
    LIST_ITER iterChild;
    Element():
        pData(NULL),
        pChild(NULL),
        iterChild(NULL)
    {}
};

template <typename T>
class CSIEMTreeContainer
{
public:
    CSIEMTreeContainer(){};
    virtual ~CSIEMTreeContainer(){};
public:
    Element<T>* GetRootElement()
    {
        return m_pRoot;
    }
    Element<T>* GetCurrentElement()
    {
        return m_pCurrent;
    }
    void TreeTraversing(Element<T> *pElement)
    {
        //print data element
        std::cout << "t_name:" << pElement->pData->name << std::endl;

        if(pElement->pChild != NULL && pElement->pChild->size() > 0)
        {
            //traversing children
            pElement->iterChild = pElement->pChild->begin();
            while(pElement->iterChild != pElement->pChild->end())
            {
                TreeTraversing(*(pElement->iterChild));
                pElement->iterChild++;
            }
        }
        else
        {
            return;
        }
    }

    void DeleteTree(Element<T> *pElement)
    {
        if(pElement->pData != NULL)
        {
            delete pElement->pData;
            pElement->pData = NULL;
        }

        if(pElement->pChild != NULL && pElement->pChild->size() > 0)
        {
            pElement->iterChild = pElement->pChild->begin();
            while(pElement->iterChild != pElement->pChild->end())
            {
                DeleteTree(*(pElement->iterChild));
                pElement->iterChild++;
            }
            if(pElement->pChild != NULL)
            {
                delete pElement->pChild;
                pElement->pChild = NULL;
            }
            if(pElement != NULL)
            {
                delete pElement;
                pElement = NULL;
            }
        }
        else
        {
            if(pElement != NULL)
            {
                delete pElement;
                pElement = NULL;
            }
            return;
        }
    }

private:
    Element<T> *m_pRoot;
    Element<T> *m_pCurrent;

};
} /*namespace SIEM*/

#endif /* SRC_SIEM_CORRELATION_ENGINE_SIEMTREECONTAINER_HPP_ */
