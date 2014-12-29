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
#include <string>

#include <stdint.h>

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
    std::string m_strName;
    uint32_t    m_nPriority;
    uint32_t    m_nID;
public:
    CSIEMTreeContainer()
    :m_strName(""), m_nPriority(0), m_nID(0), m_pRoot(NULL), m_pCurrent(NULL)
    {
    }
    virtual ~CSIEMTreeContainer()
    {
        if(m_pRoot)
        {
            DeleteTree(m_pRoot);
            m_pRoot = NULL;
        }
    }
public:
    Element<T>* GetRootElement() const
    {
        return m_pRoot;
    }
    Element<T>* GetCurrentElement() const
    {
        return m_pCurrent;
    }

    void SetRootElement(Element<T> *pRoot)
    {
        if(pRoot != NULL) m_pRoot = pRoot;
    }
    void SetCurrentElement(Element<T> *pCurrent)
    {
        if(pCurrent != NULL) m_pCurrent = pCurrent;
    }

    //for test
    void TreeTraversing(Element<T> *pElement)
    {
        //print data element
        std::cout << "t_name:" << pElement->pData->strName << std::endl;

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

    void CopyTree(Element<T> *pElement, Element<T> *pDst)
    {
        if(pElement == NULL || pDst == NULL) return;

        // Template class need  override operator =
        if(pDst->pData == NULL)
        {
            pDst->pData = new T();
            *(pDst->pData) = *(pElement->pData);
        }

        if(pElement->pChild != NULL && pElement->pChild->size() > 0)
        {
            //traversing children
            pElement->iterChild = pElement->pChild->begin();
            //init children list
            pDst->pChild = new std::list<Element<T> *>();

            while(pElement->iterChild != pElement->pChild->end())
            {
                Element<T> *pChildren = new Element<T>();
                pDst->pChild->push_back(pChildren);
                CopyTree(*(pElement->iterChild), pChildren);
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

    CSIEMTreeContainer& operator = (const CSIEMTreeContainer& container)
    {
        Element<T> *pRoot = container.GetRootElement();

        if(pRoot == NULL)
        {
            std::cout << "source root element is null" << std::endl;
            return *this;
        }

        //Assignment
        Element<T> *pDst = new Element<T>();
        this->CopyTree(pRoot, pDst);
        this->SetRootElement(pDst);
        this->SetCurrentElement(pDst);
        this->m_nID       = container.m_nID;
        this->m_strName   = container.m_strName;
        this->m_nPriority = container.m_nPriority;

        return *this;
    }

    CSIEMTreeContainer(const CSIEMTreeContainer<T>& container)
    :m_strName(""), m_nPriority(0), m_nID(0), m_pRoot(NULL), m_pCurrent(NULL)
    {
        Element<T> *pRoot = container.GetRootElement();
        if(pRoot == NULL)
        {
            std::cout << "source root element is null" << std::endl;
            return;
        }

        //Assignment
        Element<T> *pDst = new Element<T>();
        this->CopyTree(pRoot, pDst);
        m_pRoot = m_pCurrent = pDst;
        m_nID       = container.m_nID;
        m_strName   = container.m_strName;
        m_nPriority = container.m_nPriority;
    }

    CSIEMTreeContainer(CSIEMTreeContainer<T>& container)
    :m_strName(""), m_nPriority(0), m_nID(0), m_pRoot(NULL), m_pCurrent(NULL)
    {
        Element<T> *pRoot = container.GetRootElement();
        if(pRoot == NULL)
        {
            std::cout << "source root element is null" << std::endl;
            return;
        }

        //Assignment
        Element<T> *pDst = new Element<T>();
        this->CopyTree(pRoot, pDst);
        m_pRoot = m_pCurrent = pDst;
        m_nID       = container.m_nID;
        m_strName   = container.m_strName;
        m_nPriority = container.m_nPriority;
    }

private:
    Element<T> *m_pRoot;
    Element<T> *m_pCurrent;

};
} /*namespace SIEM*/

#endif /* SRC_SIEM_CORRELATION_ENGINE_SIEMTREECONTAINER_HPP_ */
