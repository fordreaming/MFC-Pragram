
// EditControlColorChange.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CEditControlColorChangeApp:
// �йش����ʵ�֣������ EditControlColorChange.cpp
//

class CEditControlColorChangeApp : public CWinAppEx
{
public:
	CEditControlColorChangeApp();

// ��д
	public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CEditControlColorChangeApp theApp;