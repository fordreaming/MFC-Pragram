
// ProgressControl.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CProgressControlApp:
// �йش����ʵ�֣������ ProgressControl.cpp
//

class CProgressControlApp : public CWinAppEx
{
public:
	CProgressControlApp();

// ��д
	public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CProgressControlApp theApp;