// IpMonitor.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CIpMonitorApp:
// �йش����ʵ�֣������ IpMonitor.cpp
//

class CIpMonitorApp : public CWinApp
{
public:
	CIpMonitorApp();

// ��д
	public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CIpMonitorApp theApp;