// IniDemo.h : main header file for the INIDEMO application
//

#if !defined(AFX_INIDEMO_H__94852ACA_5738_4902_90FD_E6AA0624C01A__INCLUDED_)
#define AFX_INIDEMO_H__94852ACA_5738_4902_90FD_E6AA0624C01A__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"		// main symbols

/////////////////////////////////////////////////////////////////////////////
// CIniDemoApp:
// See IniDemo.cpp for the implementation of this class
//

class CIniDemoApp : public CWinApp
{
public:
	CIniDemoApp();

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CIniDemoApp)
	public:
	virtual BOOL InitInstance();
	//}}AFX_VIRTUAL

// Implementation

	//{{AFX_MSG(CIniDemoApp)
		// NOTE - the ClassWizard will add and remove member functions here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};


/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_INIDEMO_H__94852ACA_5738_4902_90FD_E6AA0624C01A__INCLUDED_)
