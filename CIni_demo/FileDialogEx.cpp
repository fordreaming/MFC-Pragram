// FileDialogEx.cpp : implementation file
//

#include "stdafx.h"
#include "FileDialogEx.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CFileDialogEx

IMPLEMENT_DYNAMIC(CFileDialogEx, CFileDialog)

CFileDialogEx::CFileDialogEx(BOOL bOpenFileDialog, LPCTSTR lpszDefExt, LPCTSTR lpszFileName,
		DWORD dwFlags, LPCTSTR lpszFilter, CWnd* pParentWnd) :
		CFileDialog(bOpenFileDialog, lpszDefExt, lpszFileName, dwFlags, lpszFilter, pParentWnd)
{
	// Use OS version info to determine wether the system is capable of showing the
	// new dialog style.

	// Win2000/XP(return value GetVersion is smaller than 0x80000000) are
	// qualified for new dialog style.
	m_ofn.lStructSize = (GetVersion() < 0x80000000) ? 88 : 76;
}


BEGIN_MESSAGE_MAP(CFileDialogEx, CFileDialog)
	//{{AFX_MSG_MAP(CFileDialogEx)
		// NOTE - the ClassWizard will add and remove mapping macros here.
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

