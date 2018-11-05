#if !defined(AFX_FILEDIALOGEX_H__868E567B_6B77_4572_B4BF_79A3C62F40B3__INCLUDED_)
#define AFX_FILEDIALOGEX_H__868E567B_6B77_4572_B4BF_79A3C62F40B3__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// FileDialogEx.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// CFileDialogEx dialog

class CFileDialogEx : public CFileDialog
{
	DECLARE_DYNAMIC(CFileDialogEx)

public:
	CFileDialogEx(BOOL bOpenFileDialog, // TRUE for FileOpen, FALSE for FileSaveAs
		LPCTSTR lpszDefExt = NULL,
		LPCTSTR lpszFileName = NULL,
		DWORD dwFlags = OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT,
		LPCTSTR lpszFilter = NULL,
		CWnd* pParentWnd = NULL);

protected:
	//{{AFX_MSG(CFileDialogEx)
		// NOTE - the ClassWizard will add and remove member functions here.
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_FILEDIALOGEX_H__868E567B_6B77_4572_B4BF_79A3C62F40B3__INCLUDED_)
