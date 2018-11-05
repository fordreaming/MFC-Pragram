#if !defined(AFX_SECTKEYDLG_H__D48B9175_5ADF_4722_9236_D4F1B1105C8B__INCLUDED_)
#define AFX_SECTKEYDLG_H__D48B9175_5ADF_4722_9236_D4F1B1105C8B__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// SectKeyDlg.h : header file
//
#include "ComboCompletion.h"
/////////////////////////////////////////////////////////////////////////////
// CSectKeyDlg dialog

class CSectKeyDlg : public CDialog
{
// Construction
public:
	CString GetKey() const;
	CString GetSection() const;
	CSectKeyDlg(LPCTSTR lpIniPath, BOOL bSectionOnly, LPCTSTR lpPrompt, CWnd* pParent = NULL);   // standard constructor

// Dialog Data
	//{{AFX_DATA(CSectKeyDlg)
	enum { IDD = IDD_SETCKEYDLG };
	CComboCompletion	m_wndSections;
	CComboCompletion	m_wndKeys;
	CString	m_sSection;
	CString	m_sKey;
	//}}AFX_DATA


// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CSectKeyDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:

	// Generated message map functions
	//{{AFX_MSG(CSectKeyDlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnSetfocusKey();
	afx_msg void OnEditchangeSect();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()

protected:
	void RenewKeys();
	CString m_sPrompt;
	BOOL m_bSectionOnly;
	CString m_sIniPath;
	BOOL m_bEditted;
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_SECTKEYDLG_H__D48B9175_5ADF_4722_9236_D4F1B1105C8B__INCLUDED_)
