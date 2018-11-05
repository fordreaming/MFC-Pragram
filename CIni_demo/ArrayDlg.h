#if !defined(AFX_ARRAYDLG_H__511ED8EB_E586_4FCE_A31E_629C40FF4CAC__INCLUDED_)
#define AFX_ARRAYDLG_H__511ED8EB_E586_4FCE_A31E_629C40FF4CAC__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// ArrayDlg.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// CArrayDlg dialog

class CArrayDlg : public CDialog
{
// Construction
public:
	const CStringArray* GetArray() const;
	CArrayDlg(CWnd* pParent = NULL);   // standard constructor

// Dialog Data
	//{{AFX_DATA(CArrayDlg)
	enum { IDD = IDD_ARRAYDLG };
	CEdit	m_wndEdit;
	CListBox	m_wndList;
	//}}AFX_DATA


// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CArrayDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:

	// Generated message map functions
	//{{AFX_MSG(CArrayDlg)
	afx_msg void OnAdd();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()

protected:
	CStringArray m_aArray;
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_ARRAYDLG_H__511ED8EB_E586_4FCE_A31E_629C40FF4CAC__INCLUDED_)
