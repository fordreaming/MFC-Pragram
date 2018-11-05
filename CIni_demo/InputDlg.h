#if !defined(AFX_INPUTDLG_H__757F52C6_B63C_4330_AA98_76665C9AEFCA__INCLUDED_)
#define AFX_INPUTDLG_H__757F52C6_B63C_4330_AA98_76665C9AEFCA__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// InputDlg.h : header file
//

// types
enum { TYPE_STRING = 0, TYPE_INT, TYPE_DOUBLE };

/////////////////////////////////////////////////////////////////////////////
// CInputDlg dialog

class CInputDlg : public CDialog
{
// Construction
public:
	BOOL GetPrecision(int& nPrecision) const;
	CString GetData() const;
	CInputDlg(LPCTSTR lpPrompt, int nType, int nPrecision, LPCTSTR lpPrevInput = NULL, CWnd* pParent = NULL);   // standard constructor

// Dialog Data
	//{{AFX_DATA(CInputDlg)
	enum { IDD = IDD_INPUTDLG };
	CString	m_sData;
	CString	m_sLbl;
	int		m_nIdx;
	CString	m_sPrompt;
	//}}AFX_DATA


// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CInputDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:

	// Generated message map functions
	//{{AFX_MSG(CInputDlg)
	virtual BOOL OnInitDialog();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()

protected:
	void InitType(int nType, int nPrecision);
	int m_nType;
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_INPUTDLG_H__757F52C6_B63C_4330_AA98_76665C9AEFCA__INCLUDED_)
