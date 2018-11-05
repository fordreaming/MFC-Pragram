#if !defined(AFX_BASEDLG_H__87F7AD9A_10EB_4E0C_AF0C_3C552AFBD8D8__INCLUDED_)
#define AFX_BASEDLG_H__87F7AD9A_10EB_4E0C_AF0C_3C552AFBD8D8__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// BaseDlg.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// CBaseDlg dialog

class CBaseDlg : public CDialog
{
// Construction
public:
	int GetBase() const;
	CBaseDlg(int nBase, CWnd* pParent = NULL);   // standard constructor

// Dialog Data
	//{{AFX_DATA(CBaseDlg)
	enum { IDD = IDD_BASEDLG };
	int		m_nIdx;
	//}}AFX_DATA


// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CBaseDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	int Idx2Base(int nIdx) const;
	int Base2Idx(int nBase) const;

	// Generated message map functions
	//{{AFX_MSG(CBaseDlg)
		// NOTE: the ClassWizard will add member functions here
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_BASEDLG_H__87F7AD9A_10EB_4E0C_AF0C_3C552AFBD8D8__INCLUDED_)
