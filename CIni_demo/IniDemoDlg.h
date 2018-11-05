// IniDemoDlg.h : header file
//

#if !defined(AFX_INIDEMODLG_H__25AE5124_BA5E_4090_9E6B_677F47EF196F__INCLUDED_)
#define AFX_INIDEMODLG_H__25AE5124_BA5E_4090_9E6B_677F47EF196F__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

/////////////////////////////////////////////////////////////////////////////
// CIniDemoDlg dialog
#include "ButtonSSL.h"
#include "ini.h"

class CIniDemoDlg : public CDialog
{
// Construction
public:
	CIniDemoDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	//{{AFX_DATA(CIniDemoDlg)
	enum { IDD = IDD_INIDEMO_DIALOG };
	CButtonSSL	m_wndStruct;
	CButtonSSL	m_wndSection;
	CButtonSSL	m_wndKey;
	CButtonSSL	m_wndInt;
	CButtonSSL	m_wndDouble;
	CButtonSSL	m_wndBool;
	CButtonSSL	m_wndString;
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CIniDemoDlg)
	public:
	virtual BOOL PreTranslateMessage(MSG* pMsg);
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	BOOL LoadFile(LPCTSTR lpPathName);
	HICON m_hIcon;

	// Generated message map functions
	//{{AFX_MSG(CIniDemoDlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnSelfile();
	afx_msg void OnReload();
	afx_msg void OnAbout();
	afx_msg void OnGetstring();
	afx_msg void OnDestroy();
	afx_msg void OnWritestring();
	afx_msg void OnAppendstring();
	afx_msg void OnGetint();
	afx_msg void OnWriteint();
	afx_msg void OnIncreaseint();
	afx_msg void OnBase();
	afx_msg void OnUpdateBase(CCmdUI* pCmdUI);
	afx_msg void OnGetarray();
	afx_msg void OnWritearray();
	afx_msg void OnGetbool();
	afx_msg void OnWritebool();
	afx_msg void OnInvertbool();
	afx_msg void OnGetdouble();
	afx_msg void OnWritedouble();
	afx_msg void OnIncreasedouble();
	afx_msg void OnGetpoint();
	afx_msg void OnWritepoint();
	afx_msg void OnGetrect();
	afx_msg void OnWriterect();
	afx_msg void OnSectexist();
	afx_msg void OnSectList();
	afx_msg void OnSectCopy();
	afx_msg void OnSectDelete();
	afx_msg void OnSectMove();
	afx_msg void OnKeyexist();
	afx_msg void OnKeyList();
	afx_msg void OnKeyCopy();
	afx_msg void OnKeyDelete();
	afx_msg void OnKeyMove();
	afx_msg void OnKeyListname();
	afx_msg void OnGetbytes();
	afx_msg void OnWritebytes();
	afx_msg void OnAppendBlk();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()

protected:
	void EndOperation(LPCTSTR lpPrompt, BOOL bSuccessful, LPCTSTR lpMsg = NULL);
	BOOL InputDouble(LPCTSTR lpPrompt, double& f);
	BOOL InputString(LPCTSTR lpPrompt, CString& s);
	BOOL InputInt(LPCTSTR lpPrompt, int& n);

	BOOL SelectTarget(BOOL bSectionOnly);
	BOOL SelectSource(BOOL bSectionOnly);
	CIni m_ini;
	
	// history
	CString m_sSection1;
	CString m_sSection2;
	CString m_sKey1;
	CString m_sKey2;
	CString m_sInput;

	int m_nBase;
	int m_nPrecision;
	CString m_sDelimiter;
	CString m_sAppPath;
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_INIDEMODLG_H__25AE5124_BA5E_4090_9E6B_677F47EF196F__INCLUDED_)
