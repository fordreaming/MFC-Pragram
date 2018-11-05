// InputDlg.cpp : implementation file
//

#include "stdafx.h"
#include "IniDemo.h"
#include "InputDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CInputDlg dialog

CInputDlg::CInputDlg(LPCTSTR lpPrompt, int nType, int nPrecision, LPCTSTR lpPrevInput, CWnd* pParent /*=NULL*/)
	: CDialog(CInputDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CInputDlg)
	m_sData = _T("");
	m_sLbl = _T("");
	m_nIdx = -1;
	m_sPrompt = _T("");
	//}}AFX_DATA_INIT
	m_nType = nType;
	m_sPrompt = CString(lpPrompt) + _T(":");
	if (lpPrevInput != NULL)
		m_sData = lpPrevInput;
	InitType(nType, nPrecision);
}

void CInputDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CInputDlg)
	DDX_Text(pDX, IDC_EDIT1, m_sData);
	DDX_Text(pDX, IDC_LBL, m_sLbl);
	DDX_CBIndex(pDX, IDC_BASEORPREC, m_nIdx);
	DDX_Text(pDX, IDC_PROMPT, m_sPrompt);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CInputDlg, CDialog)
	//{{AFX_MSG_MAP(CInputDlg)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CInputDlg message handlers

void CInputDlg::InitType(int nType, int nPrecision)
{
	if (nType == TYPE_INT)
	{
		//m_sPrompt = _T("Int Value:");
	}
	else if (nType == TYPE_DOUBLE)
	{
		nPrecision = max(-1, nPrecision);
		nPrecision = min(8, nPrecision);
		m_sLbl = _T("Double Precision:");
		m_nIdx = nPrecision + 1;
		//m_sPrompt = _T("Double Value:");
	}
	else
	{
		//m_sPrompt = _T("String Value:");
	}
}

CString CInputDlg::GetData() const
{
	return m_sData;
}

BOOL CInputDlg::GetPrecision(int& nPrecision) const
{
	if (m_nType == TYPE_DOUBLE)
	{
		nPrecision = m_nIdx - 1;
		return TRUE;
	}

	return FALSE;
}

BOOL CInputDlg::OnInitDialog() 
{
	CDialog::OnInitDialog();
	
	// TODO: Add extra initialization here
	if (m_nType != TYPE_DOUBLE)
	{
		GetDlgItem(IDC_LBL)->ShowWindow(SW_HIDE);
		GetDlgItem(IDC_BASEORPREC)->ShowWindow(SW_HIDE);
	}
	return TRUE;  // return TRUE unless you set the focus to a control
	              // EXCEPTION: OCX Property Pages should return FALSE
}