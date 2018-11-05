// SectKeyDlg.cpp : implementation file
//

#include "stdafx.h"
#include "IniDemo.h"
#include "SectKeyDlg.h"
#include "Ini.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CSectKeyDlg dialog


CSectKeyDlg::CSectKeyDlg(LPCTSTR lpIniPath, BOOL bSectionOnly, LPCTSTR lpPrompt, CWnd* pParent /*=NULL*/)
	: CDialog(CSectKeyDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CSectKeyDlg)
	m_sSection = _T("");
	m_sKey = _T("");
	//}}AFX_DATA_INIT

	m_sPrompt = lpPrompt;
	m_bSectionOnly = bSectionOnly;
	m_sIniPath = lpIniPath;
	m_bEditted = FALSE;
}


void CSectKeyDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CSectKeyDlg)
	DDX_Control(pDX, IDC_SECT, m_wndSections);
	DDX_Control(pDX, IDC_KEY, m_wndKeys);
	DDX_CBString(pDX, IDC_SECT, m_sSection);
	DDX_CBString(pDX, IDC_KEY, m_sKey);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CSectKeyDlg, CDialog)
	//{{AFX_MSG_MAP(CSectKeyDlg)
	ON_CBN_SETFOCUS(IDC_KEY, OnSetfocusKey)
	ON_CBN_EDITCHANGE(IDC_SECT, OnEditchangeSect)
	ON_CBN_SELCHANGE(IDC_SECT, OnEditchangeSect)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CSectKeyDlg message handlers

BOOL CSectKeyDlg::OnInitDialog() 
{
	CDialog::OnInitDialog();
	
	// TODO: Add extra initialization here
	SetWindowText(m_sPrompt);

	// list all sections
	CStringArray aSections;
	CIni ini(m_sIniPath);
	ini.GetSectionNames(&aSections);

	for (int i = 0; i < aSections.GetSize(); i++)
		m_wndSections.AddString(aSections[i]);

	if (m_bSectionOnly)
	{
		m_wndKeys.ShowWindow(SW_HIDE);
		GetDlgItem(IDC_LBLKEY)->ShowWindow(SW_HIDE);
	}

	if (aSections.GetSize() > 0)
	{
		m_sSection = aSections[0];
		RenewKeys();
		UpdateData(FALSE);
	}	

	return TRUE;  // return TRUE unless you set the focus to a control
	              // EXCEPTION: OCX Property Pages should return FALSE
}

CString CSectKeyDlg::GetSection() const
{
	return m_sSection;
}

CString CSectKeyDlg::GetKey() const
{	
	return m_sKey;
}

void CSectKeyDlg::RenewKeys()
{
	if (m_bSectionOnly)
		return;
	
	m_wndKeys.ResetContent();
	CStringArray aKeys;
	CIni ini(m_sIniPath);
	ini.GetKeyNames(m_sSection, &aKeys);

	for (int i = 0; i < aKeys.GetSize(); i++)
		m_wndKeys.AddString(aKeys[i]);
	
	m_sKey = aKeys.GetSize() > 0 ? aKeys[0] : _T("");	
}

void CSectKeyDlg::OnSetfocusKey() 
{
	// TODO: Add your control notification handler code here
	if (m_bEditted)
	{
		m_bEditted = FALSE;
		m_wndSections.GetWindowText(m_sSection);
		RenewKeys();
		m_wndKeys.SetWindowText(m_sKey);
	}
}

void CSectKeyDlg::OnEditchangeSect() 
{
	// TODO: Add your control notification handler code here
	m_bEditted = TRUE;
	m_wndKeys.ResetContent();
	m_wndKeys.SetWindowText(_T(""));
}
