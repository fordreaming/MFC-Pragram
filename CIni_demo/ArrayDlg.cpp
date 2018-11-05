// ArrayDlg.cpp : implementation file
//

#include "stdafx.h"
#include "inidemo.h"
#include "ArrayDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CArrayDlg dialog


CArrayDlg::CArrayDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CArrayDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CArrayDlg)
		// NOTE: the ClassWizard will add member initialization here
	//}}AFX_DATA_INIT
}


void CArrayDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CArrayDlg)
	DDX_Control(pDX, IDC_EDIT1, m_wndEdit);
	DDX_Control(pDX, IDC_LIST1, m_wndList);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CArrayDlg, CDialog)
	//{{AFX_MSG_MAP(CArrayDlg)
	ON_BN_CLICKED(IDC_ADD, OnAdd)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CArrayDlg message handlers

void CArrayDlg::OnAdd() 
{
	// TODO: Add your control notification handler code here
	CString s;
	GetDlgItemText(IDC_EDIT1, s);
	s.TrimLeft();
	s.TrimRight();
	if (!s.IsEmpty())
	{
		m_wndList.AddString(s);
		m_aArray.Add(s);
	}

	m_wndEdit.SetSel(0, -1);
	m_wndEdit.SetFocus();	
}

const CStringArray* CArrayDlg::GetArray() const
{
	return &m_aArray;
}
