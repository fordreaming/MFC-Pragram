// BaseDlg.cpp : implementation file
//

#include "stdafx.h"
#include "inidemo.h"
#include "BaseDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CBaseDlg dialog

const int BASES[4] = { 2, 8, 10, 16 }; 

/////////////////////////////////////////////////////////////////////////////
// CInputDlg dialog
CBaseDlg::CBaseDlg(int nBase, CWnd* pParent /*=NULL*/)
	: CDialog(CBaseDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CBaseDlg)
	m_nIdx = -1;
	//}}AFX_DATA_INIT
	m_nIdx = Base2Idx(nBase);
}


void CBaseDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CBaseDlg)
	DDX_CBIndex(pDX, IDC_COMBO1, m_nIdx);
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CBaseDlg, CDialog)
	//{{AFX_MSG_MAP(CBaseDlg)
		// NOTE: the ClassWizard will add message map macros here
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CBaseDlg message handlers

int CBaseDlg::Base2Idx(int nBase) const
{
	for (int i = 0; i < 4; i++)
	{
		if (BASES[i] == nBase)
			return i;
	}
	return 2;
}

int CBaseDlg::Idx2Base(int nIdx) const
{
	return (nIdx >= 0 && nIdx < 4) ? BASES[nIdx] : 10;
}

int CBaseDlg::GetBase() const
{
	return Idx2Base(m_nIdx);
}
