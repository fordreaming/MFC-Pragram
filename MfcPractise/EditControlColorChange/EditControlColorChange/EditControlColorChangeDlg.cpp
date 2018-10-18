
// EditControlColorChangeDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "EditControlColorChange.h"
#include "EditControlColorChangeDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CEditControlColorChangeDlg �Ի���




CEditControlColorChangeDlg::CEditControlColorChangeDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CEditControlColorChangeDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CEditControlColorChangeDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, m_edit1);
}

BEGIN_MESSAGE_MAP(CEditControlColorChangeDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_MESSAGE(WM_MY_MESSAGE,OnMyMessage)
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_WM_CTLCOLOR()
	ON_WM_TIMER()
END_MESSAGE_MAP()


// CEditControlColorChangeDlg ��Ϣ�������

BOOL CEditControlColorChangeDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// ���ô˶Ի����ͼ�ꡣ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������  

	m_redcolor=RGB(255,0,0);                      // ��ɫ  
	m_bluecolor=RGB(0,0,255);                     // ��ɫ  
	m_textcolor=RGB(255,255,255);                 // �ı���ɫ����Ϊ��ɫ  
	m_redbrush.CreateSolidBrush(m_redcolor);      // ��ɫ����ɫ  
	m_bluebrush.CreateSolidBrush(m_bluecolor);    // ��ɫ����ɫ 

	
	SetTimer(1,10000,NULL);

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void CEditControlColorChangeDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CEditControlColorChangeDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CEditControlColorChangeDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


HBRUSH CEditControlColorChangeDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH hbr = CDialog::OnCtlColor(pDC, pWnd, nCtlColor);

	// TODO:  �ڴ˸��� DC ���κ�����
	switch (nCtlColor) //������ͬһ���͵Ŀؼ������ж�  
	{  
		// process my edit controls by ID.  
	//case CTLCOLOR_EDIT:  
	case CTLCOLOR_MSGBOX://����ؼ����ı��������Ϣ���������һ��switch  
		switch (pWnd->GetDlgCtrlID())//��ĳһ���ض��ؼ������ж�  
		{      
			// first CEdit control ID  
		case IDC_EDIT1:         // ��һ���ı���  
			// here  
			pDC->SetBkColor(m_bluecolor);    // change the background  
			// color [background colour  
			// of the text ONLY]  
			pDC->SetTextColor(m_textcolor); // change the text color  
			hbr = (HBRUSH) m_bluebrush;    // apply the blue brush  
			// [this fills the control  
			// rectangle]  
			break;    
			// second CEdit control ID  
		case IDC_EDIT2:         // �ڶ����ı���  
			// but control is still  
			// filled with the brush  
			// color!  
			pDC->SetBkMode(TRANSPARENT);   // make background  
			// transparent [only affects  
			// the TEXT itself]  
			pDC->SetTextColor(m_textcolor); // change the text color  
			hbr = (HBRUSH) m_redbrush;     // apply the red brush  
			// [this fills the control  
			// rectangle]  
			break;  
		default:  
			hbr=CDialog::OnCtlColor(pDC,pWnd,nCtlColor);  
			break;  
		}  
		break;  
	}  

	// TODO:  ���Ĭ�ϵĲ������軭�ʣ��򷵻���һ������
	return hbr;
}
CString g_strLog;

LRESULT CEditControlColorChangeDlg::OnMyMessage(WPARAM wParam, LPARAM lParam)
{
	//TODO: Add your message handle code
	CString *cstr = (CString*)wParam;
	CString strTime;
	CTime curTime = CTime::GetCurrentTime();
	strTime = curTime.Format(_T("%Y-%m-%d %H:%M:%S "));
	UpdateData(TRUE);
	g_strLog += strTime;
	g_strLog += *cstr;
	/*g_strLog += *cstr;*/
	g_strLog += "\r\n";
	
	
	m_edit1.SetWindowText(g_strLog);
	m_edit1.SetScrollPos(SB_VERT,m_edit1.GetLineCount(),TRUE);
	m_edit1.LineScroll(m_edit1.GetLineCount());  
	
	
	UpdateData(FALSE);
	return 0;
}

void CEditControlColorChangeDlg::OnTimer(UINT_PTR nIDEvent)
{
	// TODO: �ڴ������Ϣ�����������/�����Ĭ��ֵ
	CString strL = _T("test\n\n");
	SendMessage(WM_MY_MESSAGE, WPARAM(&strL), 0);
	CDialog::OnTimer(nIDEvent);
}
