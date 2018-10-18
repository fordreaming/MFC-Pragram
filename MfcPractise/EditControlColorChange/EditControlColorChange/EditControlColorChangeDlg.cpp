
// EditControlColorChangeDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "EditControlColorChange.h"
#include "EditControlColorChangeDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
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


// CEditControlColorChangeDlg 对话框




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


// CEditControlColorChangeDlg 消息处理程序

BOOL CEditControlColorChangeDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
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

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码  

	m_redcolor=RGB(255,0,0);                      // 红色  
	m_bluecolor=RGB(0,0,255);                     // 蓝色  
	m_textcolor=RGB(255,255,255);                 // 文本颜色设置为白色  
	m_redbrush.CreateSolidBrush(m_redcolor);      // 红色背景色  
	m_bluebrush.CreateSolidBrush(m_bluecolor);    // 蓝色背景色 

	
	SetTimer(1,10000,NULL);

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
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

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CEditControlColorChangeDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CEditControlColorChangeDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


HBRUSH CEditControlColorChangeDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH hbr = CDialog::OnCtlColor(pDC, pWnd, nCtlColor);

	// TODO:  在此更改 DC 的任何属性
	switch (nCtlColor) //对所有同一类型的控件进行判断  
	{  
		// process my edit controls by ID.  
	//case CTLCOLOR_EDIT:  
	case CTLCOLOR_MSGBOX://假设控件是文本框或者消息框，则进入下一个switch  
		switch (pWnd->GetDlgCtrlID())//对某一个特定控件进行判断  
		{      
			// first CEdit control ID  
		case IDC_EDIT1:         // 第一个文本框  
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
		case IDC_EDIT2:         // 第二个文本框  
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

	// TODO:  如果默认的不是所需画笔，则返回另一个画笔
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
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	CString strL = _T("test\n\n");
	SendMessage(WM_MY_MESSAGE, WPARAM(&strL), 0);
	CDialog::OnTimer(nIDEvent);
}
