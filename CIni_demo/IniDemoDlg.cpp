// IniDemoDlg.cpp : implementation file
//

#include "stdafx.h"
#include "IniDemo.h"
#include "IniDemoDlg.h"
#include "filedialogex.h"
#include "sectkeydlg.h"
#include "InputDlg.h"
#include "BaseDlg.h"
#include "ArrayDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

// submenu indices
enum { MNU_STRING = 0, MNU_INT, MNU_BOOL, MNU_DBL, MNU_STRUCT, MNU_SECT, MNU_KEY };

/////////////////////////////////////////////////////////////////////////////
// CAboutDlg dialog used for App About

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// Dialog Data
	//{{AFX_DATA(CAboutDlg)
	enum { IDD = IDD_ABOUTBOX };
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CAboutDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	//{{AFX_MSG(CAboutDlg)
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
	//{{AFX_DATA_INIT(CAboutDlg)
	//}}AFX_DATA_INIT
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CAboutDlg)
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
	//{{AFX_MSG_MAP(CAboutDlg)
		// No message handlers
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CIniDemoDlg dialog

CIniDemoDlg::CIniDemoDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CIniDemoDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CIniDemoDlg)
	//}}AFX_DATA_INIT
	// Note that LoadIcon does not require a subsequent DestroyIcon in Win32
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	
	// Initialization
	::GetModuleFileName(NULL, m_sAppPath.GetBuffer(MAX_PATH), MAX_PATH);
	m_sAppPath.ReleaseBuffer();

	if (m_sAppPath.Find('\\') != -1)
	{
		for (int i = m_sAppPath.GetLength() - 1; i >= 0; i--)
		{
			TCHAR ch = m_sAppPath[i];
			m_sAppPath.Delete(i);
			if (ch == '\\')
				break;	
		}
	}

	CIni ini;
	ini.SetPathName(m_sAppPath + _T("\\IniDemo.ini"));
	m_ini.SetPathName(ini.GetString(_T("Settings"), _T("Last File"), m_sAppPath + _T("\\Test.Ini")));
	m_nBase = ini.GetInt(_T("Settings"), _T("Integer Base"), BASE_DECIMAL);
	m_nPrecision = ini.GetInt(_T("Settings"), _T("Double Precision"), -1);	
	m_sDelimiter = ini.GetString(_T("Settings"), _T("Delimiter"), _T(","));
	m_sInput = ini.GetString(_T("History"), _T("Input"));
}

void CIniDemoDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CIniDemoDlg)
	DDX_Control(pDX, IDC_STRUCT, m_wndStruct);
	DDX_Control(pDX, IDC_SECTION, m_wndSection);
	DDX_Control(pDX, IDC_KEYS, m_wndKey);
	DDX_Control(pDX, IDC_INT, m_wndInt);
	DDX_Control(pDX, IDC_DOUBLE, m_wndDouble);
	DDX_Control(pDX, IDC_BOOL, m_wndBool);
	DDX_Control(pDX, IDC_STRINGS, m_wndString);
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CIniDemoDlg, CDialog)
	//{{AFX_MSG_MAP(CIniDemoDlg)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_SELFILE, OnSelfile)
	ON_BN_CLICKED(IDC_RELOAD, OnReload)
	ON_BN_CLICKED(IDC_ABOUT, OnAbout)
	ON_COMMAND(ID_GETSTRING, OnGetstring)
	ON_WM_DESTROY()
	ON_COMMAND(ID_WRITESTRING, OnWritestring)
	ON_COMMAND(ID_APPENDSTRING, OnAppendstring)
	ON_COMMAND(ID_GETINT, OnGetint)
	ON_COMMAND(ID_WRITEINT, OnWriteint)
	ON_COMMAND(ID_INCREASEINT, OnIncreaseint)
	ON_COMMAND(ID_BASE, OnBase)
	ON_UPDATE_COMMAND_UI(ID_BASE, OnUpdateBase)
	ON_COMMAND(ID_GETARRAY, OnGetarray)
	ON_COMMAND(ID_WRITEARRAY, OnWritearray)
	ON_COMMAND(ID_GETBOOL, OnGetbool)
	ON_COMMAND(ID_WRITEBOOL, OnWritebool)
	ON_COMMAND(ID_INVERTBOOL, OnInvertbool)
	ON_COMMAND(ID_GETDOUBLE, OnGetdouble)
	ON_COMMAND(ID_WRITEDOUBLE, OnWritedouble)
	ON_COMMAND(ID_INCREASEDOUBLE, OnIncreasedouble)
	ON_COMMAND(ID_GETPOINT, OnGetpoint)
	ON_COMMAND(ID_WRITEPOINT, OnWritepoint)
	ON_COMMAND(ID_GETRECT, OnGetrect)
	ON_COMMAND(ID_WRITERECT, OnWriterect)
	ON_COMMAND(ID_SECTEXIST, OnSectexist)
	ON_COMMAND(ID_SECT_LIST, OnSectList)
	ON_COMMAND(ID_SECT_COPY, OnSectCopy)
	ON_COMMAND(ID_SECT_DELETE, OnSectDelete)
	ON_COMMAND(ID_SECT_MOVE, OnSectMove)
	ON_COMMAND(ID_KEYEXIST, OnKeyexist)
	ON_COMMAND(ID_KEY_LIST, OnKeyList)
	ON_COMMAND(ID_KEY_COPY, OnKeyCopy)
	ON_COMMAND(ID_KEY_DELETE, OnKeyDelete)
	ON_COMMAND(ID_KEY_MOVE, OnKeyMove)
	ON_COMMAND(ID_KEY_LISTNAME, OnKeyListname)
	ON_COMMAND(ID_GETBYTES, OnGetbytes)
	ON_COMMAND(ID_WRITEBYTES, OnWritebytes)
	ON_BN_CLICKED(IDC_STRINGS, OnGetstring)
	ON_BN_CLICKED(IDC_INT, OnGetint)
	ON_BN_CLICKED(IDC_BOOL, OnGetbool)
	ON_BN_CLICKED(IDC_DOUBLE, OnGetdouble)
	ON_BN_CLICKED(IDC_SECTION, OnSectList)
	ON_BN_CLICKED(IDC_KEYS, OnKeyList)
	ON_COMMAND(ID_APPEND_BLK, OnAppendBlk)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CIniDemoDlg message handlers

BOOL CIniDemoDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon
	
	// TODO: Add extra initialization here
	srand((unsigned int)time(NULL));
	m_wndString.SetSSLButtonStyle(SSL_BS_MENU_BTN);
	m_wndString.SetSSLButtonMenu(IDR_MENU1, MNU_STRING);

	m_wndStruct.SetSSLButtonStyle(SSL_BS_MENU_BTN);
	m_wndStruct.SetSSLButtonMenu(IDR_MENU1, MNU_STRUCT);

	m_wndSection.SetSSLButtonStyle(SSL_BS_MENU_BTN);
	m_wndSection.SetSSLButtonMenu(IDR_MENU1, MNU_SECT);

	m_wndKey.SetSSLButtonStyle(SSL_BS_MENU_BTN);
	m_wndKey.SetSSLButtonMenu(IDR_MENU1, MNU_KEY);

	m_wndInt.SetSSLButtonStyle(SSL_BS_MENU_BTN);
	m_wndInt.SetSSLButtonMenu(IDR_MENU1, MNU_INT);

	m_wndDouble.SetSSLButtonStyle(SSL_BS_MENU_BTN);
	m_wndDouble.SetSSLButtonMenu(IDR_MENU1, MNU_DBL);

	m_wndBool.SetSSLButtonStyle(SSL_BS_MENU_BTN);
	m_wndBool.SetSSLButtonMenu(IDR_MENU1, MNU_BOOL);

	LoadFile(NULL);

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CIniDemoDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CIniDemoDlg::OnPaint() 
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, (WPARAM) dc.GetSafeHdc(), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CIniDemoDlg::OnQueryDragIcon()
{
	return (HCURSOR) m_hIcon;
}


void CIniDemoDlg::OnSelfile() 
{
	// TODO: Add your control notification handler code here
	CFileDialogEx dlg(TRUE, _T("ini"), NULL, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT, 
		_T("Ini Files (*.ini)|*.ini|All Files (*.*)|*.*||"),
		this);

	if (dlg.DoModal() == IDOK)
		LoadFile(dlg.GetPathName());
}

BOOL CIniDemoDlg::LoadFile(LPCTSTR lpPathName)
{
	SetDlgItemText(IDC_EDIT1, _T(""));
	CString sTitle = _T("Ini Demo");
	if (lpPathName != NULL)
		m_ini.SetPathName(lpPathName);
	
	if (!m_ini.GetPathName().IsEmpty())
		sTitle.Format(_T("Ini Demo - [%s]"), m_ini.GetPathName());
	SetWindowText(sTitle);

	CStdioFile file;
	if (!file.Open(m_ini.GetPathName(), CFile::modeRead))
		return FALSE;

	CString sContents, sLine;
	while (file.ReadString(sLine))
		sContents += sLine + _T("\r\n");

	file.Close();
	sContents.TrimRight();
	SetDlgItemText(IDC_EDIT1, sContents);
	return TRUE;	
}

void CIniDemoDlg::OnReload() 
{
	// TODO: Add your control notification handler code here
	LoadFile(NULL);
}

void CIniDemoDlg::OnAbout() 
{
	// TODO: Add your control notification handler code here
	CAboutDlg dlg;
	dlg.DoModal();
}

BOOL CIniDemoDlg::SelectSource(BOOL bSectionOnly)
{
	CSectKeyDlg dlg(m_ini.GetPathName(), bSectionOnly, _T("Select Source"));
	if (dlg.DoModal() != IDOK)
		return FALSE;

	m_sSection1 = dlg.GetSection();
	m_sKey1 = dlg.GetKey();
	return TRUE;
}

BOOL CIniDemoDlg::SelectTarget(BOOL bSectionOnly)
{
	CSectKeyDlg dlg(m_ini.GetPathName(), bSectionOnly, _T("Select Destination"));
	if (dlg.DoModal() != IDOK)
		return FALSE;

	m_sSection2 = dlg.GetSection();
	m_sKey2 = dlg.GetKey();
	return TRUE;
}

void CIniDemoDlg::OnGetstring() 
{
	// TODO: Add your command handler code here
	if (!SelectSource(FALSE))
		return;

	CString str;
	str.Format(_T("String Value:\n\n%s"), m_ini.GetString(m_sSection1, m_sKey1, _T("(null)")));
	MessageBox(str, _T("Read String Operation"));
}

void CIniDemoDlg::OnDestroy() 
{
	CDialog::OnDestroy();
	
	// TODO: Add your message handler code here
	CIni ini;
	ini.SetPathName(m_sAppPath + _T("\\IniDemo.ini"));
	ini.WriteString(_T("Settings"), _T("Last File"), m_ini.GetPathName());
	ini.WriteInt(_T("Settings"), _T("Integer Base"), m_nBase);
	ini.WriteInt(_T("Settings"), _T("Double Precision"), m_nPrecision);
	ini.WriteString(_T("Settings"), _T("Delimiter"), m_sDelimiter);
	ini.WriteString(_T("History"), _T("Input"), m_sInput);
}

void CIniDemoDlg::OnWritestring() 
{
	// TODO: Add your command handler code here
	CString s;
	if (SelectTarget(FALSE) && InputString(_T("String to write"), s))
		EndOperation(_T("Write String"), m_ini.WriteString(m_sSection2, m_sKey2, s));
}

BOOL CIniDemoDlg::InputString(LPCTSTR lpPrompt, CString &s)
{
	CInputDlg dlg(lpPrompt, TYPE_STRING, m_nPrecision, m_sInput);
	if (dlg.DoModal() != IDOK)
		 return FALSE;
	m_sInput = dlg.GetData();
	s = m_sInput;
	return TRUE;
}

BOOL CIniDemoDlg::InputInt(LPCTSTR lpPrompt, int &n)
{
	CInputDlg dlg(lpPrompt, TYPE_INT, m_nPrecision, m_sInput);
	if (dlg.DoModal() != IDOK)
		 return FALSE;
	m_sInput = dlg.GetData();
	n = _tcstol(m_sInput, NULL, 10);
	return TRUE;
}

BOOL CIniDemoDlg::InputDouble(LPCTSTR lpPrompt, double &f)
{
	CInputDlg dlg(lpPrompt, TYPE_DOUBLE, m_nPrecision, m_sInput);
	if (dlg.DoModal() != IDOK)
		 return FALSE;
	dlg.GetPrecision(m_nPrecision);
	m_sInput = dlg.GetData();
	f = _tcstod(m_sInput, NULL);
	return TRUE;
}

void CIniDemoDlg::EndOperation(LPCTSTR lpPrompt, BOOL bSuccessful, LPCTSTR lpMsg)
{
	if (bSuccessful)
	{
		OnReload();
		MessageBox(lpMsg == NULL ? _T("Operation completed successfully.") : lpMsg, lpPrompt, MB_ICONINFORMATION);
	}
	else
	{
		MessageBox(_T("Operation failed."), lpPrompt, MB_ICONEXCLAMATION);
	}	 
}

void CIniDemoDlg::OnAppendstring() 
{
	// TODO: Add your command handler code here
	CString s;
	if (SelectTarget(FALSE) && InputString(_T("String to Append"), s))
		EndOperation(_T("Append String"), m_ini.AppendString(m_sSection2, m_sKey2, s));
}

void CIniDemoDlg::OnGetint() 
{
	// TODO: Add your command handler code here
	if (!SelectSource(FALSE))
		return;

	CString str;
	str.Format(_T("Int Value:\n\n%d"), m_ini.GetInt(m_sSection1, m_sKey1, 0));
	MessageBox(str, _T("Read Int Operation"));
}

void CIniDemoDlg::OnWriteint() 
{
	// TODO: Add your command handler code here
	int n;
	if (SelectTarget(FALSE) && InputInt(_T("Integer to Write"), n))
		EndOperation(_T("Write Int"), m_ini.WriteInt(m_sSection2, m_sKey2, n, m_nBase));
}

void CIniDemoDlg::OnIncreaseint() 
{
	// TODO: Add your command handler code here
	int n;
	if (SelectTarget(FALSE) && InputInt(_T("Increase by"), n))
		EndOperation(_T("Increase Int"), m_ini.IncreaseInt(m_sSection2, m_sKey2, n, m_nBase));
}

void CIniDemoDlg::OnBase() 
{
	// TODO: Add your command handler code here
	CBaseDlg dlg(m_nBase);
	if (dlg.DoModal() == IDOK)
		m_nBase = dlg.GetBase();
}

void CIniDemoDlg::OnUpdateBase(CCmdUI* pCmdUI) 
{
	// TODO: Add your command update UI handler code here
	CString s;
	s.Format(_T("Base: %d"), m_nBase);
	pCmdUI->SetText(s);
}

void CIniDemoDlg::OnGetarray() 
{
	// TODO: Add your command handler code here
	if (!SelectSource(FALSE) || !InputString(_T("Array Delimiter"), m_sDelimiter))
		return;

	if (m_sDelimiter.IsEmpty())
		m_sDelimiter = _T(",");

	CStringArray aArray;
	CString str("String Array Contents:\n\n");
	m_ini.GetArray(m_sSection1, m_sKey1, &aArray, m_sDelimiter);

	for (int i = 0; i < aArray.GetSize(); i++)
	{
		str += aArray[i] + _T("\n");
	}
	str.TrimRight();
	MessageBox(str, _T("Read Array Operation"));
}

void CIniDemoDlg::OnWritearray() 
{
	// TODO: Add your command handler code here
	if (!SelectTarget(FALSE))
		return;
	
	CArrayDlg dlg;
	if (dlg.DoModal() != IDOK)
		return;
	
	if (!InputString(_T("Array Delimiter"), m_sDelimiter))
		return;

	EndOperation(_T("Write Array"), m_ini.WriteArray(m_sSection2, m_sKey2, dlg.GetArray(), -1, m_sDelimiter));
}

void CIniDemoDlg::OnGetbool() 
{
	// TODO: Add your command handler code here
	if (!SelectSource(FALSE))
		return;

	CString str;
	str.Format(_T("Bool Value:\n\n%s"), m_ini.GetBool(m_sSection1, m_sKey1, FALSE) ? _T("TRUE") : _T("FALSE"));
	MessageBox(str, _T("Read Bool Operation"));
}

void CIniDemoDlg::OnWritebool() 
{
	// TODO: Add your command handler code here
	CString s;
	if (SelectTarget(FALSE) && InputString(_T("Bool to Write"), s))
		EndOperation(_T("Write Bool"), m_ini.WriteBool(m_sSection2, m_sKey2, m_ini.StringToBool(s, FALSE)));
}

void CIniDemoDlg::OnInvertbool() 
{
	// TODO: Add your command handler code here
	if (SelectTarget(FALSE))
		EndOperation(_T("Invert Bool"), m_ini.InvertBool(m_sSection2, m_sKey2));	
}

void CIniDemoDlg::OnGetdouble() 
{
	// TODO: Add your command handler code here
	if (!SelectSource(FALSE))
		return;

	CString str;
	str.Format(_T("Double Value:\n\n%f"), m_ini.GetDouble(m_sSection1, m_sKey1, 0.0));
	MessageBox(str, _T("Read Double Operation"));
}

void CIniDemoDlg::OnWritedouble() 
{
	// TODO: Add your command handler code here
	double f;
	if (SelectTarget(FALSE) && InputDouble(_T("Double to Write"), f))
		EndOperation(_T("Write Double"), m_ini.WriteDouble(m_sSection2, m_sKey2, f, m_nPrecision));
}

void CIniDemoDlg::OnIncreasedouble() 
{
	// TODO: Add your command handler code here
	double f;
	if (SelectTarget(FALSE) && InputDouble(_T("Increase by"), f))
		EndOperation(_T("Increase Double"), m_ini.IncreaseDouble(m_sSection2, m_sKey2, f, m_nPrecision));
}

BOOL CIniDemoDlg::PreTranslateMessage(MSG* pMsg) 
{
	// TODO: Add your specialized code here and/or call the base class
	if (pMsg->message == WM_CHAR)
		return TRUE;
	
	return CDialog::PreTranslateMessage(pMsg);
}

void CIniDemoDlg::OnGetpoint() 
{
	// TODO: Add your command handler code here
	if (!SelectSource(FALSE))
		return;

	CString str;
	POINT pt = m_ini.GetPoint(m_sSection1, m_sKey1, CPoint(0, 0));
	str.Format(_T("POINT Value:\n\nx = %d\ny = %d"), pt.x, pt.y);
	MessageBox(str, _T("Read POINT Operation"));
}

void CIniDemoDlg::OnWritepoint() 
{
	// TODO: Add your command handler code here
	POINT pt;
	::GetCursorPos(&pt);
	if (SelectTarget(FALSE))
		EndOperation(_T("Write POINT"), m_ini.WritePoint(m_sSection2, m_sKey2, pt), _T("Current mouse cursor position has been written to the ini file."));
}

void CIniDemoDlg::OnGetrect() 
{
	// TODO: Add your command handler code here
	if (!SelectSource(FALSE))
		return;

	CString str;
	RECT rc = m_ini.GetRect(m_sSection1, m_sKey1, CRect(0, 0, 0, 0));
	str.Format(_T("RECT Value:\n\nleft = %d\ntop = %d\nright = %d\nbottom = %d"), rc.left, rc.top, rc.right, rc.bottom);
	MessageBox(str, _T("Read RECT Operation"));
}

void CIniDemoDlg::OnWriterect() 
{
	// TODO: Add your command handler code here
	RECT rc;
	this->GetWindowRect(&rc);
	if (SelectTarget(FALSE))
		EndOperation(_T("Write RECT"), m_ini.WriteRect(m_sSection2, m_sKey2, rc), _T("Current window boundary rectangle has been written to the ini file."));
}

void CIniDemoDlg::OnSectexist() 
{
	// TODO: Add your command handler code here
	if (!SelectSource(TRUE))
		return;

	CString s;
	s.Format(_T("Section \"%s\" %s."), m_sSection1, m_ini.IsSectionExist(m_sSection1) ? _T("exists") : _T("does not exist"));
	MessageBox(s, _T("Check Section Existence"));	
}

void CIniDemoDlg::OnSectList() 
{
	// TODO: Add your command handler code here
	CStringArray aArray;
	m_ini.GetSectionNames(&aArray);
	CString str("Section list:\n\n");
	for (int i = 0; i < aArray.GetSize(); i++)
		str += aArray[i] + _T("\n");
	str.TrimRight();
	MessageBox(str, _T("Section List"));
}

void CIniDemoDlg::OnSectCopy() 
{
	// TODO: Add your command handler code here
	if (SelectSource(TRUE) && SelectTarget(TRUE))
		EndOperation(_T("Copy Section"), m_ini.CopySection(m_sSection1, m_sSection2, FALSE));
}

void CIniDemoDlg::OnSectDelete() 
{
	// TODO: Add your command handler code here
	if (SelectTarget(TRUE))
		EndOperation(_T("Delete Section"), m_ini.DeleteSection(m_sSection2));
}

void CIniDemoDlg::OnSectMove() 
{
	// TODO: Add your command handler code here
	if (SelectSource(TRUE) && SelectTarget(TRUE))
		EndOperation(_T("Move Section"), m_ini.MoveSection(m_sSection1, m_sSection2));
}

void CIniDemoDlg::OnKeyexist() 
{
	// TODO: Add your command handler code here
	if (!SelectSource(FALSE))
		return;

	CString s;
	s.Format(_T("Key \"%s\" %s in section \"%s\"."), m_sKey1, m_ini.IsKeyExist(m_sSection1, m_sKey1) ? _T("exists") : _T("does not exist"), m_sSection1);
	MessageBox(s, _T("Check Key Existence"));	
}

void CIniDemoDlg::OnKeyList() 
{
	// TODO: Add your command handler code here
	if (!SelectSource(TRUE))
		return;

	CStringArray aArray;
	m_ini.GetKeyLines(m_sSection1, &aArray);
	CString str("Key lines:\n\n");
	for (int i = 0; i < aArray.GetSize(); i++)
		str += aArray[i] + _T("\n");
	str.TrimRight();
	MessageBox(str, _T("Key Lines"));
}

void CIniDemoDlg::OnKeyCopy() 
{
	// TODO: Add your command handler code here
	if (SelectSource(FALSE) && SelectTarget(FALSE))
		EndOperation(_T("Copy Key"), m_ini.CopyKey(m_sSection1, m_sKey1, m_sSection2, m_sKey2, FALSE));
}

void CIniDemoDlg::OnKeyDelete() 
{
	// TODO: Add your command handler code here
	if (SelectTarget(FALSE))
		EndOperation(_T("Delete Key"), m_ini.DeleteKey(m_sSection2, m_sKey2));
}

void CIniDemoDlg::OnKeyMove() 
{
	// TODO: Add your command handler code here
	if (SelectSource(FALSE) && SelectTarget(FALSE))
		EndOperation(_T("Move Key"), m_ini.MoveKey(m_sSection1, m_sKey1, m_sSection2, m_sKey2));
}

void CIniDemoDlg::OnKeyListname() 
{
	// TODO: Add your command handler code here
	if (!SelectSource(TRUE))
		return;

	CStringArray aArray;
	m_ini.GetKeyNames(m_sSection1, &aArray);
	CString str("Key names:\n\n");
	for (int i = 0; i < aArray.GetSize(); i++)
		str += aArray[i] + _T("\n");
	str.TrimRight();
	MessageBox(str, _T("Key Names"));
}

void CIniDemoDlg::OnGetbytes() 
{
	// TODO: Add your command handler code here
	if (!SelectSource(FALSE))
		return;

	BYTE d[256];
	const DWORD LEN = m_ini.GetDataBlock(m_sSection1, m_sKey1, d, 256);
	CString sMsg;
	sMsg.Format(_T("%d bytes of data were successfully read:\n\n"), LEN);

	for (DWORD i = 0; i < LEN; i++)
	{
		CString s;
		s.Format(_T("%d, "), d[i]);
		sMsg += s;
	}

	sMsg.TrimRight(_T(", "));
	MessageBox(sMsg, _T("Get Block"), MB_ICONINFORMATION);
}

void CIniDemoDlg::OnWritebytes() 
{
	// TODO: Add your command handler code here
	if (!SelectTarget(FALSE))
		return;

	BYTE d[5];
	for (int i = 0; i < 5; i++)
		d[i] = BYTE(rand());
	EndOperation(_T("Write Block"), m_ini.WriteDataBlock(m_sSection2, m_sKey2, d, 5), _T("5 random bytes have been written to the ini file."));	
}

void CIniDemoDlg::OnAppendBlk()
{
	// TODO: Add your command handler code here
	BYTE b = BYTE(rand());
	if (SelectTarget(FALSE))
		EndOperation(_T("Append Block"), m_ini.AppendDataBlock(m_sSection2, m_sKey2, &b, 1), _T("One random byte have been appended to the specified key."));	
}
