; CLW file contains information for the MFC ClassWizard

[General Info]
Version=1
LastClass=CIniDemoDlg
LastTemplate=CDialog
NewFileInclude1=#include "stdafx.h"
NewFileInclude2=#include "inidemo.h"
LastPage=0

ClassCount=9
Class1=CButtonSSL
Class2=CFileDialogEx
Class3=CIniDemoApp
Class4=CAboutDlg
Class5=CIniDemoDlg
Class6=CInputDlg
Class7=CSectKeyDlg

ResourceCount=7
Resource1=IDD_ARRAYDLG
Resource2=IDD_BASEDLG
Resource3=IDD_SETCKEYDLG
Resource4=IDD_INPUTDLG
Resource5=IDD_ABOUTBOX (English (U.S.))
Class8=CBaseDlg
Resource6=IDD_INIDEMO_DIALOG (English (U.S.))
Class9=CArrayDlg
Resource7=IDR_MENU1

[CLS:CButtonSSL]
Type=0
BaseClass=CButton
HeaderFile=ButtonSSL.h
ImplementationFile=ButtonSSL.cpp

[CLS:CFileDialogEx]
Type=0
BaseClass=CFileDialog
HeaderFile=FileDialogEx.h
ImplementationFile=FileDialogEx.cpp

[CLS:CIniDemoApp]
Type=0
BaseClass=CWinApp
HeaderFile=IniDemo.h
ImplementationFile=IniDemo.cpp

[CLS:CAboutDlg]
Type=0
BaseClass=CDialog
HeaderFile=IniDemoDlg.cpp
ImplementationFile=IniDemoDlg.cpp
LastObject=CAboutDlg
Filter=D
VirtualFilter=dWC

[CLS:CIniDemoDlg]
Type=0
BaseClass=CDialog
HeaderFile=IniDemoDlg.h
ImplementationFile=IniDemoDlg.cpp
Filter=D
VirtualFilter=dWC
LastObject=ID_WRITEBYTES

[CLS:CInputDlg]
Type=0
BaseClass=CDialog
HeaderFile=InputDlg.h
ImplementationFile=InputDlg.cpp
LastObject=CInputDlg
Filter=D
VirtualFilter=dWC

[CLS:CSectKeyDlg]
Type=0
BaseClass=CDialog
HeaderFile=SectKeyDlg.h
ImplementationFile=SectKeyDlg.cpp
LastObject=CSectKeyDlg
Filter=D
VirtualFilter=dWC

[DLG:IDD_ABOUTBOX]
Type=1
Class=CAboutDlg

[DLG:IDD_INIDEMO_DIALOG]
Type=1
Class=CIniDemoDlg

[DLG:IDD_INPUTDLG]
Type=1
Class=CInputDlg
ControlCount=6
Control1=IDC_PROMPT,static,1342308352
Control2=IDC_EDIT1,edit,1350631552
Control3=IDC_LBL,static,1342308352
Control4=IDC_BASEORPREC,combobox,1344339971
Control5=IDOK,button,1342242817
Control6=IDCANCEL,button,1342242816

[DLG:IDD_SETCKEYDLG]
Type=1
Class=CSectKeyDlg
ControlCount=6
Control1=IDC_STATIC,static,1342308352
Control2=IDC_SECT,combobox,1344339970
Control3=IDC_LBLKEY,static,1342308352
Control4=IDC_KEY,combobox,1344339970
Control5=IDOK,button,1342242817
Control6=IDCANCEL,button,1342242816

[DLG:IDD_ABOUTBOX (English (U.S.))]
Type=1
Class=CAboutDlg
ControlCount=4
Control1=IDC_STATIC,static,1342177283
Control2=IDC_STATIC,static,1342308480
Control3=IDC_STATIC,static,1342308352
Control4=IDOK,button,1342373889

[DLG:IDD_INIDEMO_DIALOG (English (U.S.))]
Type=1
Class=CIniDemoDlg
ControlCount=14
Control1=IDC_STATIC,static,1342308352
Control2=IDC_EDIT1,edit,1353715716
Control3=IDC_SELFILE,button,1342242816
Control4=IDC_RELOAD,button,1342242816
Control5=IDC_ABOUT,button,1342242816
Control6=IDCANCEL,button,1342242816
Control7=IDC_STATIC,static,1342308352
Control8=IDC_STRINGS,button,1342242816
Control9=IDC_INT,button,1342242816
Control10=IDC_BOOL,button,1342242816
Control11=IDC_DOUBLE,button,1342242816
Control12=IDC_STRUCT,button,1342242816
Control13=IDC_SECTION,button,1342242816
Control14=IDC_KEYS,button,1342242816

[MNU:IDR_MENU1]
Type=1
Class=CIniDemoDlg
Command1=ID_GETSTRING
Command2=ID_WRITESTRING
Command3=ID_APPENDSTRING
Command4=ID_GETARRAY
Command5=ID_WRITEARRAY
Command6=ID_BASE
Command7=ID_GETINT
Command8=ID_WRITEINT
Command9=ID_INCREASEINT
Command10=ID_GETBOOL
Command11=ID_WRITEBOOL
Command12=ID_INVERTBOOL
Command13=ID_GETDOUBLE
Command14=ID_WRITEDOUBLE
Command15=ID_INCREASEDOUBLE
Command16=ID_GETPOINT
Command17=ID_WRITEPOINT
Command18=ID_GETRECT
Command19=ID_WRITERECT
Command20=ID_GETBYTES
Command21=ID_WRITEBYTES
Command22=ID_APPEND_BLK
Command23=ID_SECTEXIST
Command24=ID_SECT_LIST
Command25=ID_SECT_COPY
Command26=ID_SECT_DELETE
Command27=ID_SECT_MOVE
Command28=ID_KEYEXIST
Command29=ID_KEY_LIST
Command30=ID_KEY_LISTNAME
Command31=ID_KEY_COPY
Command32=ID_KEY_DELETE
Command33=ID_KEY_MOVE
CommandCount=33

[DLG:IDD_BASEDLG]
Type=1
Class=CBaseDlg
ControlCount=2
Control1=IDOK,button,1342242817
Control2=IDC_COMBO1,combobox,1344339971

[CLS:CBaseDlg]
Type=0
HeaderFile=BaseDlg.h
ImplementationFile=BaseDlg.cpp
BaseClass=CDialog
Filter=D
LastObject=CBaseDlg
VirtualFilter=dWC

[DLG:IDD_ARRAYDLG]
Type=1
Class=CArrayDlg
ControlCount=5
Control1=IDC_LIST1,listbox,1352679681
Control2=IDC_EDIT1,edit,1350631552
Control3=IDC_ADD,button,1342242816
Control4=IDOK,button,1342242817
Control5=IDCANCEL,button,1342242816

[CLS:CArrayDlg]
Type=0
HeaderFile=ArrayDlg.h
ImplementationFile=ArrayDlg.cpp
BaseClass=CDialog
Filter=D
VirtualFilter=dWC
LastObject=IDC_EDIT1

