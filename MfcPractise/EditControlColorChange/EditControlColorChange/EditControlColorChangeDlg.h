
// EditControlColorChangeDlg.h : 头文件
//

#pragma once
#include "afxwin.h"

#define WM_MY_MESSAGE (WM_USER + 100)

// CEditControlColorChangeDlg 对话框
class CEditControlColorChangeDlg : public CDialog
{
// 构造
public:
	CEditControlColorChangeDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_EDITCONTROLCOLORCHANGE_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持

protected:  
	CBrush m_redbrush,m_bluebrush;  
	COLORREF m_redcolor,m_bluecolor,m_textcolor; 


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg LRESULT OnMyMessage(WPARAM wParam, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	CEdit m_edit1;
	afx_msg void OnTimer(UINT_PTR nIDEvent);

	CFont font;
};
