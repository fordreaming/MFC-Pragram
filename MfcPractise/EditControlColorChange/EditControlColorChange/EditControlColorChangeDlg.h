
// EditControlColorChangeDlg.h : ͷ�ļ�
//

#pragma once
#include "afxwin.h"

#define WM_MY_MESSAGE (WM_USER + 100)

// CEditControlColorChangeDlg �Ի���
class CEditControlColorChangeDlg : public CDialog
{
// ����
public:
	CEditControlColorChangeDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_EDITCONTROLCOLORCHANGE_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��

protected:  
	CBrush m_redbrush,m_bluebrush;  
	COLORREF m_redcolor,m_bluecolor,m_textcolor; 


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
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
