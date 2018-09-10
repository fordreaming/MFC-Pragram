// IpMonitorDlg.h : ͷ�ļ�
//

#pragma once
#include "afxcmn.h"
#include "afxwin.h"

#include "pcap.h"
#include "set"

// CIpMonitorDlg �Ի���
class CIpMonitorDlg : public CDialog
{
// ����
public:
	CIpMonitorDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_IPMONITOR_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg LRESULT OnDisplayHostInfo(WPARAM wParam,LPARAM lParam);
	afx_msg LRESULT OnPacketHandle(WPARAM wParam, LPARAM lParam);
	DECLARE_MESSAGE_MAP()
public:
	// �ؼ���Ϣ
	// ������Ϣ�б�
	CListCtrl m_list_adapter;
	// �����������ڵĻ����
	CButton m_btn_search;
	// ����ѡ�������豸
	CButton m_btn_repick;
	// ѡ�������豸��������Ϣ
	CStatic m_static_adapter;
	// �������ڻ������Ϣ
	CListCtrl m_list_host;
	// ����ʱ��
	CEdit m_edit_capture_time;
	// �������ؾ������ڻ������Ϊ��״̬
	CStatic m_static_status;
	// ��ʼ����
	CButton m_btn_capture;
	// IP���ݰ�ͳ����Ϣ�б�
	CListCtrl m_list_ip_packet;
	// �˳�
	CButton m_btn_exit;
	// ֹͣ���������
	CButton m_btn_stop;
	// Ŀ��IP��ַ
	CComboBox m_combo_ip;


	// ������Ϣ
	// �����������б�
	pcap_if_t *m_dev_list;
	// ѡ��������������ID
	CString m_dev_id;
	// ѡ��������������IP��ַ
	DWORD m_ip;
	// ѡ��������������IP��ַ����������
	DWORD m_mask;
	// ѡ��������������MAC��ַ
	unsigned char *m_mac;
	// ����ARP�������ݰ��߳�
	CWinThread *m_pSendThread;
	// ����ARP��Ӧ���ݰ��߳�
	CWinThread *m_pRecvThread;
	// �򿪵��������
	pcap_t *m_pAdapterHandle;
	// ���ؾ������ڻ����̨��
	int m_count;
	// ���񵽵�Tcp���ݰ�����ͷ���
	struct PacketInfo_t *m_tcp_list;
	// ���񵽵�Udp���ݰ�����ͷ���
	struct PacketInfo_t *m_udp_list;
	// ���񵽵����������ݰ���list�е���ʾλ��
	int m_packet_pos;







	// ��ȡ������Ϣ�б�
	bool GetDevList();
	// ��ȡѡ������MAC��ַ
	bool GetLocalMac();
	// ��װARP�㲥���ݰ�
	unsigned char* EnArpPacket(DWORD destip);

	afx_msg void OnNMClickListAdapter(NMHDR *pNMHDR, LRESULT *pResult);
	
	afx_msg void OnBnClickedButtonSearch();
	
	afx_msg void OnBnClickedButtonStop();
	afx_msg void OnBnClickedButtonRepick();
	afx_msg void OnBnClickedButtonExit();
	afx_msg void OnBnClickedButtonCapture();
};
