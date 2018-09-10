// IpMonitorDlg.h : 头文件
//

#pragma once
#include "afxcmn.h"
#include "afxwin.h"

#include "pcap.h"
#include "set"

// CIpMonitorDlg 对话框
class CIpMonitorDlg : public CDialog
{
// 构造
public:
	CIpMonitorDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_IPMONITOR_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg LRESULT OnDisplayHostInfo(WPARAM wParam,LPARAM lParam);
	afx_msg LRESULT OnPacketHandle(WPARAM wParam, LPARAM lParam);
	DECLARE_MESSAGE_MAP()
public:
	// 控件信息
	// 网卡信息列表
	CListCtrl m_list_adapter;
	// 搜索局域网内的活动主机
	CButton m_btn_search;
	// 重新选择网卡设备
	CButton m_btn_repick;
	// 选中网卡设备的描述信息
	CStatic m_static_adapter;
	// 局域网内活动主机信息
	CListCtrl m_list_host;
	// 捕获时间
	CEdit m_edit_capture_time;
	// 搜索本地局域网内活动主机行为的状态
	CStatic m_static_status;
	// 开始捕获
	CButton m_btn_capture;
	// IP数据包统计信息列表
	CListCtrl m_list_ip_packet;
	// 退出
	CButton m_btn_exit;
	// 停止搜索活动主机
	CButton m_btn_stop;
	// 目标IP地址
	CComboBox m_combo_ip;


	// 数据信息
	// 网络适配器列表
	pcap_if_t *m_dev_list;
	// 选定的网络适配器ID
	CString m_dev_id;
	// 选定的网络适配器IP地址
	DWORD m_ip;
	// 选定的网络适配器IP地址的子网掩码
	DWORD m_mask;
	// 选定的网络适配器MAC地址
	unsigned char *m_mac;
	// 发送ARP请求数据包线程
	CWinThread *m_pSendThread;
	// 接收ARP响应数据包线程
	CWinThread *m_pRecvThread;
	// 打开的网卡句柄
	pcap_t *m_pAdapterHandle;
	// 本地局域网内活动主机台数
	int m_count;
	// 捕获到的Tcp数据包链表头结点
	struct PacketInfo_t *m_tcp_list;
	// 捕获到的Udp数据包链表头结点
	struct PacketInfo_t *m_udp_list;
	// 捕获到的新类型数据包在list中的显示位置
	int m_packet_pos;







	// 获取网卡信息列表
	bool GetDevList();
	// 获取选定网卡MAC地址
	bool GetLocalMac();
	// 封装ARP广播数据包
	unsigned char* EnArpPacket(DWORD destip);

	afx_msg void OnNMClickListAdapter(NMHDR *pNMHDR, LRESULT *pResult);
	
	afx_msg void OnBnClickedButtonSearch();
	
	afx_msg void OnBnClickedButtonStop();
	afx_msg void OnBnClickedButtonRepick();
	afx_msg void OnBnClickedButtonExit();
	afx_msg void OnBnClickedButtonCapture();
};
