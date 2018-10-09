// IpMonitorDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "IpMonitor.h"
#include "IpMonitorDlg.h"

#include "Packet32.h"
#include "winsock2.h"
#include "ntddndis.h"
#include "stdlib.h"
#include "DataType.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define MSG_RECV_ARP WM_USER + 1
#define MSG_RECV_TCP_UDP WM_USER + 2


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���
UINT SendThread(LPVOID lpParam);
UINT RecvThread(LPVOID lpParam);

//�����߳�ִ�б�־
bool g_run = false;

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


// CIpMonitorDlg �Ի���




CIpMonitorDlg::CIpMonitorDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CIpMonitorDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	
	//������ʼ��
	m_dev_list = NULL;
	m_dev_id = "";
	m_ip = 0;
	m_mac = new unsigned char[6];
	m_pSendThread = NULL;
	m_pRecvThread = NULL;
	m_mask = 0;
	m_pAdapterHandle = NULL;
	m_count = 0;
	m_tcp_list = NULL;
	m_udp_list = NULL;
	m_packet_pos = 0;
}

void CIpMonitorDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_ADAPTER, m_list_adapter);
	DDX_Control(pDX, IDC_BUTTON_SEARCH, m_btn_search);
	DDX_Control(pDX, IDC_BUTTON_REPICK, m_btn_repick);
	DDX_Control(pDX, IDC_STATIC_INFO_ADAPTER_PICKED, m_static_adapter);
	DDX_Control(pDX, IDC_LIST_HOST, m_list_host);
	DDX_Control(pDX, IDC_EDIT_CAPTURE_TIME, m_edit_capture_time);
	DDX_Control(pDX, IDC_BUTTON_CAPTURE, m_btn_capture);
	DDX_Control(pDX, IDC_LIST_IP_PACKET, m_list_ip_packet);
	DDX_Control(pDX, IDC_BUTTON_EXIT, m_btn_exit);
	DDX_Control(pDX, IDC_BUTTON_STOP, m_btn_stop);
	DDX_Control(pDX, IDC_STATIC_STATUS, m_static_status);
	DDX_Control(pDX, IDC_COMBO1, m_combo_ip);
}

BEGIN_MESSAGE_MAP(CIpMonitorDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_NOTIFY(NM_CLICK, IDC_LIST_ADAPTER, &CIpMonitorDlg::OnNMClickListAdapter)
	ON_BN_CLICKED(IDC_BUTTON_SEARCH, &CIpMonitorDlg::OnBnClickedButtonSearch)
	ON_MESSAGE(MSG_RECV_ARP, OnDisplayHostInfo)
	ON_MESSAGE(MSG_RECV_TCP_UDP, OnPacketHandle)
	ON_BN_CLICKED(IDC_BUTTON_STOP, &CIpMonitorDlg::OnBnClickedButtonStop)
	ON_BN_CLICKED(IDC_BUTTON_REPICK, &CIpMonitorDlg::OnBnClickedButtonRepick)
	ON_BN_CLICKED(IDC_BUTTON_EXIT, &CIpMonitorDlg::OnBnClickedButtonExit)
	ON_BN_CLICKED(IDC_BUTTON_CAPTURE, &CIpMonitorDlg::OnBnClickedButtonCapture)
END_MESSAGE_MAP()


// CIpMonitorDlg ��Ϣ�������

BOOL CIpMonitorDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
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

	// ���ô˶Ի����ͼ�ꡣ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������

	//������Ϣ�б��ʼ��
	m_list_adapter.InsertColumn(0, "�豸����", 0, 205);
	m_list_adapter.InsertColumn(1, "IP��ַ", 0, 105);
	m_list_adapter.InsertColumn(2, "��������", 0, 105);
	m_list_adapter.InsertColumn(3, "�豸ID", 0, 205);

	if (GetDevList() == false)
	{
		AfxMessageBox("��ȡ�����豸�б�ʧ��");
	}

	//��ť����
	m_btn_capture.EnableWindow(false);
	m_btn_repick.EnableWindow(false);
	m_btn_search.EnableWindow(false);
	m_btn_stop.EnableWindow(false);

	m_static_adapter.SetWindowText("δѡ������");
	m_static_status.SetWindowText("");
	
	m_edit_capture_time.EnableWindow(false);

	//�������ڻ������Ϣ�б��ʼ��
	m_list_host.InsertColumn(0, "IP��ַ", 0, 150);
	m_list_host.InsertColumn(1, "MAC��ַ", 0, 150);

	//IP���ݰ�ͳ����Ϣ��ʼ��
	m_list_ip_packet.InsertColumn(0, "ԴIP��ַ", 0, 120);
	m_list_ip_packet.InsertColumn(1, "Ŀ��IP��ַ", 0, 120);
	m_list_ip_packet.InsertColumn(2, "Դ�˿ں�", 0, 95);
	m_list_ip_packet.InsertColumn(3, "Ŀ��˿ں�", 0, 95);
	m_list_ip_packet.InsertColumn(4, "Э������", 0, 95);
	m_list_ip_packet.InsertColumn(5, "���ݰ�����", 0, 95);

	//Ŀ��IP��ַ���������
	m_combo_ip.EnableWindow(false);

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void CIpMonitorDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

void CIpMonitorDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ��������о���
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

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù����ʾ��
//
HCURSOR CIpMonitorDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

bool CIpMonitorDlg::GetDevList()
//��ȡ������Ϣ�б�
{
	pcap_if_t *tmp;
	pcap_addr_t *maddr;
	char errbuff[100];
	int status, index;
	sockaddr_in *ip;
	bool morethanone;

	index = 0;
	status = pcap_findalldevs(&m_dev_list, errbuff);
	if (status == -1)
	{
		return false;
	}

	for (tmp = m_dev_list; tmp != NULL; tmp = tmp->next)
	{
		CString des = tmp->description;
		des.Replace("Network adapter '", "");
		des.Replace("' on local host", "");

		m_list_adapter.InsertItem(index, des);
		m_list_adapter.SetItemText(index, 3, tmp->name);

		if (tmp->addresses == NULL)
		{
			m_list_adapter.DeleteItem(index);

			continue;
		}

		morethanone = false;
		for (maddr = tmp->addresses; maddr != NULL; maddr = maddr->next)
		{
			if (morethanone)
			{
				m_list_adapter.InsertItem(index, "");
				m_list_adapter.SetItemText(index, 2, tmp->name);
			}

			if (maddr->addr->sa_family == AF_INET)
			{
				ip = (sockaddr_in*) maddr->addr;
				m_list_adapter.SetItemText(index, 1, inet_ntoa(ip->sin_addr));

				ip = (sockaddr_in*) maddr->netmask;
				m_list_adapter.SetItemText(index, 2, inet_ntoa(ip->sin_addr));

				index++;				
				morethanone = true;
			}
		}
	}

	if (m_list_adapter.GetItemCount() == 0)
	{
		return false;
	}

	return true;

}



void CIpMonitorDlg::OnNMClickListAdapter(NMHDR *pNMHDR, LRESULT *pResult)
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	int nItem = -1;

	LPNMITEMACTIVATE lpNMItemActivate = (LPNMITEMACTIVATE)pNMHDR;

	if (lpNMItemActivate != NULL)
	{
		nItem = lpNMItemActivate->iItem;
	}

	//��ȡѡ�������豸��ID
	m_dev_id = m_list_adapter.GetItemText(nItem, 3);
	//��ȡѡ�������豸��IP��ַ
	m_ip = inet_addr(m_list_adapter.GetItemText(nItem, 1));
	//��ȡѡ�������豸IP��ַ����������
	m_mask = inet_addr(m_list_adapter.GetItemText(nItem, 2));

	if (GetLocalMac() == false)
	{
		AfxMessageBox("��ȡ������MAC��ַʧ�ܣ�������ѡ������");
	}

	//���¾�̬�ı�����ʾ
	CString str = "";
	str.Format("ѡ�������豸��%s", m_list_adapter.GetItemText(nItem, 0));
	m_static_adapter.SetWindowText(str);
	
	m_btn_search.EnableWindow(true);
	*pResult = 0;
}

bool CIpMonitorDlg::GetLocalMac()
{
	LPADAPTER lpAdapter;
	PPACKET_OID_DATA  OidData;
	BOOLEAN status;

	CString str = m_dev_id;
	str.Replace("rpcap://", "");

	lpAdapter =  PacketOpenAdapter(str.GetBuffer(str.GetLength()));

	if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
	{
		return false;
	}


	/*����һ����������ȡMAC��ַ*/
	OidData = (PPACKET_OID_DATA)new BYTE[6 + sizeof(PACKET_OID_DATA)];
	if (OidData == NULL) 
	{
		PacketCloseAdapter(lpAdapter);
		return false;
	}

	//��ȡMAC��ַ 

	OidData->Oid = OID_802_3_CURRENT_ADDRESS;

	OidData->Length = 6;
	ZeroMemory(OidData->Data, 6);

	status = PacketRequest((struct _ADAPTER *)lpAdapter, FALSE, OidData);
	if(status)
	{
		memcpy(m_mac, OidData->Data, 6);
	}
	else
	{
		return false;
	}

	free(OidData);
	PacketCloseAdapter(lpAdapter);
	return true;
}
void CIpMonitorDlg::OnBnClickedButtonSearch()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������

	char errbuf[PCAP_ERRBUF_SIZE + 1];
	if ((m_pAdapterHandle = pcap_open(m_dev_id, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
	{
		AfxMessageBox("�޷���������");
		return;
	}
	//�ÿվ������ڻ������Ϣ��
	m_list_host.DeleteAllItems();

	//��ѡ����
	m_list_adapter.EnableWindow(false);
	
	//��ť����
	m_btn_search.EnableWindow(false);
	m_btn_repick.EnableWindow(false);
	m_btn_stop.EnableWindow(true);

	m_combo_ip.ResetContent();
	m_combo_ip.EnableWindow(false);

	m_edit_capture_time.Clear();
	m_edit_capture_time.EnableWindow(false);

	//�����߳�����״̬
	g_run = true;
	//�������ڻ����̨��
	m_count = 0;

	//��ʾ������Ϊ״̬
	m_static_status.SetWindowText("���������������ڻ����...");

	m_pRecvThread = AfxBeginThread(RecvThread, (LPVOID)this, THREAD_PRIORITY_NORMAL, 0, CREATE_SUSPENDED);
	m_pRecvThread->m_bAutoDelete = false;
	
	m_pSendThread = AfxBeginThread(SendThread, (LPVOID)this, THREAD_PRIORITY_NORMAL, 0, CREATE_SUSPENDED);
	m_pSendThread->m_bAutoDelete = false;

	m_pRecvThread->ResumeThread();
	m_pSendThread->ResumeThread();

	//���뱾��IP��ַ��MAC��ַ��Ϣ
	in_addr ipaddress;
	ipaddress.s_addr = m_ip;
	m_list_host.InsertItem(m_count, inet_ntoa(ipaddress));

	m_combo_ip.InsertString(m_count, inet_ntoa(ipaddress));
	
	CString MacAddress = "";
	MacAddress.Format("%02X-%02X-%02X-%02X-%02X-%02X", 
		m_mac[0], m_mac[1], m_mac[2], 
		m_mac[3], m_mac[4], m_mac[5]);

	m_list_host.SetItemText(m_count++, 1, MacAddress);
	
}

unsigned char *CIpMonitorDlg::EnArpPacket(DWORD destip)
{
	static unsigned char *ArpPacket = new BYTE[sizeof(ArpHead_t) + sizeof(EthernetHead_t)];

	EthernetHead_t *EthernetHead = (EthernetHead_t*)ArpPacket;

	EthernetHead->eth_type = htons(0x0806);
	memset(EthernetHead->dest_mac, 0xFF, 6);
	memcpy(EthernetHead->source_mac, m_mac, 6);

	ArpHead_t *ArpHead = (ArpHead_t*)(ArpPacket + sizeof(EthernetHead_t));
	ArpHead->add_len = 6;
	ArpHead->pro_len = 4;
	ArpHead->hardware_type = htons(0x0001);
	ArpHead->option = htons(0x0001);
	ArpHead->protocol_type = htons(0x0800);
	memcpy(ArpHead->sour_addr, m_mac, 6);
	memset(ArpHead->dest_addr, 0xFF, 6);
	memset(ArpHead->padding, 0, 18);
	ArpHead->sour_ip = m_ip;
	ArpHead->dest_ip = destip;

	return ArpPacket;
}

UINT SendThread(LPVOID lpParam)
{
	CIpMonitorDlg *pdlg = (CIpMonitorDlg*)lpParam;

	DWORD netsize = ntohl(~pdlg->m_mask);
	DWORD netnum = ntohl(pdlg->m_ip & pdlg->m_mask);
	
	for (unsigned short i = 0; i < netsize && g_run == true; i++)
	{
		netnum++;						//���α���IP��ַ*.*.*.1��*.*.*.255�����豾������������Ϊ255.255.255.0��
		
		netnum = htonl(netnum);			//��IP��ַ�������ֽ�ת��Ϊ�����ֽ�
		
		if (netnum != pdlg->m_ip)
		{
			unsigned char *ArpPacket_Req = pdlg->EnArpPacket(netnum);
			pcap_sendpacket(pdlg->m_pAdapterHandle, ArpPacket_Req, sizeof(ArpHead_t) + sizeof(EthernetHead_t));		//����

		}
		
		netnum = ntohl(netnum);			//�������ֽ�ת��Ϊ�����ֽ��Ա�֤�����һ����ȷ��IP��ַ
		Sleep(5);
	}
	return 0;
}

UINT RecvThread(LPVOID lpParam)
{
	CIpMonitorDlg *pdlg = (CIpMonitorDlg*)lpParam;
	struct pcap_pkthdr *header;
	const unsigned char *pkt_data;
	int i;
	int res = 0;
	HostInfo_t HostInfo;			//��¼IP��ַ��MAC��ַ�Ķ�Ӧ��ϵ

	//����ARP���ݰ�
	struct bpf_program fcode;
	//���������
	if (pcap_compile(pdlg->m_pAdapterHandle, &fcode, "arp", 1, 0) < 0)//���߲�Ĳ������˱��ʽ�����һ���ܹ�
		//���������������͵ĵײ���ֽ���
	{
		MessageBox(NULL, "���������ʧ��", "note", MB_OK);
		return 1;
	}
	//���ù�����
	if (pcap_setfilter(pdlg->m_pAdapterHandle, &fcode) < 0)//�����������ں˲���Ự�����
	{
		MessageBox(NULL, "���ù�����ʧ��", "note", MB_OK);
		return 1;
	}

	while (g_run == true)
	{
		res = pcap_next_ex(pdlg->m_pAdapterHandle, &header, &pkt_data);
		if (res == 0)						//��ʱ
		{
			break;
		}

		ArpHead_t *ArpHead_Rev= (ArpHead_t*)(pkt_data + 14);
		
		//�ж�ARP��Ӧ���ݰ�Ŀ��MAC��ַ�Ƿ�Ϊ����MAC��ַ
		for (i = 0; i < 6; i++)
		{
			if (pdlg->m_mac[i] != ArpHead_Rev->dest_addr[i])
			{
				break;
			}
		}
		//�ٶ���ӦARP���ݰ��Ĳ����ֶν����ж�
		if (i == 6 && ArpHead_Rev->option == htons(0x0002) && ((ArpHead_Rev->sour_ip & pdlg->m_mask) == (pdlg->m_mask & pdlg->m_ip)))
		{
			HostInfo.ip = ArpHead_Rev->sour_ip;
			memcpy(HostInfo.mac, ArpHead_Rev->sour_addr, 6);

			//��IP��ַ��MAC��ַ�Ķ�Ӧ��Ϣ����Ϣ����ʽ�������߳�
			AfxGetApp()->m_pMainWnd->SendMessage(MSG_RECV_ARP, WPARAM(&HostInfo), 0);
		}
	}
	return 0;
}

LRESULT CIpMonitorDlg::OnDisplayHostInfo(WPARAM wParam,LPARAM lParam)
{
	HostInfo_t *pHostInfo = (HostInfo_t*)wParam;
	
	CString MacAddress = "";
	struct in_addr IpAddress;
	IpAddress.s_addr = pHostInfo->ip;

	m_list_host.InsertItem(m_count, inet_ntoa(IpAddress));

	m_combo_ip.AddString(inet_ntoa(IpAddress));
	
	MacAddress.Format("%02X-%02X-%02X-%02X-%02X-%02X", 
		pHostInfo->mac[0], pHostInfo->mac[1], pHostInfo->mac[2], 
		pHostInfo->mac[3], pHostInfo->mac[4], pHostInfo->mac[5]);

	m_list_host.SetItemText(m_count++, 1, MacAddress);

	return 0;
}
void CIpMonitorDlg::OnBnClickedButtonStop()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������

	g_run = false;

	WaitForSingleObject(m_pSendThread, INFINITE);
	WaitForSingleObject(m_pRecvThread, INFINITE);

	//ɾ��CWindThread
	m_pRecvThread->Delete();
	m_pSendThread->Delete();

	//����ֹͣ���״̬����


	//����������Ϊ״̬
	m_static_status.SetWindowText("�����������ڻ�������");

	//��ť����
	m_btn_repick.EnableWindow(true);
	m_btn_search.EnableWindow(true);
	m_btn_stop.EnableWindow(false);


	if (m_count == 1)
	{
		AfxMessageBox("��ǰ���������޻������������ѡ������������");
		return;
	}


	//��Ŀ��IP��ַ��������п���
	m_combo_ip.InsertString(0, "���л����IP��ַ");
	m_combo_ip.SetCurSel(0);	
	m_combo_ip.EnableWindow(true);

	//���ʼ����ť
	m_btn_capture.EnableWindow(true);

	m_edit_capture_time.EnableWindow(true);

}

void CIpMonitorDlg::OnBnClickedButtonRepick()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������

	//��ť����
	m_btn_repick.EnableWindow(false);

	m_list_adapter.EnableWindow(true);

	m_btn_capture.EnableWindow(false);
	m_edit_capture_time.EnableWindow(false);
	m_combo_ip.EnableWindow(false);
}

void CIpMonitorDlg::OnBnClickedButtonExit()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	if (m_tcp_list)
	{
		delete m_tcp_list;
	}
	if (m_udp_list)
	{
		delete m_udp_list;
	}
	pcap_freealldevs(m_dev_list);

	SendMessage(WM_CLOSE);
}

void CIpMonitorDlg::OnBnClickedButtonCapture()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������

	CString str;
	m_edit_capture_time.GetWindowText(str);

	long duration = (long)(atof(str) * CLOCKS_PER_SEC);
	
	if (duration <= 0)
	{
		AfxMessageBox("������Ϸ��Ĳ���ʱ��");
		return;
	}
	
	//��ȡѡ����Ŀ��IP��ַ
	int pos = m_combo_ip.GetCurSel();	//��ȡ��ǰѡ�е��ڲ������豸����
	
	CString filter = "";
	if (pos == 0)							//���Ĭ��
	{
		filter.Format("tcp or udp");
	}
	else
	{
		CString ipstr;
		m_combo_ip.GetWindowText(ipstr);
		filter.Format("(tcp and (host %s))or(udp and (host %s))", ipstr, ipstr);
	}

	//����TCP��UDP���ݰ�
	struct bpf_program fcode;
	if (pcap_compile(m_pAdapterHandle, &fcode, filter, 1, 0) < 0)
	{
		AfxMessageBox("���������ʧ��");
		return;
	}

	if (pcap_setfilter(m_pAdapterHandle, &fcode) < 0)
	{
		AfxMessageBox("���ù�����ʧ��");
		return;
	}

	//��ʱ
	long time_start = clock();
	
	//����ͳ��TCP���ݰ���UDP���ݰ�������ͷ���
	m_tcp_list = new PacketInfo_t;
	m_tcp_list->next = NULL;

	m_udp_list = new PacketInfo_t;
	m_udp_list->next = NULL;
	
	m_packet_pos = 0;

	m_list_ip_packet.DeleteAllItems();

	//�ؼ�����
	m_btn_capture.EnableWindow(false);
	m_combo_ip.EnableWindow(false);
	m_btn_exit.EnableWindow(false);
	m_btn_repick.EnableWindow(false);
	m_btn_search.EnableWindow(false);
	m_edit_capture_time.EnableWindow(false);

	//�ڹ涨ʱ�����ڲ������ݰ�
	struct pcap_pkthdr *header;
	const unsigned char *pkt_data;
	int res;
	while (clock() - time_start < duration)
	{
		res = pcap_next_ex(m_pAdapterHandle, &header, &pkt_data);
		if (res == 0 || header->len < 14 + 20 + 8)						//��ʱ���յ������ݰ�����С������֡ͷ����+IPͷ����+UDPͷ����
		{
			continue;
		}
		SendMessage(MSG_RECV_TCP_UDP, (WPARAM)pkt_data, 0);
	}

	m_btn_capture.EnableWindow(true);
	m_combo_ip.EnableWindow(true);
	m_btn_exit.EnableWindow(true);
	m_btn_search.EnableWindow(true);
	m_btn_repick.EnableWindow(true);
	m_edit_capture_time.EnableWindow(true);
}

LRESULT CIpMonitorDlg::OnPacketHandle(WPARAM wParam, LPARAM lParam)
{
	unsigned char *RecvInfo = (unsigned char*)wParam;

	IpHead_t *IpHead = (IpHead_t*)(RecvInfo + 14);
	DWORD sourceip = IpHead->SourceAddress;
	DWORD destip = IpHead->DestAddress;
	
	unsigned short sourceport;
	unsigned short destport;

	PacketInfo_t *PacketNode;
	bool istcp;
	if (IpHead->Protocal == 6)
	{
		 PacketNode = m_tcp_list;
		 
		 TcpHead_t *TcpHead = (TcpHead_t*)(RecvInfo + 14 + (IpHead->Version_HeaderLength & 15) * 4);
		 sourceport = ntohs(TcpHead->SourcePort);
		 destport = ntohs(TcpHead->DestPort);
		 istcp = true;
	}
	else if (IpHead->Protocal == 17)
	{
		PacketNode = m_udp_list;
		
		UdpHead_t *UdpHead = (UdpHead_t*)(RecvInfo + 14 + (IpHead->Version_HeaderLength & 15) * 4);
		sourceport = ntohs(UdpHead->SourcePort);
		destport = ntohs(UdpHead->DestPort);
		istcp = false;
	}
	else
	{
		return 1;
	}
 	
	while (PacketNode->next != NULL)
	{
		if (PacketNode->next->dest_ip == destip && PacketNode->next->sour_ip == sourceip && PacketNode->next->dest_port == destport && PacketNode->next->sour_port == sourceport)
		{
			//���ݰ�ͳ����Ŀ��һ
			PacketNode->next->packet_count++;

			char buffer[20];
			_itoa_s(PacketNode->next->packet_count, buffer, 10);
			
			//������ʾ
			m_list_ip_packet.SetItemText(PacketNode->next->seq, 5, buffer);
			m_list_ip_packet.Update(PacketNode->next->seq);
			return 0;
		}
		PacketNode = PacketNode->next;
	}

	PacketInfo_t *NewPacketNode = new PacketInfo_t;
	NewPacketNode->dest_ip = destip;
	NewPacketNode->dest_port = destport;
	NewPacketNode->next = NULL;
	NewPacketNode->packet_count = 1;
	NewPacketNode->seq = m_packet_pos++;
	NewPacketNode->sour_ip = sourceip;
	NewPacketNode->sour_port = sourceport;
	PacketNode->next = NewPacketNode;

	//������ʾ
	in_addr ipaddress;
	ipaddress.s_addr = NewPacketNode->sour_ip;
	m_list_ip_packet.InsertItem(NewPacketNode->seq, inet_ntoa(ipaddress));

	ipaddress.s_addr = NewPacketNode->dest_ip;
	m_list_ip_packet.SetItemText(NewPacketNode->seq, 1, inet_ntoa(ipaddress));

	char sportbuf[20];
	_itoa_s(NewPacketNode->sour_port, sportbuf, 10);
	m_list_ip_packet.SetItemText(NewPacketNode->seq, 2, sportbuf);

	char dportbuf[20];
	_itoa_s(NewPacketNode->dest_port, dportbuf, 10);
	m_list_ip_packet.SetItemText(NewPacketNode->seq, 3, dportbuf);

	if (istcp == true)
	{
		m_list_ip_packet.SetItemText(NewPacketNode->seq, 4, "TCPЭ��");
	}
	else
	{
		m_list_ip_packet.SetItemText(NewPacketNode->seq, 4, "UDPЭ��");
	}

	char cntbuf[20];
	_itoa_s(NewPacketNode->packet_count, cntbuf, 10);
	m_list_ip_packet.SetItemText(NewPacketNode->seq, 5, cntbuf);

	m_list_ip_packet.Update(NewPacketNode->seq);

	return 0;
}