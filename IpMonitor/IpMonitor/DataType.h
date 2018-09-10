#pragma pack(1)
struct ArpHead_t
{
	unsigned short hardware_type;
	unsigned short protocol_type;
	unsigned char add_len;
	unsigned char pro_len;
	unsigned short option;
	unsigned char sour_addr[6];
	unsigned long sour_ip;
	unsigned char dest_addr[6];
	unsigned long dest_ip;
	unsigned char padding[18];
};

struct EthernetHead_t
{
	unsigned char dest_mac[6];
	unsigned char source_mac[6];
	unsigned short eth_type;
};

struct HostInfo_t
{
	unsigned char mac[6];
	DWORD ip;
};

struct PacketInfo_t
{
	DWORD sour_ip;
	DWORD dest_ip;
	unsigned short sour_port;
	unsigned short dest_port;
	int packet_count;
	PacketInfo_t *next;
	int seq;
};

struct IpHead_t
{
	unsigned char Version_HeaderLength;
	unsigned char TypeOfService;
	unsigned short TotalLength;
	unsigned short Identification;
	unsigned short Flags_FragmentOffset;
	unsigned char TimeToLive;
	unsigned char Protocal;
	unsigned short HeaderChecksum;
	unsigned long SourceAddress;
	unsigned long DestAddress;
};

struct TcpHead_t
{
	unsigned short SourcePort;
	unsigned short DestPort;
	unsigned long Seq;
	unsigned long Ack;
	unsigned char Length;
	unsigned char Flag;
	unsigned short Window;
	unsigned short Checksum;
	unsigned short Urgent;
	unsigned int MssOpt;
	unsigned short NopOpt;
	unsigned short SackOpt;
};

struct UdpHead_t
{
	unsigned short SourcePort;
	unsigned short DestPort;
	unsigned short Length;
	unsigned short Checksum;
};

#pragma pack()