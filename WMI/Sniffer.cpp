#ifdef _MSC_VER
/*
* we do not want the warnings about the old deprecated and unsecure CRT functions
* since these examples can be compiled under *nix as well
*/
#define _CRT_SECURE_NO_WARNINGS
#endif


#include <stdlib.h>
#include <signal.h>
#include <tchar.h>
//#include <cstdlib>
#include <cstdio>
//#include <stdio.h>
#include <iostream>

#include <pcap.h>

#pragma comment(lib,"ws2_32.lib") //For winsock

#define LINE_LEN 16
#define ETH_ALEN 6			/* Octets in one ethernet addr   */
#define BUF_SIZE 65536
#define TIME_BUF_SIZE 20

char alrt[42];			// holds attempt message
char id[4];			// holds attempt id
char command[50];		// holds excuting commad

char time_buf[TIME_BUF_SIZE];	// holds timestamp

char *sour, *dest; 		// source and destination ip addresses as strings

struct sockaddr_in addrs;	// hold soruce and destination ip address

time_t curtime;			// time variables
struct tm *loctime;		// time variables

FILE *log_fd;                   // log file descriptor

// for decrypted data
char *data;

const char *opnum_methods[] = { "", "", "", \
"OpenNamespace", \
"CancelAsyncCall", \
"QueryObjectSink", \
"GetObject", \
"GetObjectAsync", \
"PutClass", \
"PutClassAsync", \
"DeleteClass", \
"DeleteClassAsync", \
"CreateClassEnum", \
"CreateClassEnumAsync", \
"PutInstance", \
"PutInstanceAsync", \
"DeleteInstance", \
"DeleteInstanceAsync", \
"CreateInstanceEnum", \
"CreateInstanceEnumAsync", \
"ExecQuery", \
"ExecQueryAsync", \
"ExecNotificationQuery", \
"ExecNotificationQueryAsync", \
"ExecMethod", \
"ExecMethodAsync" };

typedef struct iphdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char ihl : 4;
	unsigned char version : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int version : 4;
	unsigned int ihl : 4;
#else
# error "Please fix <bits/endian.h>"
#endif
	u_int8_t tos;
	u_int16_t tot_len;
	u_int16_t id;
	u_int16_t frag_off;
	u_int8_t ttl;
	u_int8_t protocol;
	u_int16_t check;
	u_int32_t saddr;
	u_int32_t daddr;
	/*The options start here. */
};

typedef u_int32_t tcp_seq;
typedef struct tcphdr
{
	union
	{
		struct
		{
			u_int16_t th_sport;             /* source port */
			u_int16_t th_dport;             /* destination port */
			tcp_seq th_seq;					/* sequence number */
			tcp_seq th_ack;					/* acknowledgement number */
# if __BYTE_ORDER == __LITTLE_ENDIAN
			u_int8_t th_x2 : 4;				/* (unused) */
			u_int8_t th_off : 4;            /* data offset */
# elif __BYTE_ORDER == __BIG_ENDIAN
			u_int8_t th_off : 4;            /* data offset */
			u_int8_t th_x2 : 4;             /* (unused) */
# endif
			u_int8_t th_flags;

# define TH_FIN 0x01
# define TH_SYN 0x02
# define TH_RST 0x04
# define TH_PUSH        0x08
# define TH_ACK 0x10
# define TH_URG 0x20
			u_int16_t th_win;               /* window */
			u_int16_t th_sum;               /* checksum */
			u_int16_t th_urp;               /* urgent pointer */
		};
		struct
		{
			u_int16_t source;
			u_int16_t dest;
			u_int32_t seq;
			u_int32_t ack_seq;
# if __BYTE_ORDER == __LITTLE_ENDIAN
			u_int16_t res1 : 4;
			u_int16_t doff : 4;
			u_int16_t fin : 1;
			u_int16_t syn : 1;
			u_int16_t rst : 1;
			u_int16_t psh : 1;
			u_int16_t ack : 1;
			u_int16_t urg : 1;
			u_int16_t res2 : 2;
# elif __BYTE_ORDER == __BIG_ENDIAN
			u_int16_t doff : 4;
			u_int16_t res1 : 4;
			u_int16_t res2 : 2;
			u_int16_t urg : 1;
			u_int16_t ack : 1;
			u_int16_t psh : 1;
			u_int16_t rst : 1;
			u_int16_t syn : 1;
			u_int16_t fin : 1;
# else
#  error "Adjust your <bits/endian.h> defines"
# endif
			u_int16_t window;
			u_int16_t check;
			u_int16_t urg_ptr;
		};
	};
};

typedef struct ethhdr {
	unsigned char   h_dest[ETH_ALEN];       /* destination eth addr */
	unsigned char   h_source[ETH_ALEN];     /* source ether addr    */
	unsigned short h_proto;					/* packet type ID field */
};

struct dcerpc_hdr{
	u_int8_t version;
	u_int8_t version_minor;
	u_int8_t pack_type;
	u_int8_t pack_flag;

	u_int32_t data_rep;

	u_int16_t frag_len;
	u_int16_t auth_len;
	u_int32_t call_id;

	u_int32_t alloc_hint;
	u_int16_t context_id;
	u_int16_t op_num;

	unsigned char obj_uuid[16];
};

struct dcerpc_trl{
	u_int8_t auth_type;
	u_int8_t auth_level;
	u_int8_t auth_pad_len;
	u_int8_t auth_rsvrd;
	u_int32_t auth_context_id;

	u_int32_t ntlmssp_ver_num;
	unsigned char ntlmssp_ver_body[12];
};

struct dcerpc_auth{
	u_int8_t version;
	u_int8_t version_minor;
	u_int8_t pack_type;
	u_int8_t pack_flag;

	u_int32_t data_rep;

	u_int16_t frag_len;
	u_int16_t auth_len;
	u_int32_t call_id;

	u_int32_t unknown;

	u_int8_t auth_type;
	u_int8_t auth_level;
	u_int8_t auth_pad_len;
	u_int8_t auth_rsvrd;
	u_int32_t auth_context_id;

};

struct ntlmssp{
	u_int64_t identifier;
	u_int32_t message_type;

	u_int16_t lan_man_res_length;
	u_int16_t lan_man_res_maxlen;
	u_int32_t lan_man_res_offset;

	u_int16_t ntlm_res_length;
	u_int16_t ntlm_res_maxlen;
	u_int32_t ntlm_res_offset;


	u_int16_t domain_name_length;
	u_int16_t domain_name_maxlen;
	u_int32_t domain_name_offset;

	u_int16_t user_name_length;
	u_int16_t user_name_maxlen;
	u_int32_t user_name_offset;

	u_int16_t host_name_length;
	u_int16_t host_name_maxlen;
	u_int32_t host_name_offset;

	u_int16_t session_key_length;
	u_int16_t session_key_maxlen;
	u_int32_t session_key_offset;

	u_int32_t negotiate_flags;

	union
	{
		u_int64_t verson;

		struct {
			u_int8_t version_major_version;
			u_int8_t version_minor_version;
			u_int16_t version_build_number;

			unsigned char version_pad[3];
			u_int8_t  version_ntlm_cur_rev;
		};
	};

	unsigned char MIC[16];

};

#pragma pack(2)
struct dcerpc_pack{
	struct ethhdr eth;
	struct iphdr ip;
	struct tcphdr tcp;
	struct dcerpc_hdr dcerpc_h;
};

#pragma pack(2)
struct dcerpc_pack_auth{
	struct ethhdr eth;
	struct iphdr ip;
	struct tcphdr tcp;
	struct dcerpc_auth auth;
	struct ntlmssp ntlmssp_h;
};

void process(const u_char *, size_t);
void process_data(const u_char *, size_t, int, int);
void process_auth(const u_char *, size_t, int, int);
void alert(const u_char *, char *);
void alert_ex(const u_char *, char *);
void log_ex(const u_char *);
void log_auth(const u_char *);
void eth_print(const u_char *);
void SignalHandler(int);

int main(int argc, char **argv)
{
	pcap_if_t *alldevs, *d;
	pcap_t *fp;
	u_int inum, i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;

	// create log file or point the log file descriptor to log file
	if (!(log_fd = fopen("wmi.log", "a+"))){
		fprintf(stderr, "Error : Openning Log File : %s\n", errbuf);
		exit(1);
	}

	// checks if log file is empty
	fseek(log_fd, 0, SEEK_END);
	// if log file is empty write the login header
	if (ftell(log_fd) == 0){
		fprintf(log_fd, "Timestamp,Source IP,Dest IP,Source Port,Dest Port,DCERPC Auth Pack Type,DCERPC Auth Level,Attempt ID,Op Num,Method,Command,Raw Data\n");
	}

	printf("\nDevice list :\n\n");
	/* The user didn't provide a packet source: Retrieve the local device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s\n    ", ++i, d->name);

		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	printf("\n");
	printf("Enter the interface number (1-%d) : ", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");

		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the adapter */
	if ((fp = pcap_open_live(d->name,	// name of the device
		65536,							// portion of the packet to capture. 
		// 65536 grants that the whole packet will be captured on all the MACs.
		1,								// promiscuous mode (nonzero means promiscuous)
		1000,							// read timeout
		errbuf							// error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nError opening adapter\n");
		return -1;
	}

	data = (char *)malloc(BUF_SIZE);

	if (!data){
		fprintf(stderr, "Error : Allocating Memory for data buffer : %s\n", errbuf);
		exit(1);
	}

	strncpy(alrt, "Attempting to authenticate with id : ", 37);

	typedef void(*SignalHandlerPointer)(int);
	SignalHandlerPointer previousHandler;
	previousHandler = signal(SIGINT, SignalHandler);

	/* Read the packets */
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{

		if (res == 0)
			/* Timeout elapsed */
			continue;

		process(pkt_data, header->caplen);
	}

	if (res == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(fp));
		return -1;
	}
	pcap_close(fp);
	return 0;
}

void process(const u_char *buf, size_t nbytes){

	struct iphdr *iph = (struct iphdr *)(buf + 14);

	if (iph->tot_len > 118){

		struct dcerpc_pack *dce_h = (struct dcerpc_pack *)buf;

		if (dce_h->dcerpc_h.version == 5){
			if (dce_h->dcerpc_h.pack_type == 16){
				struct dcerpc_pack_auth *dce_auth = (struct dcerpc_pack_auth *)buf;
				if (dce_auth->auth.auth_type == 10){
					switch (dce_auth->auth.auth_level){
					case 2:
						memset(id, 0, 4);
						alert(buf, "Attempting to connect");
						process_auth(buf, nbytes, sizeof(struct dcerpc_pack_auth), nbytes);
						log_auth(buf);
						break;
					case 4:
						memset(id, 0, 4);
						_snprintf(id, 4, "%d", dce_auth->auth.auth_context_id);
						strncpy((alrt + 37), id, 4);
						alert(buf, alrt);
						process_auth(buf, nbytes, sizeof(struct dcerpc_pack_auth), nbytes);
						log_auth(buf);
						break;
					}
				}
			}
			else{
				switch (dce_h->dcerpc_h.op_num){
				case 20:
				case 21:
				case 22:
				case 23:
				case 24:
				case 25:
					alert_ex(buf, "Executing  :  ");
					process_data(buf, nbytes, 118, (nbytes - 24));
					log_ex(buf);
					break;
				}
			}
		}
	}
}

void process_auth(const u_char *buf, size_t nbytes, int spos, int epos){
	memset(data, 0, sizeof(BUF_SIZE));
	unsigned char   ch;
	int j = 0;
	for (int i = spos; i < epos; i++){
		ch = buf[i];
		if ((ch < 0x20) || (ch > 0x7E)){
			continue;
		}
		data[j++] = ch;
	}
	data[j] = '\0';
}

void process_data(const u_char *buf, size_t nbytes, int spos, int epos){
	memset(data, 0, sizeof(BUF_SIZE));
	unsigned char   ch;
	int j = 0;
	for (int i = spos; i < epos; i++){
		ch = buf[i];
		if ((ch < 0x20) || (ch > 0x7E)){
			continue;
		}
		data[j++] = ch;
	}
	data[j] = '\0';


	std::string text(data);
	std::size_t found = -1;
	if ((found = text.find("object:Win32_")) == std::string::npos){
		if ((found = text.find("Win32_")) == std::string::npos){
			if ((found = text.find("cim_datafile")) == std::string::npos){
				printf("%s\n", data);
			}
		}
	}

	if (found != std::string::npos){
		memset(command, 0, 50);
		int j = 0;
		for (int i = found;; i++){
			if (data[i] > 0x7A || data[i] < 0x30)
				break;
			command[j++] = data[i];
		}
		command[j] = '\0';
		printf("%s", command);
	}
	printf("\n");
}

void eth_print(const u_char *buf){
	for (int i = 0; i<ETH_ALEN; i++){
		if (i>0)
			printf(":");
		if (buf[i] != 255)
			printf("%02x", (unsigned char)buf[i]);
	}
	printf("\n");
}

// log execution details
void log_ex(const u_char *buf){
	struct dcerpc_pack *dce_h = (struct dcerpc_pack *)buf;
	fprintf(log_fd, "%s,", time_buf);			// timestamp
	fprintf(log_fd, "%s,", sour);				// source ip address
	fprintf(log_fd, "%s,", dest);				// destination ip address

	fprintf(log_fd, "%u,", ntohs(dce_h->tcp.source));	// tcp source address
	fprintf(log_fd, "%u,", ntohs(dce_h->tcp.dest));		// tcp destination address

	fprintf(log_fd, ",");
	fprintf(log_fd, ","); 
	fprintf(log_fd, ",");

	fprintf(log_fd, "%d,", dce_h->dcerpc_h.op_num);		// dcerpc packet op num
	fprintf(log_fd, "%s,", opnum_methods[dce_h->dcerpc_h.op_num]);	// method relevant to op num
	fprintf(log_fd, "%s,", command);			// executed command

	fprintf(log_fd, "%s", data);				// raw data
	fprintf(log_fd, "\n");

	fflush(stdout);
	fflush(log_fd);

}

// log authentication attempt details
void log_auth(const u_char *buf){
	struct dcerpc_pack_auth *dce_auth = (struct dcerpc_pack_auth *)buf;
	fprintf(log_fd, "%s,", time_buf);			// timestamp
	fprintf(log_fd, "%s,", sour);				// source ip address
	fprintf(log_fd, "%s,", dest);				// destination ip address

	fprintf(log_fd, "%u,", ntohs(dce_auth->tcp.source));	// tcp source port
	fprintf(log_fd, "%u,", ntohs(dce_auth->tcp.dest));	// tcp destination port

	fprintf(log_fd, "%d,", dce_auth->auth.pack_type);	// dcerpc auth packet type
	fprintf(log_fd, "%d,", dce_auth->auth.auth_level);	// dcerpc auth packet authentication level
	fprintf(log_fd, "%s,", id);

	fprintf(log_fd, ",");
	fprintf(log_fd, ",");
	fprintf(log_fd, ",");

	fprintf(log_fd, "%s", data);				// raw data
	fprintf(log_fd, "\n");

	fflush(stdout);
	fflush(log_fd);
}

void alert(const u_char *buf, char *msg){
	memset(time_buf, 0, TIME_BUF_SIZE);
	curtime = time(NULL);
	loctime = localtime(&curtime);

	strftime(time_buf, TIME_BUF_SIZE, "%Y/%m/%d %H:%M:%S", loctime);

	struct iphdr *iph = (struct iphdr *)(buf + 14);
	memset(&addrs, 0, sizeof(struct sockaddr_in));
	addrs.sin_addr.s_addr = iph->saddr;
	sour = _strdup(inet_ntoa(addrs.sin_addr));
	addrs.sin_addr.s_addr = iph->daddr;
	dest = _strdup(inet_ntoa(addrs.sin_addr));

	printf("%s : %s -> %s : %s\n", time_buf, sour, dest, msg);
}

void alert_ex(const u_char *buf, char *msg){
	memset(time_buf, 0, TIME_BUF_SIZE);
	curtime = time(NULL);
	loctime = localtime(&curtime);

	strftime(time_buf, TIME_BUF_SIZE, "%Y/%m/%d %H:%M:%S", loctime);

	struct iphdr *iph = (struct iphdr *)(buf + 14);
	memset(&addrs, 0, sizeof(struct sockaddr_in));
	addrs.sin_addr.s_addr = iph->saddr;
	sour = _strdup(inet_ntoa(addrs.sin_addr));
	addrs.sin_addr.s_addr = iph->daddr;
	dest = _strdup(inet_ntoa(addrs.sin_addr));

	printf("%s : %s -> %s : %s", time_buf, sour, dest, msg);
}

/* signal handler */
void SignalHandler(int signal)
{
	if (signal == SIGINT) {
		free(data);
		fclose(log_fd);
	}
}