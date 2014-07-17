/*
+--------------------------------------------------+
| @file: sntp_status.c                             |
| @brief: Program for sntp status testing          |
| @author: YoungJoo.Kim <http://superlinuxer.com>  |
| @version:                                        |
| @date: 20080925                                  |
+--------------------------------------------------+
 
+-----------------------------------------------------------------------------+
shell> gcc -o sntp_status sntp_status.c  
shell> ./sntp_status kr.pool.ntp.org 
server               : kr.pool.ntp.org
server port          : 123
my bind port         : 12786
 
send packet size     : 48
send packet          : e3 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
li_vn_mode           : 227 / LI: 3, VN: 4, MODE : 3
Stratum              : 00
Poll                 : 04
Precision            : 00
Root Delay           : 00
Root Dispersion      : 00
Reference Identifier : 00
Reference Timestamp  : 00
Originate Timestamp  : 00
Receive Timestamp    : 00
Transmit Timestamp   : 00
Reference Time       : 2036/02/07 15:28:16
Originate Time       : 2036/02/07 15:28:16
Receive Time         : 2036/02/07 15:28:16
Transmit Time        : 2036/02/07 15:28:16
 
recv packet size     : 48
recv packet          : 24 02 04 e9 00 00 11 63 00 00 07 48 85 64 09 02 d5 a4 90 4c 2d 5b f8 f1 00 00 00 00 00 00 00 00 d5 a4 91 ae 7d 9e e3 8d d5 a4 91 ae 7d a0 df 3b
li_vn_mode           : 36 / LI: 0, VN: 4, MODE : 4
Stratum              : 02
Poll                 : 04
Precision            : -23
Root Delay           : 63110000
Root Dispersion      : 48070000
Reference Identifier : 2096485
Reference Timestamp  : f1f85b2d4c90a4d5
Originate Timestamp  : 00
Receive Timestamp    : 8de39e7dae91a4d5
Transmit Timestamp   : 3bdfa07dae91a4d5
Reference Time       : 2013/08/01 16:44:12
Originate Time       : 2036/02/07 15:28:16
Receive Time         : 2013/08/01 16:50:06
Transmit Time        : 2013/08/01 16:50:06
 
send packet size     : 48
send packet          : e3 00 04 fa 00 01 00 00 00 01 00 00 85 64 09 02 d5 a4 91 ae 7d a0 df 3b d5 a4 91 ae 7d a0 df 3b d5 a4 91 ae 7d 9e e3 8d d5 a4 91 ae 7d a0 df 3b
li_vn_mode           : 227 / LI: 3, VN: 4, MODE : 3
Stratum              : 00
Poll                 : 04
Precision            : -6
Root Delay           : 100
Root Dispersion      : 100
Reference Identifier : 2096485
Reference Timestamp  : 3bdfa07dae91a4d5
Originate Timestamp  : 3bdfa07dae91a4d5
Receive Timestamp    : 8de39e7dae91a4d5
Transmit Timestamp   : 3bdfa07dae91a4d5
Reference Time       : 2013/08/01 16:50:06
Originate Time       : 2013/08/01 16:50:06
Receive Time         : 2013/08/01 16:50:06
Transmit Time        : 2013/08/01 16:50:06
 
recv packet size     : 48
recv packet          : 24 02 04 e9 00 00 11 63 00 00 07 48 85 64 09 02 d5 a4 90 4c 2d 5b f8 f1 d5 a4 91 ae 7d a0 df 3b d5 a4 91 ae 7f 48 03 be d5 a4 91 ae 7f 4a 17 fe
li_vn_mode           : 36 / LI: 0, VN: 4, MODE : 4
Stratum              : 02
Poll                 : 04
Precision            : -23
Root Delay           : 63110000
Root Dispersion      : 48070000
Reference Identifier : 2096485
Reference Timestamp  : f1f85b2d4c90a4d5
Originate Timestamp  : 3bdfa07dae91a4d5
Receive Timestamp    : be03487fae91a4d5
Transmit Timestamp   : fe174a7fae91a4d5
Reference Time       : 2013/08/01 16:44:12
Originate Time       : 2013/08/01 16:50:06
Receive Time         : 2013/08/01 16:50:06
Transmit Time        : 2013/08/01 16:50:06
 
NTPD SERVER STATUS  : OK
+-----------------------------------------------------------------------------+
 
 
	http://www.faqs.org/rfcs/rfc2030.html
 
					   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|LI | VN  |Mode |    Stratum    |     Poll      |   Precision   |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                          Root Delay                           |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                       Root Dispersion                         |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                     Reference Identifier                      |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                                                               |
	|                   Reference Timestamp (64)                    |
	|                                                               |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                                                               |
	|                   Originate Timestamp (64)                    |
	|                                                               |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                                                               |
	|                    Receive Timestamp (64)                     |
	|                                                               |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                                                               |
	|                    Transmit Timestamp (64)                    |
	|                                                               |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                 Key Identifier (optional) (32)                |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                                                               |
	|                                                               |
	|                 Message Digest (optional) (128)               |
	|                                                               |
	|                                                               |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	Figure. NTP Message Header Version 4
 
 
	LI       Value     Meaning
	-------------------------------------------------------
	00       0         no warning
	01       1         last minute has 61 seconds
	10       2         last minute has 59 seconds)
	11       3         alarm condition (clock not synchronized)
 
	Mode     Meaning
	------------------------------------
	0        reserved
	1        symmetric active
	2        symmetric passive
	3        client
	4        server
	5        broadcast
	6        reserved for NTP control message
	7        reserved for private use
 
	Stratum  Meaning
	----------------------------------------------
	0        unspecified or unavailable
	1        primary reference (e.g., radio clock)
	2-15     secondary reference (via NTP or SNTP)
	16-255   reserved
 
	Code     External Reference Source
	----------------------------------------------------------------
	LOCL     uncalibrated local clock used as a primary reference for
			 a subnet without external means of synchronization
	PPS      atomic clock or other pulse-per-second source
			 individually calibrated to national standards
	ACTS     NIST dialup modem service
	USNO     USNO modem service
	PTB      PTB (Germany) modem service
	TDF      Allouis (France) Radio 164 kHz
	DCF      Mainflingen (Germany) Radio 77.5 kHz
	MSF      Rugby (UK) Radio 60 kHz
	WWV      Ft. Collins (US) Radio 2.5, 5, 10, 15, 20 MHz
	WWVB     Boulder (US) Radio 60 kHz
	WWVH     Kaui Hawaii (US) Radio 2.5, 5, 10, 15 MHz
	CHU      Ottawa (Canada) Radio 3330, 7335, 14670 kHz
	LORC     LORAN-C radionavigation system
	OMEG     OMEGA radionavigation system
	GPS      Global Positioning Service
	GOES     Geostationary Orbit Environment Satellite
 
 
	* Version 3 or Version 4 는 optional 을 제외한 전체 바이트는 48Byte 이다.
 
	전체 헤더 바이트 : 48byte
 
	* 보내기 예제
 
	1000 0000 == 256
	1110 0011 == 227
	0000 0011 == 3
	0000 0100 == 4
	0000 0011 == 3
 
	ex) 3 4 3 을 1byte에 넣을때
					   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|LI | VN  |Mode |    Stratum    |     Poll      |   Precision   |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
 
	0000 0011 << 6 = 11xx xxxx
	0000 0100 << 3 = xx10 0xxx
	0000 0011      = xxxx x011
	--------------------------
					 1110 0011
 
 
	0   LI(3) + VN(4) + Mode(3) = 227 = 1byte  = integer
	1   Stratum                 = 0   = 1byte  = unsigned integer
	2   Poll                    = 4   = 1byte  = signed integer
	3   Precision               = -6  = 1byte  = signed integer
	4   Root Delay              = 256 = 4byte  = signed fixed-point number
	5   Root Dispersion         = 256 = 4byte  = unsigned fixed-point number 
	6   Reference Identifier    = 0   = 4byte  = four-character ASCII string
	7   Reference Timestamp     = 0   = 8byte  = 64-bit timestamp format
	8   Originate Timestamp     = 0   = 8byte  = 64-bit timestamp format
	9   Receive Timestamp       = 0   = 8byte  = 64-bit timestamp format
	10  Transmit Timestamp      = N   = 8byte  = 64-bit timestamp format
 
	LI - 2bit
	   Leap Indicater 이것은 현재시간의 마지막분에 추가/삭제 되려는 초가 임박했다는 2-bit code 경고 이다.
 
	VN - 3bit
	   NTP 버젼 번호
 
	Mode - 3bit
	   Client 에서는 3 서버는 4번 사용
 
	Stratum - 1byte
	   local clock 의 계층 level
 
	Poll - 1byte
	   연속 되는 메시지 사이의 최대 간격
	   이필드의 범위는 4(16s) ~ 14(16284s) 까지 나타낼수 있지만
	   대부분 애플리케이션에서 6(64s) 이하나 10(1024s)까지만 사용한다.	
 
	Precision - 1byte
	   local clock 의 정밀도
	   보통 이 필드의 범위는 mains-frequency clock 을 위한 -6 부터 몇몇 워크스테이션에서 발견되는 microsecond
	   clock 을 위한 -20 까지 나타낸다.
 
	Root Delay - 4byte
	   첫번째 참조 source 까지의 총 roundtrip delay
	   보통 이 필드의 범위는 약 1/1000 초의 음수에서 부터 수백초의 값까지 나타낸다.
 
	Root Dispersion - 4byte
	   첫번째 참조 source 까지 명목상 error
	   보통 이 필드의 범위는 0에서 수백초의 값까지 나타낸다.
 
	Reference Identifier - 4byte
	   NTP Version 3 또는 NTP Version 4 의 경우에는 이것은 4자의 ASCII 문자 값이다.
 
	Reference Timestamp - 8byte
	   마지막으로 설정되거나 확실한 local clock 이다.
 
	Originate Timestamp - 8byte
	   클라이언트가 서버에 과거에 했던 요청 시간
 
	Receive Timestamp - 8byte
	   서버로부터 도착되어진 응답 시간
 
	Transmit Timestamp - 8byte
	   서버가 클라이언트에 과거에 보낸 응답 시간
 
 
	* LI + VN + Mode 처리
		#define PKT_LI_VN_MODE(li, vn, md) ((u_char)((((li) << 6) & 0xc0) | (((vn) << 3) & 0x38) | ((md) & 0x7)))
		* LI = 3, VN = 4, Mode = 3 
		perl -e 'print ((((3) << 6) & 0xc0) | (((4) << 3) & 0x38) | ((3) & 0x7))'
		Result = 227
 
*/
#include <stdio.h>
#include <string.h>
#include <netdb.h>
 
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
 
#include <time.h>
 
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
 
 
/* from ntp-4.2.4p5/include/ntp_unixtime.h */
#define JAN_1970        0x83aa7e80      /* 2208988800 1970 - 1900 in seconds */
 
/* from #include <stdint.h> */
typedef unsigned char		uint8_t;
typedef signed char			int8_t;
typedef unsigned short int	uint16_t;
typedef short int			int16_t;
typedef unsigned int		uint32_t;
typedef int					int32_t;
typedef unsigned long int	uint64_t;
typedef long int			int64_t;
 
/* from ntp-4.2.4p5/include/ntp_fp.h */
/*
 * NTP uses two fixed point formats.  The first (l_fp) is the "long"
 * format and is 64 bits long with the decimal between bits 31 and 32.
 * This is used for time stamps in the NTP packet header (in network
 * byte order) and for internal computations of offsets (in local host
 * byte order). We use the same structure for both signed and unsigned
 * values, which is a big hack but saves rewriting all the operators
 * twice. Just to confuse this, we also sometimes just carry the
 * fractional part in calculations, in both signed and unsigned forms.
 * Anyway, an l_fp looks like:
 *
 *    0           1           2           3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                 Integral Part                 |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                 Fractional Part               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
 
typedef struct {
	union {
		uint32_t Xl_ui;
		int32_t Xl_i;
	} Ul_i;
	union {
		uint32_t Xl_uf;
		int32_t Xl_f;
	} Ul_f;
} l_fp;
 
 
#define l_ui    Ul_i.Xl_ui      /* unsigned integral part */
#define l_i Ul_i.Xl_i           /* signed integral part */
#define l_uf    Ul_f.Xl_uf      /* unsigned fractional part */
#define l_f Ul_f.Xl_f           /* signed fractional part */
 
#define NTP_TO_UNIX(n,u) do {  u = n - JAN_1970; } while (0)
#define NTOHL_FP(n, h)  do { (h)->l_ui = ntohl((n)->l_ui); (h)->l_uf = ntohl((n)->l_uf); } while (0)
#define HTONL_F(f, nts) do { (nts)->l_uf = htonl(f); \
	if ((f) & 0x80000000) \
	(nts)->l_i = -1; \
	else \
	(nts)->l_i = 0; \
} while (0)
 
/* from ntp-4.2.4p5/include/ntp.h */
#define NTP_VERSION ((uint8_t)4) /* current version number */
 
/*
 * Values for peer.leap, sys_leap
 */
#define LEAP_NOWARNING  0x0 /* normal, no leap second warning */
#define LEAP_ADDSECOND  0x1 /* last minute of day has 61 seconds */
#define LEAP_DELSECOND  0x2 /* last minute of day has 59 seconds */
#define LEAP_NOTINSYNC  0x3 /* overload, clock is free running */
 
/*
 * Values for peer mode and packet mode. Only the modes through
 * MODE_BROADCAST and MODE_BCLIENT appear in the transition
 * function. MODE_CONTROL and MODE_PRIVATE can appear in packets,
 * but those never survive to the transition function.
 * is a
 */
#define MODE_UNSPEC     0   /* unspecified (old version) */
#define MODE_ACTIVE     1   /* symmetric active mode */
#define MODE_PASSIVE    2   /* symmetric passive mode */
#define MODE_CLIENT     3   /* client mode */
#define MODE_SERVER     4   /* server mode */
#define MODE_BROADCAST  5   /* broadcast mode */
 
#define PKT_LI_VN_MODE(li, vn, md) ((uint8_t)((((li) << 6) & 0xc0) | (((vn) << 3) & 0x38) | ((md) & 0x7)))
 
struct pkt {
  uint8_t   li_vn_mode;     /* leap indicator, version and mode */
  uint8_t   stratum;        /* peer stratum */
  uint8_t   ppoll;          /* peer poll interval */
  int8_t    precision;      /* peer clock precision */
  uint32_t  rootdelay;      /* distance to primary clock */
  uint32_t  rootdispersion; /* clock dispersion */
  uint32_t  refid;          /* reference clock ID */
  l_fp      reftime;        /* time peer clock was last updated */
  l_fp      org;            /* originate time stamp */
  l_fp      rec;            /* receive time stamp */
  l_fp      xmt;            /* transmit time stamp */
 
#define LEN_PKT_NOMAC   12 * sizeof(uint32_t) /* min header length */
#define LEN_PKT_MAC     LEN_PKT_NOMAC +  sizeof(uint32_t)
#define MIN_MAC_LEN     3 * sizeof(uint32_t)     /* DES */
#define MAX_MAC_LEN     5 * sizeof(uint32_t)     /* MD5 */
 
/*
 * The length of the packet less MAC must be a multiple of 64
 * with an RSA modulus and Diffie-Hellman prime of 64 octets
 * and maximum host name of 128 octets, the maximum autokey
 * command is 152 octets and maximum autokey response is 460
 * octets. A packet can contain no more than one command and one
 * response, so the maximum total extension field length is 672
 * octets. But, to handle humungus certificates, the bank must
 * be broke.
 */
#ifdef OPENSSL
  uint32_t exten[NTP_MAXEXTEN / 4]; /* max extension field */
#else /* OPENSSL */
  uint32_t exten[1];                /* misused */
#endif /* OPENSSL */
  uint8_t  mac[MAX_MAC_LEN];        /* mac */
};
 
#define PKT_SIZE 48
#define IS_SOCKET(sock) (sock > 0)
#define SUCCESS 0
#define FAILURE 1
 
int status = 0;
 
void make_request(struct pkt *sendpkt);
void print_packet(struct pkt *sendpkt);
int socket_set_option (int sock, int level, int optname, const void *optval);
 
int main(int argc, char **argv) {
	struct pkt sendpkt;
	struct pkt recvpkt;
	struct timeval timeval_v;
	struct sockaddr_in localAddr;
	struct sockaddr_in servAddr;
	char *host = (argv[1]) ? argv[1] : "localhost";
	int fromlen, len;
	struct hostent *h;
	int sock, port=123, n, i = 0, timeout = 2;
	char *sendbuf = (char *)&sendpkt;
	char *recvbuf = (char *)&recvpkt;
 
	h = gethostbyname(host);
	if (h == NULL)
		return -1;
 
	memset((char *)&servAddr, 0x0, sizeof(servAddr));
	servAddr.sin_family = h->h_addrtype;
	memcpy((char *)&servAddr.sin_addr.s_addr, h->h_addr_list[0], h->h_length);
	servAddr.sin_port = htons(port);
	sock = socket(AF_INET, SOCK_DGRAM, 0);
 
	if (sock < 0)
		return -1;
 
	memset((char *)&localAddr, 0x0, sizeof(localAddr));
	localAddr.sin_family = AF_INET;
	localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	localAddr.sin_port = htons(0);
	bzero((char *)&localAddr.sin_zero, 8);
	if (bind(sock, (struct sockaddr *)&localAddr, sizeof(localAddr)) < 0) {
		perror("ntp: bind");
		return -1;
	}
 
	/* recvfrom 으로부터의 blocking 시간의 설정 */
	if (timeout > 0) {
		timeval_v.tv_sec = timeout;
		timeval_v.tv_usec = 0;
		socket_set_option(sock, SOL_SOCKET, SO_SNDTIMEO, &timeval_v);
		socket_set_option(sock, SOL_SOCKET, SO_RCVTIMEO, &timeval_v);
	}
 
	/* getsockname() 함수를 이용하면 sin_port = 0 의 상황에서도
	 * kernel 에서 현재 나에게 자동으로 bind 된 포트를 확인 할수 있다.
	 */
	len = sizeof(localAddr);
	getsockname(sock, (struct sockaddr *)&localAddr, (socklen_t *)&len);
	printf("server               : %s\n", host);
	printf("server port          : %d\n", port);
	printf("my bind port         : %d\n\n", ntohs(localAddr.sin_port));
 
	make_request(&sendpkt);
 
    printf("send packet size     : %d\n", PKT_SIZE);
    printf("send packet          : ");
 
    /* request packet 내용을 한자씩 읽어서 보여준다. */
    for(i=0;i < PKT_SIZE; i++) {
        printf("%02x ", (unsigned char)*(sendbuf+i));
    }
	printf("\n");
	print_packet(&sendpkt);
	printf("\n");
 
	/* 첫번째 request packet 전송 */
	if (sendto(sock, sendbuf, PKT_SIZE, 0, (struct sockaddr *)&servAddr, sizeof(servAddr)) != PKT_SIZE) {
		perror("ntp: sendto");
		goto try_return;
	}
	n = recvfrom(sock, &recvpkt, PKT_SIZE, 0,
			(struct sockaddr *)&servAddr, (socklen_t *)&fromlen);
 
    printf("recv packet size     : %d\n", n);
    printf("recv packet          : ");
	for(i=0;i < PKT_SIZE; i++) {
        printf("%02x ", (unsigned char)*(recvbuf+i));
    }
	printf("\n");
	print_packet(&recvpkt);
	printf("\n");
	/* 첫번째 request packet 전송 끝 */
 
	/* 두번째 request packet 전송 시작 */
	recvpkt.li_vn_mode = PKT_LI_VN_MODE(LEAP_NOTINSYNC, NTP_VERSION, MODE_CLIENT);/* 3 4 3 == 227 */;
	recvpkt.stratum = 0;
	recvpkt.ppoll = 4;
	recvpkt.precision = -6;
	recvpkt.rootdelay = 256;
	recvpkt.rootdispersion = 256;
 
	recvpkt.reftime.l_i = recvpkt.xmt.l_i;
	recvpkt.reftime.l_f = recvpkt.xmt.l_f;
	recvpkt.org.l_i = recvpkt.xmt.l_i;
	recvpkt.org.l_f = recvpkt.xmt.l_f;
 
    printf("send packet size     : %d\n", PKT_SIZE);
    printf("send packet          : ");
 
    /* request packet 내용을 한자씩 읽어서 보여준다. */
    for(i=0;i < PKT_SIZE; i++) {
        printf("%02x ", (unsigned char)*(recvbuf+i));
    }
	printf("\n");
	print_packet(&recvpkt);
	printf("\n");
 
	if (sendto(sock, recvbuf, PKT_SIZE, 0, (struct sockaddr *)&servAddr, sizeof(servAddr)) != PKT_SIZE) {
		perror("ntp: sendto");
		goto try_return;
	}
	n = recvfrom(sock, &recvpkt, PKT_SIZE, 0,
			(struct sockaddr *)&servAddr, (socklen_t *)&fromlen);
 
    printf("recv packet size     : %d\n", n);
    printf("recv packet          : ");
	for(i=0;i < PKT_SIZE; i++) {
        printf("%02x ", (unsigned char)*(recvbuf+i));
    }
	printf("\n");
	print_packet(&recvpkt);
	/* 두번째 request packet 전송 끝 */
 
	if ((recvpkt.li_vn_mode & 0x7) == MODE_SERVER)
		status = 1;
 
try_return:
	if (status == 1)
		printf("\nNTPD SERVER STATUS  : OK\n");
	else
		printf("\nNTPDD SERVER STATUS : FAIL\n");
 
	if (IS_SOCKET(sock)) close(sock);
 
	return 0;
}
 
/*
 *************************************************
 *
 *       print_packet()
 *
 * 설명
 *       ntp 패킷 헤더를 보여준다.
 *
 * 인자
 *       1. ntp packet 구조체 포인터
 *
 * 반환값
 *       무
 *
 *************************************************
 */
void print_packet(struct pkt *npkt) {
	time_t seconds;
	struct pkt tpkt;
	char buf[128];
	uint64_t reftime, org, rec, xmt; 
 
	memcpy(&reftime, &npkt->reftime, sizeof(uint64_t));
	memcpy(&org, &npkt->org, sizeof(uint64_t));
	memcpy(&rec, &npkt->rec, sizeof(uint64_t));
	memcpy(&xmt, &npkt->xmt, sizeof(uint64_t));
 
	printf("li_vn_mode           : %02d / LI: %d, VN: %d, MODE : %d\n", (uint8_t)npkt->li_vn_mode, npkt->li_vn_mode >> 6,
															((npkt->li_vn_mode >> 3) & 0x7), npkt->li_vn_mode & 0x7);
	printf("Stratum              : %02d\n", npkt->stratum);
	printf("Poll                 : %02d\n", npkt->ppoll);
	printf("Precision            : %02d\n", npkt->precision);
	printf("Root Delay           : %02x\n", npkt->rootdelay);
	printf("Root Dispersion      : %02x\n", npkt->rootdispersion);
	printf("Reference Identifier : %02x\n", npkt->refid);
	printf("Reference Timestamp  : %02lx\n", reftime);
	printf("Originate Timestamp  : %02lx\n", org);
	printf("Receive Timestamp    : %02lx\n", rec);
	printf("Transmit Timestamp   : %02lx\n", xmt);
 
	NTOHL_FP(&npkt->reftime, &tpkt.reftime);
	NTOHL_FP(&npkt->org, &tpkt.org);
	NTOHL_FP(&npkt->rec, &tpkt.rec);
	NTOHL_FP(&npkt->xmt, &tpkt.xmt);
 
	NTP_TO_UNIX(tpkt.reftime.l_ui, seconds);
	strftime(buf, sizeof(buf), "%Y/%m/%d %T",localtime(&seconds));
	printf("Reference Time       : %s\n", buf);
 
	NTP_TO_UNIX(tpkt.org.l_ui, seconds);
	strftime(buf, sizeof(buf), "%Y/%m/%d %T",localtime(&seconds));
	printf("Originate Time       : %s\n", buf);
 
	NTP_TO_UNIX(tpkt.rec.l_ui, seconds);
	strftime(buf, sizeof(buf), "%Y/%m/%d %T",localtime(&seconds));
	printf("Receive Time         : %s\n", buf);
 
	NTP_TO_UNIX(tpkt.xmt.l_ui, seconds);
	strftime(buf, sizeof(buf), "%Y/%m/%d %T",localtime(&seconds));
	printf("Transmit Time        : %s\n", buf);
}
 
/*
 *************************************************
 *
 *       make_request()
 *
 * 설명
 *       ntp 패킷 헤더를 생성한다.
 *
 * 인자
 *       1. ntp packet 구조체 포인터
 *
 * 반환값
 *       무
 *
 *************************************************
 */
void make_request(struct pkt *sendpkt) {
	sendpkt->li_vn_mode = PKT_LI_VN_MODE(LEAP_NOTINSYNC, NTP_VERSION, MODE_CLIENT);/* 3 4 3 == 227 */;
	sendpkt->stratum = 0;
	sendpkt->ppoll = 4;
	sendpkt->precision = 0;
	sendpkt->rootdelay = 0;
	sendpkt->rootdispersion = 0;
	sendpkt->reftime.Ul_i.Xl_i = 0;
	sendpkt->reftime.Ul_f.Xl_f = 0;
	sendpkt->org.Ul_i.Xl_i = 0;
	sendpkt->org.Ul_f.Xl_f = 0;
	sendpkt->rec.Ul_i.Xl_i = 0;
	sendpkt->rec.Ul_f.Xl_f = 0;
	sendpkt->xmt.Ul_i.Xl_i = 0;
	sendpkt->xmt.Ul_f.Xl_f = 0;
}
 
/*
 *************************************************
 *
 *       socket_set_option()
 *
 * 설명
 *       socket option에 대한 현재 값을 설정 또는 변경한다.
 *
 * 인자
 *       1. socket descriptor
 *       2. SOL_SOCKET
 *          IPPROTO_IP
 *          IPPROTO_ICMPV6
 *          IPPROTO_IPV6
 *          IPPROTO_TCP
 *       3. 각 level 에 속한 optname
 *       4. 변경할 값을 저장한 변수
 *
 * 반환값
 *       성공 = SUCCESS 
 *       실패 = FAILURE
 *
 *************************************************
 */
int socket_set_option (int sock, int level, int optname, const void *optval)
{
	socklen_t optlen;
 
	switch(optname) {
		case SO_LINGER:
			optlen = sizeof(struct linger);
			if (setsockopt(sock, level, optname, optval, optlen) != 0) {
				perror("unable to retrieve socket option");
				return FAILURE;
			}
			break;
 
		case SO_RCVTIMEO:
		case SO_SNDTIMEO:
			optlen = sizeof(struct timeval);
			if (setsockopt(sock, level, optname, optval, optlen) != 0) {
				perror("unable to retrieve socket option");
				return FAILURE;
			}
			break;
 
		default:
			optlen = sizeof(int);
			if (setsockopt(sock, level, optname, optval, optlen) != 0) {
				perror("unable to retrieve socket option");
				return FAILURE;;
			}
			break;
	}
	return SUCCESS;
}
