/*
+--------------------------------------------------+
| @file: tftp_status.c                             |
| @brief: Program for tftp status testing          |
| @author: YoungJoo.Kim <vozlt@vozlt.com>          |
| @version:                                        |
| @date: 20080428                                  |
+--------------------------------------------------+
 
+-----------------------------------------------------------------------------+
shell> gcc -o tftp_status tftp_status.c
shell> ./tftp_status tftp.vozlt.com
server           : tftp.vozlt.com
server port      : 69
my bind port     : 33451
send packet size : 17
send packet      : 00 01 76 30 7a 6c 74 00 6e 65 74 61 73 63 69 69 00 
                   00 01 v  0  z  l  t  00 n  e  t  a  s  c  i  i  00 
recv packet size : 19
recv packet      : 00 05 00 01 46 69 6c 65 20 6e 6f 74 20 66 6f 75 6e 64 00 
                   00 05 00 01 F  i  l  e     n  o  t     f  o  u  n  d  00 
th_opcode        : 5
th_block         : 1
th_data          : File not found
TFTPD SERVER STATUS : OK
+-----------------------------------------------------------------------------+
 
        http://www.faqs.org/rfcs/rfc1350.html   
        opcode  operation
        1     Read request (RRQ)
        2     Write request (WRQ)
        3     Data (DATA)
        4     Acknowledgment (ACK)
        5     Error (ERROR)
 
        2 bytes     string    1 byte     string   1 byte
        ------------------------------------------------
        | Opcode |  Filename  |   0  |    Mode    |   0  |
        ------------------------------------------------
        Figure 5-1: RRQ/WRQ packet
 
        2 bytes     2 bytes      0-512 bytes
        ----------------------------------
        | Opcode |   Block #  |   Data     |
        ----------------------------------
        Figure 5-2: DATA packet
 
         2 bytes     2 bytes
         ---------------------
        | Opcode |   Block #  |
         ---------------------
        Figure 5-3: ACK packet
 
        2 bytes     2 bytes      string    1 byte
        -----------------------------------------
        | Opcode |  ErrorCode |   ErrMsg   |   0  |
        -----------------------------------------
        Figure 5-4: ERROR packet
 
    TFTP Formats
       Type   Op #     Format without header
              2 bytes    string   1 byte     string   1 byte
              -----------------------------------------------
       RRQ/  | 01/02 |  Filename  |   0  |    Mode    |   0  |
       WRQ    -----------------------------------------------
              2 bytes    2 bytes       n bytes
              ---------------------------------
       DATA  | 03    |   Block #  |    Data    |
              ---------------------------------
              2 bytes    2 bytes
              -------------------
       ACK   | 04    |   Block #  |
              --------------------
              2 bytes  2 bytes        string    1 byte
              ----------------------------------------
       ERROR | 05    |  ErrorCode |   ErrMsg   |   0  |
              ----------------------------------------
        Error Codes
           Value     Meaning
           0         Not defined, see error message (if any).
           1         File not found.
           2         Access violation.
           3         Disk full or allocation exceeded.
           4         Illegal TFTP operation.
           5         Unknown transfer ID.
           6         File already exists.
           7         No such user.
 
*/
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <ctype.h>
 
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
 
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
 
#define SEGSIZE     512
 
#define RRQ   01
#define WRQ   02
#define DATA  03
#define ACK   04
#define ERROR 05
 
/* 
 * 총 구조체 사이즈 = 5byte
 * 		short = 2byte
 * 		unsigned short = 2byte
 * 		char = 1byte
 *
 * __attribute__ ((x))
 * 		__attribute__ ((packed)) = 구조체 정렬 alignment (구조체에 정의한 내용대로 메모리 할당)
 *		밑의 구조체의 경우 __attribute__ ((packed)) 해주지 않으면 6byte로 잡힘!
 *		CPU가 메모리 Address 를 지정할때 내부적으로 가장 최적화된 단위를 사용함!(32bit의 경우 4byte)
 *		예 :
 *			typedef struct {
 *			char a;
 *			int b;
 *			} test;
 *			총 사이즈 : 8byte
 *		
 *			typedef struct {
 *			char a;
 *			int b;
 *			} __attribute__((__packed__)) test;
 *			총 사이즈 : 5byte
 * 
 * 참고 : /usr/include/arpa/tftp.h
 */
struct  tftphdr {
    short   th_opcode; /* packet type */
    union {
        unsigned short  tu_block; /* block # */
        short   tu_code; /* error code */
        char    tu_stuff[1]; /* request packet stuff */
    } __attribute__ ((__packed__)) th_u;
    char    th_data[1]; /* data or error string */
} __attribute__ ((__packed__));
 
#define th_block    th_u.tu_block
#define th_code     th_u.tu_code
#define th_stuff    th_u.tu_stuff
#define th_msg      th_data
 
#define EUNDEF      0 /* not defined */
#define ENOTFOUND   1 /* file not found */
#define EACCESS     2 /* access violation */
#define ENOSPACE    3 /* disk full or allocation exceeded */
#define EBADOP      4 /* illegal TFTP operation */
#define EBADID      5 /* unknown transfer ID */
#define EEXISTS     6 /* file already exists */
#define ENOUSER     7 /* no such user */
 
#define PKTSIZE    SEGSIZE+4
#define IS_SOCKET(sock) (sock > 0)
 
#define SUCCESS 0
#define FAILURE 1
 
int status = 0;
 
static int makerequest(int request, const char *name, struct tftphdr *dp, const char *mode);
int socket_set_option (int sock, int level, int optname, const void *optval);
 
int main(int argc, char **argv) {
 
	struct timeval timeval_v;
	struct tftphdr *dp;
	struct tftphdr *vp;
	struct sockaddr_in localAddr;
	struct sockaddr_in servAddr;
	char ackbuf[PKTSIZE];
	char buf[PKTSIZE];
	char *host = (argv[1]) ? argv[1] : "localhost";
	int size, fromlen, len;
	struct hostent *h;
	int sock, port=69, n, i = 0, timeout = 2;
	u_short vp_opcode, vp_block;
 
	vp = (struct tftphdr *)buf; /* recv buffer */
	dp = (struct tftphdr *)ackbuf; /* send buffer */
 
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
		perror("tftp: bind");
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
	printf("server           : %s\n", host);
	printf("server port      : %d\n", port);
	printf("my bind port     : %d\n", ntohs(localAddr.sin_port));
 
	/*
		2 bytes     string    1 byte     string   1 byte
		------------------------------------------------
		| Opcode |  Filename  |   0  |    Mode    |   0  |
		------------------------------------------------
		Figure 5-1: RRQ/WRQ packet
 
		2 bytes     5bytes    1 byte     8bytes   1 byte
		------------------------------------------------
		| 01     |  v0zlt     |   0  |  netascii  |   0  |
		------------------------------------------------
		Total : 17 bytes RRQ packet send
 
	*/
 
	/* RRQ request packet 생성 */
	size = makerequest(RRQ, "v0zlt", dp, "netascii");
 
	printf("send packet size : %d\n", size);
	printf("send packet      : ");
 
	/* RRQ request packet 내용을 한자씩 읽어서 보여준다. */
	for(i=0;i < size; i++) {
		printf("%02x ", (unsigned char)ackbuf[i]);
	}
	printf("\n                   ");
	for(i=0;i < size; i++) {
		if(isprint(ackbuf[i]))
			printf("%c  ", (unsigned char)ackbuf[i]);
		else
			printf("%02x ", (unsigned char)ackbuf[i]);
	}
	printf("\n\n");
 
	/* RRQ request packet 전송 */
	if (sendto(sock, ackbuf, size, 0, (struct sockaddr *)&servAddr, sizeof(servAddr)) != size) {
		perror("tftp: sendto");
		goto try_return;
	}
 
	/* RRQ response packet 받기 */
	i = 0;
	do {
		fromlen = sizeof(servAddr);
		n = recvfrom(sock, vp, PKTSIZE, 0,
				(struct sockaddr *)&servAddr, (socklen_t *)&fromlen);
		if(n < 0) i++;
		if(i > 0) goto try_return;
	} while (n <= 0);
 
	printf("recv packet size : %d\n", n);
	printf("recv packet      : ");
	/* RRQ response packet 내용을 한자씩 읽어서 보여준다. */
	for(i=0;i < n; i++) {
		printf("%02x ", (unsigned char)buf[i]);
	}
	printf("\n                   ");
	for(i=0;i < n; i++) {
		if(isprint(buf[i]))
			printf("%c  ", (unsigned char)buf[i]);
		else
			printf("%02x ", (unsigned char)buf[i]);
	}
	printf("\n");
 
 
	vp_opcode = ntohs((u_short)vp->th_opcode);
	vp_block = ntohs((u_short)vp->th_block);
 
	printf("th_opcode        : %d\n", vp_opcode);
	printf("th_block         : %d\n", vp_block);
	printf("th_data          : %s\n", vp->th_data);
 
	/* 실제 데이타 요청에 대한 응답에 대해
	 * 03 = DATA
	 * 05 = ERROR
	 * 03 / 05 의 응답은 TFTP 의 실제 작동을 확인 할수 있는 코드이다.
	 * 그러므로 이 두개의 응답 코드는 TFTPD 서버의 정상적인 작동을 의미한다.
	 */
	if (vp_opcode == 3 || vp_opcode == 5) status = 1;
 
try_return:
	if (status == 1)
		printf("\nTFTPD SERVER STATUS : OK\n");
	else
		printf("\nTFTPD SERVER STATUS : FAIL\n");
 
	if (IS_SOCKET(sock)) close(sock);
 
	return 0;
}
 
/*
 *************************************************
 *
 *       makerequest()
 *
 * 설명
 *       RRQ/WRQ request packet 를 생성한다.
 *
 * 인자
 *       1. RRQ/WRQ
 *       2. filename
 *       3. packet 을 저장할 구조체 포인터
 *       4. mode (netascii / octet / mail)
 *
 * 반환값
 *       생성된 packet 의 사이즈
 *
 *************************************************
 */
static int makerequest(int request, const char *name, struct tftphdr *dp, const char *mode)
{
	/*
		2 bytes     string    1 byte     string   1 byte
		------------------------------------------------
		| Opcode |  Filename  |   0  |    Mode    |   0  |
		------------------------------------------------
		Figure 5-1: RRQ/WRQ packet
 
		2 bytes     5bytes    1 byte     8bytes   1 byte
		------------------------------------------------
		| 01     |  v0zlt     |   0  |  netascii  |   0  |
		------------------------------------------------
		Example : 17 bytes RRQ packet send
 
	*/
	char *cp;
	/*
	short n;
 
	printf ("%d\n%d\n", dp, (char *)dp->th_opcode);
	memset (dp, htons((u_short)RRQ), 2);
	n = 2;
	memcpy (dp + n, name, strlen (name));
	n += strlen (name);
	memset (dp + n, 0, 1);
	n += 1;
	memcpy (dp + n, mode, strlen (mode));
	n += strlen (mode);
	memset (dp + n, 0, 1);
	n += 1;
 
	printf ("## %d\n", n);
 
	return 2 + strlen(name) + 1 + strlen (mode) + 1;
	*/
    dp->th_opcode = htons((u_short)RRQ);
    cp = (char *) &(dp->th_stuff);
    strncpy(cp, name, strlen(name));
    cp += strlen(name) + 1;
	*(cp - 1) = '\0';
    strncpy(cp, mode, strlen(mode));
    cp += strlen(mode) + 1;
	*(cp - 1) = '\0';
    return (cp - (char *)dp);
 
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
