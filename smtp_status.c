/*
+--------------------------------------------------+
| @file: smtp_status.c                             |
| @brief: Program for tftp status testing          |
| @author: YoungJoo.Kim <vozlt@vozlt.com>          |
| @version:                                        |
| @date: 20080414                                  |
+--------------------------------------------------+
 
+-----------------------------------------------------------------------------+
shell> gcc -o smtp_status smtp_status.c
shell> ./smtp_status mx1.hotmail.com root@smtp.vozlt.com anonymous@hotmail.com
<<< 220 SNT0-MC3-F19.Snt0.hotmail.com Sending unsolicited commercial or bulk e-mail to Microsoft's computer network is prohibited.
 
>>> HELO mx1.hotmail.com
 
<<< 250 SNT0-MC3-F19.Snt0.hotmail.com (3.19.0.77) Hello [61.72.251.55]
 
>>> MAIL FROM: root@smtp.vozlt.com
 
<<< 250 root@smtp.vozlt.com....Sender OK
 
>>> RCPT TO: anonymous@hotmail.com
 
<<< 250 anonymous@hotmail.com
 
>>> DATA
 
<<< 354 Start mail input; end with <CRLF>.<CRLF>
 
>>> Subject: SMTP PROTOCOL TESTING
DATA SECTION
.
 
<<< 250 <SNT0-MC3-F1964xSNUX00142e45@SNT0-MC3-F19.Snt0.hotmail.com> Queued mail for delivery
 
>>> QUIT
 
<<< 221 SNT0-MC3-F19.Snt0.hotmail.com Service closing transmission channel
 
SMTP SERVER STATUS : OK
+-----------------------------------------------------------------------------+
 
[SMTP COMMAND-REPLY SEQUENCES]
 
	http://www.ietf.org/rfc/rfc0821.txt
 
	S = SUCCESS
	F = FAILURE
	E = ERROR
 
				CONNECTION ESTABLISHMENT
				   S: 220
				   F: 421
				HELO
				   S: 250
				   E: 500, 501, 504, 421
				MAIL
				   S: 250
				   F: 552, 451, 452
				   E: 500, 501, 421
 
				RCPT
				   S: 250, 251
				   F: 550, 551, 552, 553, 450, 451, 452
				   E: 500, 501, 503, 421
				DATA
				   I: 354 -> data -> S: 250
									 F: 552, 554, 451, 452
				   F: 451, 554
				   E: 500, 501, 503, 421
				RSET
				   S: 250
				   E: 500, 501, 504, 421
				SEND
				   S: 250
				   F: 552, 451, 452
				   E: 500, 501, 502, 421
				SOML
				   S: 250
				   F: 552, 451, 452
				   E: 500, 501, 502, 421
				SAML
				   S: 250
				   F: 552, 451, 452
				   E: 500, 501, 502, 421
				VRFY
				   S: 250, 251
				   F: 550, 551, 553
				   E: 500, 501, 502, 504, 421
				EXPN
				   S: 250
				   F: 550
				   E: 500, 501, 502, 504, 421
				HELP
				   S: 211, 214
				   E: 500, 501, 502, 504, 421
				NOOP
				   S: 250
				   E: 500, 421
				QUIT
				   S: 221
				   E: 500
				TURN
				   S: 250
				   F: 502
				   E: 500, 503
 
 
	HELO :
			클라이언트 자신의 확인(identify)
 
	MAIL :
			메시지의 출처(originator)를 확인
 
	RCPT : 
			메시지의 수신처(recipient)를 확인
			수신처가 여러곳일 경우 한 개 이상일 수 있다
			한명 이상에게 보낼 수 있다.
 
	DATA :  
			메일 메시지의 내용을 전송
			한줄에 마침표만 있는 줄을 전송함으로써 내용을 끝을 알림
 
	QUIT :
			메일 교환을 종료
 
 
	EXAMPLE : 	
			<<< 220
			>>> MAIL From: from@vozlt.com
			<<< 250
			>>> RCPT To: vozlt@vozlt.com
			<<< 250
			>>> DATA
			<<< 354
			>>> blah~blah~
			>>> .
			<<< 250
			>>> quit
			<<< 221
 
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
 
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
 
#define SUCCESS 0
#define FAILURE 1
 
#define LINGERON 1
#define LINGEROFF 0
 
#define IS_SOCKET(sock) (sock > 0)
 
int socket_set_option (int sock, int level, int optname, const void *optval);
int socket_close (int sock, int l_onoff);
int socket_connect_tcp (char *server, unsigned int port, unsigned int timeout);
int socket_wait_io (int sock, unsigned int seconds);
int socket_getline (char *str, size_t size, int sock, unsigned int timeout);
 
int main(int argc, char **argv) {
 
	int sock, status = 0;
	char *host = (argv[1]) ? argv[1] : "localhost";
	char *from = (argv[2]) ? argv[2] : "anonymous@anonymous.con";
	char *to = (argv[3]) ? argv[3] : "anonymous@anonymous.con";
	char *data = (argv[4]) ? argv[4] : "Subject: SMTP PROTOCOL TESTING\r\nDATA SECTION";
	char buf[512];
	unsigned int port = 25;
 
	if ((sock = socket_connect_tcp(host, port, 2)) < 0) {
		snprintf(buf, sizeof(buf) - 1, "socket_connect_tcp() Failed, %d Line, Host %s, Port %d", __LINE__, host, port);
		perror(buf);
		goto try_return;
	}
 
	/* 서버 준비 확인 */
	socket_getline(buf, sizeof(buf), sock, 1);
	printf("<<< %s\n", buf);
	if (strncmp (buf, "220", 3) != 0)
		goto try_return;
 
	/* HELO 응답 확인 */
	sprintf(buf, "HELO %s\r\n", host);
	printf(">>> %s\n", buf);
	write (sock, buf, strlen(buf));
	socket_getline(buf, sizeof(buf), sock, 1);
	printf("<<< %s\n", buf);
	if (strncmp (buf, "250", 3) != 0)
		goto try_return;
 
	/* MAIL 응답 확인 */
	sprintf(buf, "MAIL FROM: %s\r\n", from);
	printf(">>> %s\n", buf);
	write (sock, buf, strlen(buf));
	socket_getline(buf, sizeof(buf), sock, 1);
	printf("<<< %s\n", buf);
	if (strncmp (buf, "250", 3) != 0)
		goto try_return;
 
	/* RCPT 응답 확인 */
	sprintf(buf, "RCPT TO: %s\r\n", to);
	printf(">>> %s\n", buf);
	write (sock, buf, strlen(buf));
	socket_getline(buf, sizeof(buf), sock, 1);
	printf("<<< %s\n", buf);
	if (strncmp (buf, "250", 3) != 0)
		goto try_return;
 
	/* DATA 응답 확인 */
	sprintf(buf, "%s", "DATA\r\n");
	printf(">>> %s\n", buf);
	write (sock, buf, strlen(buf));
	socket_getline(buf, sizeof(buf), sock, 1);
	printf("<<< %s\n", buf);
	if (strncmp (buf, "354", 3) != 0)
		goto try_return;
 
	/* DATA 쓰기 완료 . 응답 확인 */
	sprintf(buf, "%s\r\n.\r\n", data);
	printf(">>> %s\n", buf);
	write (sock, buf, strlen(buf));
	socket_getline(buf, sizeof(buf), sock, 1);
	printf("<<< %s\n", buf);
	if (strncmp (buf, "250", 3) != 0)
		goto try_return;
 
	/* QUIT 응답 확인 */
	sprintf(buf, "%s", "QUIT\r\n");
	printf(">>> %s\n", buf);
	write (sock, buf, strlen(buf));
	socket_getline(buf, sizeof(buf), sock, 1);
	printf("<<< %s\n", buf);
	if (strncmp (buf, "221", 3) != 0)
		goto try_return;
 
	status = 1;
 
try_return:
	if(status == 1)
		printf("SMTP SERVER STATUS : OK\n");
	else
		printf("SMTP SERVER STATUS : FAIL\n");
 
	if (IS_SOCKET(sock)) socket_close(sock, LINGERON);
 
	return 0;
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
 
/*
 *************************************************
 *
 *       socket_close()
 *
 * 설명
 *       socket 을 close 한다.
 *
 * 인자
 *       1. socket descriptor
 *       2. LINGERON  = 기본적인 기다림을 가지지 않고 곧장 종료
 *          LINGEROFF = 기본적인 기다림을 가진후 종료 (기본값)
 *
 * 반환값
 *       close() 반환 값
 *
 *************************************************
 */
int socket_close (int sock, int l_onoff)
{
	/*
	 *
	 * SO_LINGER 옵션 
	 * 이것은 TCP 에서 적용되는 것인데 close함수의 행동을 지정하는 옵션입니다.
	 * close() 하면 recv Buffer 나 send Buffer 에 보내거나 받을 데이터가 있다면 전부 처리 후 close() 를 합니다.
	 * 그 방법을 바꾸는 것입니다. 먼저 전달되는 구조체에 대해서 알아 보도록 합시다. 
	 *
	 * struct linger
	 * {
	 *     int l_onoff;
	 *     int l_linger;
	 * };
	 *
	 * setsockopt( sock, SOL_SOCKET, SO_LINGER, &linger 구조체 주소, sizeof( linger ) );
	 * 
	 * 이런 식으로 호출하면 되겠죠. 그리고 세부적인 동작 설정은 linger구조체의 변수 설정에 있습니다. 
	 *
	 *  1. l_onoff가 0이면 기본적인 TCP동작이 적용됩니다. 
	 *  2. l_onoff가 0이 아니고(주로 1을 넣습니다.) l_linger가 0이면 연결이 닫힐 때 버퍼의 내용을 버리고 연결을 끊어 버립니다. 
	 *  3. l_onoff가 0이 아니고 l_linger도 0이 아니면 소켓이 닫힐 때 블럭 당한다고 합니다. 
	 *
	 *         이 소켓옵션을 쓸 땐 2번을 주로 씁니다. 쓰는 이유는 만약 서버가 종료되고 다시 시작 할 때 입니다. 
	 *         연결이 끊어지고 남은 데이터를 전송합니다.
	 *         그때 남은 데이터를 보낸다면 클라이언트에게 ack 메시지(받았다는 확인 메시지)를 받아야 완전한 종료가 이루어집니다.
	 *         그 메시지를 기다리는 시간이 있습니다.
	 *         만약 그것을 다 받지 못했다면 다시 보내야 하지요.
	 *         그런 상황에서 다시 서버를 시작하려고 하면 이미 사용 중인 포트라는 에러를 내게 됩니다.
	 *         그래서 이런 옵션을 사용하는 것입니다. 그런데 그것은 바람직한 해결 방법이 아니라고 합니다.
	 *         그래서 이런 옵션은 추천되고 있지 않습니다. 
	 *
	 */
	struct linger linger_v;		
 
	if (l_onoff > 0) {
		linger_v.l_onoff = 0x01;
		linger_v.l_linger = 0x00;
		socket_set_option(sock, SOL_SOCKET, SO_LINGER, &linger_v);
	}
	return close(sock);
}
 
/*
 *************************************************
 *
 *       socket_connect_tcp()
 *
 * 설명
 *       tcp 연결을 수행한다.
 *
 * 인자
 *       1. 목적지 서버
 *       2. 목적지 포트
 *       3. 최대 연결 기다림 시간(0 = 기본 소켓 타임 아웃 시간 설정)
 *
 * 반환값
 *       성공 = socket descriptor
 *       실패 = -1
 *
 *************************************************
 */
int socket_connect_tcp (char *server, unsigned int port, unsigned int timeout)
{
	struct sockaddr_in localAddr, servAddr;
	struct hostent *h;
	struct timeval timeval_v;
	int rc;
	int sock;
 
	h = gethostbyname(server);
	if (h == NULL)
		return -1;
 
	memset((char *)&servAddr, 0x0, sizeof(servAddr));
	servAddr.sin_family = h->h_addrtype;
	memcpy((char *)&servAddr.sin_addr.s_addr, h->h_addr_list[0], h->h_length);
	servAddr.sin_port = htons(port);
 
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;
 
	if (timeout > 0) {
		timeval_v.tv_sec = timeout;
		timeval_v.tv_usec = 0;
		socket_set_option(sock, SOL_SOCKET, SO_SNDTIMEO, &timeval_v);
		socket_set_option(sock, SOL_SOCKET, SO_RCVTIMEO, &timeval_v);
	}
 
	memset((char *)&localAddr, 0x0, sizeof(localAddr));
	localAddr.sin_family = AF_INET;
	localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	localAddr.sin_port = htons(0);
 
	rc = bind(sock, (struct sockaddr *)&localAddr, sizeof(localAddr));
	if (rc < 0)
		return -1;
 
	rc = connect(sock, (struct sockaddr *)&servAddr, sizeof(servAddr));
	if (rc < 0)
		return -1;
 
	return sock;
}
 
/*
 *************************************************
 *
 *       socket_wait_io()
 *
 * 설명
 *       socket/file descriptor I/O 상태를 확인한다.
 *
 * 인자
 *       1. socket/file descriptor
 *       2. socket/file descriptor 상태 검사 제한 시간(초)
 *
 * 반환값
 *       I/O 발생  =  1 
 *       타임 아웃 =  0
 *       에러      = -1
 *
 *************************************************
 */
int socket_wait_io (int sock, unsigned int seconds)
{
	fd_set set;
	struct timeval timeout;
 
	FD_ZERO(&set);
	FD_SET(sock, &set);
 
	timeout.tv_sec = seconds;
	timeout.tv_usec = 0;
 
	return select(sock + 1, &set, (fd_set *)NULL, (fd_set *)NULL, &timeout);
}
 
/*
 *************************************************
 *
 *       socket_getline()
 *
 * 설명
 *       해당 socket descriptor 로 부터 한 라인을 읽어 들인다.
 *
 * 인자
 *       1. 읽어들인 라인을 저장할 버퍼에 대한 포인터
 *       2. 읽어들일 한라인에 대한 최대 크기
 *       3. socket descriptor
 *       4. I/O 최대 기다림 시간
 *
 * 반환값
 *       성공 = 읽은 바이트 수
 *       실패 = -1
 *
 *************************************************
 */
int socket_getline (char *str, size_t size, int sock, unsigned int timeout)
{
	char c, *ptr = str;
	int r;
 
	while(socket_wait_io(sock, timeout) > 0) {
		if ((r = read(sock, &c, 1)) != 0) {
			if (r < 0)
				return -1;
 
			if ((ptr - str) >= size)
				break; 
 
			*(ptr++) = c;
 
			if (c == '\n')
				break;
		} else { return -1; }
	}
	*ptr = '\0';
	return (ptr - str);
}
