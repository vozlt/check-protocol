# @file: Makefile
# @brief:
# @author: YoungJoo.Kim <http://superlinuxer.com>
# @version:
# @date: 20140715

TARGETS=icmp_status icmp_traceroute smtp_status sntp_status tftp_status
GCC=gcc
CFLAGS=-Wall -O2

all: $(TARGETS)

clean:
	rm -f *.o $(TARGETS)
