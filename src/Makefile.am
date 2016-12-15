SUBDIRS=lib
CURRENTPATH=$(shell /bin/pwd)
INCLUDES=-I$(CURRENTPATH)/include
export INCLUDES

noinst_PROGRAMS=pcap-filter
pcap_filter_SOURCES=main.c
pcap_filter_LDADD=$(CURRENTPATH)/lib/libpcap-filter.a
