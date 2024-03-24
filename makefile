LDLIBS=-lpcap

all: send-arp-test


main.o: mac.h ip.h ethhdr.h arphdr.h main.cpp request.o

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

request.o : request.h request.cpp

send-arp-test: main.o arphdr.o ethhdr.o ip.o mac.o request.o -lnet -lpcap
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp-test *.o
