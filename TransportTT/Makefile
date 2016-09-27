CC = gcc
CCP = g++
CFLAGS  = -g -Wall
CPFLAGS = -g -Wall -pthread

TRANSPORT_TEST = TransportTT

OBJS = main.o Server.o Client.o Config.o ServerAPI.o

LIBS = -lpthread 

CPPLIBS = -lpthread -lssl

BOOSTLIB = -lboost_system

CPPFLAGS = -I/usr/include/openssl

SRCS = Config.c

default: $(TRANSPORT_TEST)

debug: CPFLAGS += -DDEBUG=1
debug: $(TRANSPORT_TEST)

#Build with any logging for embtest
embtest:CPFLAGS += -DEMBTEST=1
embtest: $(TRANSPORT_TEST)

centos5v: CPFLAGS += -DSSL_9_CENTOS_5=1
centos5v: $(TRANSPORT_TEST)

profile: CPFLAGS += -pg
profile: $(TRANSPORT_TEST)

$(TRANSPORT_TEST): $(OBJS)
	$(CCP) $(CPFLAGS) $(CPPFLAGS) $(CPPLIBS) $(BOOSTLIB) -o $@ $(OBJS)

main.o: main.cpp Client.cpp Server.cpp ServerAPI.cpp Config.c 
	$(CCP) $(CPFLAGS) $(LIBFLAGS) $(CPPLIBS) -c main.cpp

Client.o: Client.cpp Client.h
	$(CCP) $(CPFLAGS) $(LIBFLAGS) $(CPPLIBS) -lboost_system -lboost_thread -c Client.cpp 

ServerAPI.o: ServerAPI.cpp ServerAPI.h
	$(CCP) $(CPFLAGS) $(LIBFLAGS) $(CPPLIBS) -c ServerAPI.cpp 

Server.o: Server.cpp Server.h
	$(CCP) $(CPFLAGS) $(LIBFLAGS) $(CPPLIBS) $(BOOSTLIB) -c Server.cpp 

Config.o: $(SRCS)
	$(CC) $(CPFLAGS) $(LIBS)-c $(SRCS) 

install: $(TRANSPORT_TEST)
	 chmod 6755 $(TRANSPORT_TEST)
	 sudo ln -s $(CURDIR)/$(TRANSPORT_TEST) /usr/local/bin/$(TRANSPORT_TEST)

clean:
	rm -f count *.o *~
	rm -f $(TRANSPORT_TEST) 
