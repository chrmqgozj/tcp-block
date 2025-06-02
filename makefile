LDLIBS += -lpcap -lnet

all: tcp-block

tcp-block: tcp-block.cpp

clean:
	rm -f main *.o
