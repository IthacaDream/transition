CC = g++

INC = -I./ -I/usr/local/include/

LIB = -L./ -L/usr/local/lib/  -lccn -lcrypto

CFLAGS = -g $(INC) -fpermissive

.PYONY: all
.PYONY: clean

all: demo demo_c0 demo_c1

demo: demo.cc
	$(CC) $(CFLAGS) -o $@ demo.cc $(LIB) -lpthread
demo_c0: demo_c0.cc
	$(CC) $(CFLAGS) -o $@ demo_c0.cc $(LIB)
demo_c1: demo_c1.cc
	$(CC) $(CFLAGS) -o $@ demo_c1.cc $(LIB)



clean:
	rm -rf *.o demo demo_c0 demo_c1


