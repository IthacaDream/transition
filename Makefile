CC = g++

OBJ = transition.o md5.o config.o

INC = -I./ -I/usr/local/include/

LIB = -L./ -L/usr/local/lib/  -lccn -lcrypto -llog4cpp -lpthread

CFLAGS = -g $(INC) -fpermissive -DMLOG
#CFLAGS = -g $(INC) -fpermissive

#%.o : %.c
#	gcc -std=c99 $(CFLAGS) -c $< -o $@

%.o : %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

transition: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LIB) 

clean:
	rm -rf *.o transition
	rm -rf core core.*
