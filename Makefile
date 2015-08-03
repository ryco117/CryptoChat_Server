CC=g++
CFLAGS=-I/usr/include/mysql++/ -I/usr/include/mysql/ -lmysqlpp -lscrypt -fpermissive -w
OUT=./bin/serv

serv:
	$(CC) -o $(OUT) -DNO_NI crypto/fortuna.cpp serv.cpp $(CFLAGS)
