CC=g++
CFLAGS=-I/usr/include/mysql++/ -I/usr/include/mysql/ -lmysqlpp -lscrypt -fpermissive -w
OUT=./bin/serv

serv: ./crypto/AES.o
	$(CC) -o $(OUT) ./crypto/AES.o crypto/fortuna.cpp serv.cpp $(CFLAGS)

./crypto/AES.o: ./crypto/AES.asm
	nasm -f elf64 -o ./crypto/AES.o ./crypto/AES.asm

no-ni:
	$(CC) -o $(OUT) -DNO_NI crypto/fortuna.cpp serv.cpp $(CFLAGS)
