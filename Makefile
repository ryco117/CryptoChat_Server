CXXC=g++
CC=gcc
CFLAGS=-I/usr/include/mysql++/ -I/usr/include/mysql/ -L./crypto/ -lmysqlpp -lscrypt -O2
OUT=./bin/serv
OBJECTS-BASE=crypto/base64.o crypto/curve25519-donna.o crypto/ecdh.o crypto/fortuna.o
OBJECTS-NI=crypto/AES.o ./crypto/AES-NI.o $(OBJECTS-BASE)
OBJECTS-NO-NI=crypto/AES-NO-NI.o $(OBJECTS-BASE)

serv: crypto/libcryptochat.a
	$(CXXC) -o $(OUT) echo.cpp ServDB.cpp request.cpp serv.cpp $(CFLAGS) -lcryptochat

no-ni: crypto/libcryptochat-no-ni.a
	$(CXXC) -o $(OUT) echo.cpp ServDB.cpp request.cpp serv.cpp $(CFLAGS) -lcryptochat-no-ni

clean:
	rm ./crypto/*.o
	rm ./crypto/*.a
	rm $(OUT)

./crypto/libcryptochat.a: $(OBJECTS-NI)
	ar rvs ./crypto/libcryptochat.a ./crypto/AES.o ./crypto/AES-NI.o ./crypto/base64.o ./crypto/curve25519-donna.o ./crypto/ecdh.o ./crypto/fortuna.o

./crypto/libcryptochat-no-ni.a: $(OBJECTS-NO-NI)
	ar rvs ./crypto/libcryptochat-no-ni.a ./crypto/AES-NO-NI.o ./crypto/base64.o ./crypto/curve25519-donna.o ./crypto/ecdh.o ./crypto/fortuna.o

./crypto/AES-NI.o: ./crypto/AES-NI.asm
	nasm -f elf64 -o ./crypto/AES-NI.o ./crypto/AES-NI.asm

./crypto/AES.o: ./crypto/AES.cpp
	$(CXXC) -c -o ./crypto/AES.o ./crypto/AES.cpp

./crypto/AES-NO-NI.o: ./crypto/AES.cpp
	$(CXXC) -c -o ./crypto/AES-NO-NI.o -O2 ./crypto/AES.cpp -DNO_NI

./crypto/base64.o: ./crypto/base64.cpp
	$(CXXC) -c -o ./crypto/base64.o -O2 ./crypto/base64.cpp

./crypto/curve25519-donna.o: ./crypto/curve25519-donna.c
	$(CC) -c -o ./crypto/curve25519-donna.o -O2 ./crypto/curve25519-donna.c

./crypto/ecdh.o: ./crypto/ecdh.cpp
	$(CXXC) -c -o ./crypto/ecdh.o -O2 ./crypto/ecdh.cpp

./crypto/fortuna.o: ./crypto/fortuna.cpp
	$(CXXC) -c -o ./crypto/fortuna.o -O2 ./crypto/fortuna.cpp
