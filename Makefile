CXXC=g++
CC=gcc
CFLAGS=-std=c++11 -I/usr/include/mysql++/ -I/usr/include/mysql/ -I/usr/local/include/ -L./usr/local/lib/ -lmysqlpp -lscrypt -Wunused-variable -O2 -DVERBOSE_OUTPUT
OUT=./bin/serv

serv:
	$(CXXC) -o $(OUT) echo.cpp ServDB.cpp RequestManager.cpp serv.cpp $(CFLAGS) -lcryptolibrary

no-ni:
	$(CXXC) -o $(OUT) echo.cpp ServDB.cpp RequestManager.cpp serv.cpp $(CFLAGS) -lcryptolibrary-no-ni

clean:
	rm ./crypto/*.o
	rm ./crypto/*.a
	rm $(OUT)
