/*CryptoChat Server
Copyright (C) 2015 Ryan Andersen
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.*/



#ifndef REQUESTMANAGER_H
#define REQUESTMANAGER_H

#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string>
#include <string.h>
#include <sstream>
#include <iostream>
#include <fstream>
#include <assert.h>

#include "ServDB.h"
#include "echo.h"
#include "crypto/base64.h"
#include "crypto/ecdh.h"

#ifdef VERBOSE_OUTPUT
	#define VERBOSE_PRINT(...)	printf(__VA_ARGS__)
#else
	#define VERBOSE_PRINT(...)
#endif

//	SERVER REQUEST FUNCTIONS
//------------------------------------------------------------------------------------------------------------------------------
/*
	Types:
		- Request server's public key																		|	[0]
		- Create new user from public key, encrypted private key, pass salt, iv								|	[1]
		- Request ____'s (encrypted private key) v (pass salt) v (block IV) v (random int) 4 bits of info	|	[2]
		- Login attempt																						|	[3]
			* User signs the random int using shared key by hashing key with random int as salt (scrypt)	|
				- User can't do anything until they have verified by signing this data						|
				- Random int is then changed server side													|
				- This prevents an attacker who captures a login hash from being able to login with it		|
		- Request ____'s public key																			|	[4]
		- Request add-____-to-contact																		|	[5]
		- Create conversation with ____																		|	[6]
		- Add ____ to conversation																			|	[7]
		- Send a message in a conversation																	|	[8]
		- Fetch contacts 																					|	[9]
		- Remove contact																					|	[10]
		- Leave conversation																				|	[11]
		- Fetch user's conversation info																	|	[12]
		- Increase user's last msg eof of conv																|	[13]
		- Fetch missed messages for all convs																|	[14]
		- Update contact nickname																			|	[15]
		- Set user's last msg eof of conv																	|	[16]
*/

struct ClientData
{
	int sock;
	unsigned int userID;
	char* key;
	unsigned int keySize;
};

class RequestManager
{
private:
	ClientData* clients;
	ServDB* servDB;
  	unsigned char* servPublic;
	unsigned char* servPrivate;
	FortunaPRNG* fprng;
	fd_set* master;

public:
  	RequestManager(ClientData* clients, ServDB* servDB, unsigned char* servPublic, unsigned char* servPrivate, FortunaPRNG* fprng, fd_set* master);

	//Requests
	void SendServerPublicKey(ClientData& clientData);
	bool CreateUser(ClientData& clientData, char* sendBuf, char* buf);
	bool SendInfo(ClientData& clientData, char* sendBuf, char* buf);
	bool Login(ClientData& clientData, char* sendBuf, char* buf);
	bool SendUsersPublicKey(ClientData& clientData, char* buf);
	bool AddContact(ClientData& clientData, char* sendBuf, char* buf);
	bool CreateConvWithUser(ClientData& clientData, char* sendBuf, char* buf);
	bool AddUserToConv(ClientData& clientData, char* sendBuf, char* buf);
	bool SendMessage(ClientData& clientData, char* sendBuf, char* buf);
	bool SendContacts(ClientData& clientData, char* sendBuf);
	bool RemoveContact(ClientData& clientData, char* sendBuf, char* buf);
	bool LeaveConv(ClientData& clientData, char* sendBuf, char* buf);
	bool SendUserConvInfo(ClientData& clientData, char* sendBuf);
	bool IncreaseUserEOF(ClientData& clientData, char* sendBuf, char* buf);
	bool SendMissedMsgs(ClientData& clientData);
	bool UpdateNickname(ClientData& clientData, char* sendBuf, char* buf);
	bool SetUserEOF(ClientData& clientData, char* sendBuf, char* buf);

	//	HELPER FUNCTIONS
	//------------------------------------------------------------------------------------------------------------------------------
	void SendError(ClientData& clientData, string errMsg);
  	void FullLogout(ClientData* clientData);
	int recvr(int socket, char* buffer, int length, int flags);
	void SendUserNewConv(ClientData& clientData, uint32_t convID, char* sendBuf, unsigned char type);
	bool GetMissedConvMsgs(uint32_t userID, uint32_t convID, char*& buffer, uint32_t& size);
	void SendSigned(ClientData& clientData, unsigned char type, const void* buffer, unsigned int len);
	void CreateSharedKey(uint32_t userID, char* buffer);
};
#endif
