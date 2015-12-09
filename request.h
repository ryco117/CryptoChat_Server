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

#ifndef REQUEST_H
#define REQUEST_H

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

#include "ServDB.h"
#include "echo.h"
#include "crypto/base64.h"
#include "crypto/ecdh.h"

#define MAX_CLIENTS 32768

struct ClientData {
	int sock;
	unsigned int userID;
	char* key;
	unsigned int keySize;
};

//	REQUEST FUNCTIONS
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
*/

bool SendServerPublicKey(ClientData& clientData, char* servPublic, char* sendBuf);
bool CreateUser(ClientData& clientData, ServDB& servDB, char* sendBuf, char* buf, FortunaPRNG& fprng, fd_set& master);
bool SendInfo(ClientData& clientData, ServDB& servDB, char* sendBuf, char* buf);
bool Login(ClientData*& clientData, unsigned int i, ServDB& servDB, char* sendBuf, char* buf, char* servPrivate, fd_set& master);
bool SendUsersPublicKey(ClientData& clientData, ServDB& servDB, char* sendBuf, char* buf);
bool AddContact(ClientData& clientData, ServDB& servDB, char* sendBuf, char* buf);
bool CreateConvWithUser(ClientData& clientData, ServDB& servDB, char* sendBuf, char* buf);
bool AddUserToConv(ClientData& clientData, ServDB& servDB, char* sendBuf, char* buf);
bool SendMessage(ClientData& clientData, ServDB& servDB, char* sendBuf, char* buf);
bool SendContacts(ClientData& clientData, ServDB& servDB, char* sendBuf);
bool RemoveContact(ClientData& clientData, ServDB& servDB, char* sendBuf, char* buf);
bool LeaveConv(ClientData& clientData, ServDB& servDB, char* sendBuf, char* buf);
bool SendUserConvInfo(ClientData& clientData, ServDB& servDB, char* sendBuf);
bool IncreaseUserEOF(ClientData& clientData, ServDB& servDB, char* sendBuf, char* buf);
bool SendMissedMsgs(ClientData& clientData, ServDB& servDB, char* sendBuf);
bool UpdateNickname(ClientData& clientData, ServDB& servDB, char* sendBuf, char* buf);
bool SetUserEOF(ClientData& clientData, ServDB& servDB, char* sendBuf, char* buf);

//	HELPER FUNCTIONS
//------------------------------------------------------------------------------------------------------------------------------
int recvr(int socket, char* buffer, int length, int flags);
void FullLogout(ClientData* clientData, fd_set* master, ServDB* servDB);
void SendUserNewConv(unsigned int sock, uint32_t userID, uint32_t convID, char* sendBuf, char startByte, ServDB& servDB);
void SendError(std::string errMsg, int client, char* sendBuf);

#endif