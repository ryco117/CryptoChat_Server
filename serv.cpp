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

#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>				//inet_addr
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string>
#include <string.h>
#include <sstream>
#include <iostream>
#include <fstream>

#include "ServDB.cpp"
#include "crypto/base64.h"
#include "crypto/ecdh.h"

#define MAX_CLIENTS 32768
#define LISTEN_PORT 19486
#define MAX_BUFFER_SIZE 16384
#define MAX_SELECT_TIME 1000
#define MAX_RECV_TIME 200000

using namespace std;

						//SET 32 RANDOM BYTES HERE FOR STATIC SERVER PRIVATE KEY OR ZEROES FOR RANDOM PRIVATE KEY EVERY TIME PROCESS RUNS
uint8_t servPrivate[32] = {'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
						   '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00'};

uint8_t	servPublic[32];

bool continueLoop;

bool SeedPRNG(FortunaPRNG& fprng);
void CloseSockets(int* socks, unsigned int size);
int recvr(int socket, char* buffer, int length, int flags);
void FullLogout(unsigned int* sock, unsigned int* userID, fd_set* master, ServDB* servDB);
void SendError(std::string errMsg, unsigned int client, char* sendBuf);

void signal_callback_handler(int signum)
{
	cout << "\rCaught signal " << signum << endl;
	continueLoop = false;
}

int main()
{
	continueLoop = true;
	signal(SIGINT, signal_callback_handler);
	
	FortunaPRNG fprng;
	bool setPrivate = false;
	for(unsigned int i = 0; i < 32; i++)
	{
		if(servPrivate[i] != '\x00')
		{
			setPrivate = true;
			break;
		}
	}
	if(!setPrivate)
	{
		if(!SeedPRNG(fprng))
		{
			cerr << "No private key set and couldn't seed PRNG, aborting!\n";
			return -1;
		}
		fprng.GenerateBlocks(servPrivate, 2);
	}
	curve25519_donna(servPublic, servPrivate, Curve25519Base);
	
	int Serv;														//Create socket for incoming/outgoing stuff
	if((Serv = socket(AF_INET, SOCK_STREAM, 0)) < 0)				//assign Serv to a file descriptor (socket) that uses IP addresses, TCP
	{
		close(Serv);
		perror("Socket");
		return -1;
	}
	struct sockaddr_in socketInfo;
	memset(&socketInfo, 0, sizeof(socketInfo));						//Clear data inside socketInfo to be filled with server stuff
	socketInfo.sin_family = AF_INET;								//Use IP addresses
	socketInfo.sin_addr.s_addr = htonl(INADDR_ANY);					//Allow connection from anybody
	socketInfo.sin_port = htons(LISTEN_PORT);
	
	int optval = 1;
	setsockopt(Serv, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);		//Remove Bind already used error
	if(bind(Serv, (struct sockaddr*)&socketInfo, sizeof(socketInfo)) < 0)	//Bind socketInfo to Serv
	{
		close(Serv);
		perror("Bind");
		return -2;
	}
	
	listen(Serv, 1024);												//Listen for connections on Serv
	cout << "Listening for connections\n";
	
	//		**-FILE DESCRIPTORS-**
	fd_set master;
	FD_ZERO(&master);												//clear data in master
	FD_SET(Serv, &master);											//set master to check file descriptor Serv
	fd_set read_fds = master;										//the read_fds will check the same FDs as master
	
	int* MySocks = new int[MAX_CLIENTS + 1];						//MySocks is a new array of sockets (ints) as long the max connections + 1
	unsigned int* SockToUser = new int[MAX_CLIENTS];				//Store the User ID of the user that is connected to the socket stored at the corresponding index in MySocks (except offset by one)
	MySocks[0] = Serv;												//first socket is the server FD
	for(unsigned int i = 1; i < MAX_CLIENTS + 1; i++)				//assign all the empty ones to -1 (so we know they haven't been assigned a socket)
	{
		MySocks[i] = -1;
		SockToUser[i-1] = 0;
	}
	
	timeval slctWaitTime = {0, MAX_SELECT_TIME};					//assign timeval 1000 microseconds
	timeval recvWaitTime = {0, MAX_RECV_TIME};						//assign timeval 0.2 seconds
	int fdmax = Serv;												//fdmax is the highest file descriptor value to check (because they are just ints)
	
	ServDB servDB("Chat", "localhost", "root", "CHANGE THIS PASSWORD!");	//Connect to MySQL using login info
	string err = servDB.GetError();
	if(!err.empty())
	{
		cerr << err << endl;
		continueLoop = false;
	}
	else
		servDB.Laundry();
	
	char sendBuf[MAX_BUFFER_SIZE];
	char buf[MAX_BUFFER_SIZE];
	while(continueLoop)
	{
		read_fds = master;												//assign read_fds back to the unchanged master
		slctWaitTime = {0, MAX_SELECT_TIME};
		if(select(fdmax+1, &read_fds, NULL, NULL, &slctWaitTime) == -1)	//Check for stuff to read on sockets, up to fdmax+1.. stop check after timeval (50ms)
		{
			CloseSockets(MySocks, MAX_CLIENTS + 1);
			perror("Select");
			break;
		}
		for(unsigned int i = 0; i < MAX_CLIENTS + 1; i++)			//Look through all sockets
		{
			if(MySocks[i] == -1)									//if MySocks[i] == -1 then go just continue the for loop, this part of the array hasn't been assigned a socket
				continue;
			if(FD_ISSET(MySocks[i], &read_fds))						//check read_fds to see if there is unread data in MySocks[i]
			{
				if(i == 0)											//if i = 0, then we know that we are looking at data on the Serv socket... This means a new connection!!
				{
					int newSocket;
					if((newSocket = accept(Serv, NULL, NULL)) < 0)	//assign socket newSocket to the person we are accepting on Serv
					{												//...unless it errors
						perror("Accept");
						continue;
					}
					if(setsockopt(newSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&recvWaitTime, sizeof(recvWaitTime)))
					{
						perror("setsockopt");
						close(newSocket);
						continue;
					}
					
					for(unsigned int j = 1; j < MAX_CLIENTS + 1; j++)//assign newSocket to an unassigned MySocks
					{
						if(MySocks[j] == -1) 						//Not in use
						{
							FD_SET(newSocket, &master); 			//add the newSocket FD to master set
							MySocks[j] = newSocket;
							cout << "Client " << j << " connected at " << newSocket << "\n";
							if(newSocket > fdmax)					//if the new file descriptor is greater than fdmax..
								fdmax = newSocket;					//change fdmax to newSocket
							break;
						}
						if(j == MAX_CLIENTS)
						{
							cout << "Max clients already added\n";
							close(newSocket);
							continue;
						}
					}
				}
				else
				{
					/*HANDLE REQUEST*/
					/*
						Types:
							- Request server's public key																		|	[0]			checked
							- Create new user from public key, encrypted private key, pass salt, iv								|	[1]			checked
							- Request ____'s (encrypted private key) v (pass salt) v (block IV) v (random int) 4 bits of info	|	[2]			checked
							- Login attempt																						|	[3]			checked
								* User signs the random int using shared key by hashing key with random int as salt (scrypt)	|
									- User can't do anything until they have verified by signing this data						|
									- Random int is then changed server side													|
									- This prevents an attacker who captures a login hash from being able to login with it		|
							- Request ____'s public key																			|	[4]			checked
							- Request add-____-to-contact																		|	[5]			checked
							- Create conversation with ____																		|	[6]			checked
							- Add ____ to conversation																			|	[7]			checked
							- Send a message in a conversation																	|	[8]			checked
							- Fetch contacts 																					|	[9]			checked
							- Remove contact																					|	[10]		checked
							- Leave conversation																				|	[11]		checked
							- Fetch user's conversation info																	|	[12]		checked
							- Increase user's last msg eof of conv																|	[13]		checked
							- Fetch missed messages for all convs																|	[14]		checked
							- Update contact nickname																			|	[15]		checked
					*/
					int nbytes = recv(MySocks[i], buf, 1, 0);
					if(nbytes <= 0)
					{
						//got error or connection closed by client
						if(nbytes == 0)
						{
							//connection closed
							cout <<"Client " << i << " disconnected\n";
						}
						else
						{
							perror("Recv");
						}
						FullLogout(&MySocks[i], &SockToUser[i-1], &master, &servDB);
					}
					else
					{
						if(buf[0] == 0)
						{
							//SEND BACK SERVER PUBLIC KEY
							sendBuf[0] = '\x01';									//Can't fail
							memcpy(&sendBuf[1], servPublic, 32);
							send(MySocks[i], sendBuf, 33, 0);
						}
						else if(buf[0] == 1)	//Got to have room for goodness sakes!
						{
							nbytes += recvr(MySocks[i], &buf[1], 32 + 48 + 16 + 16, 0);
							if(nbytes != 1 + 32 + 48 + 16 + 16)
							{
								SendError("Dun f*cked up", MySocks[i], sendBuf);
								continue;
							}
							
							//CREATE USER FROM BASIC INFO	   (public	 private   IV		 salt)
							uint32_t userID = servDB.CreateUser(&buf[1], &buf[33], &buf[81], &buf[97]);
							if(userID == 0)
							{
								SendError(servDB.GetError(), MySocks[i], sendBuf);
							}
							else
							{
								sendBuf[0] = '\x01';
								userID = htonl(userID);
								memcpy(&sendBuf[1], &userID, 4);
								send(MySocks[i], sendBuf, 5, 0);
							}
						}
						else if(buf[0] == 2)
						{
							nbytes += recvr(MySocks[i], &buf[1], 4 + 1, 0);
							if(nbytes != 1 + 4 + 1)
							{
								SendError("Dun f*cked up", MySocks[i], sendBuf);
								continue;
							}
							
							//SEND BACK WHAT THEY REQUESTED FROM MYSQL
							unsigned int returnLength = 1;
							uint32_t userID = ntohl(*((uint32_t*)&buf[1]));
							if(!servDB.UserExists(userID))
							{
								SendError("User does not exist on this server", MySocks[i], sendBuf);
								continue;
							}
							
							sendBuf[0] = '\x01';
							
							if(buf[5] & 8)	
							{
								uint32_t rand = servDB.FetchRandomInt(userID);
								rand = htonl(rand);
								memcpy(&sendBuf[returnLength], &rand, 4);
								returnLength += 4;
							}
							if(buf[5] & 4)	
							{
								char* userSalt = servDB.FetchSalt(userID);
								memcpy(&sendBuf[returnLength], userSalt, 16);
								returnLength += 16;
								delete[] userSalt;
							}
							if(buf[5] & 2)	
							{
								char* userIV = servDB.FetchIV(userID);
								memcpy(&sendBuf[returnLength], userIV, 16);
								returnLength += 16;
								delete[] userIV;
							}
							if(buf[5] & 1)	
							{
								char* userEncPrivKey = servDB.FetchEncPrivateKey(userID);
								if(userEncPrivKey == 0)
								{
									SendError(servDB.GetError(), MySocks[i], sendBuf);
									continue;
								}
								memcpy(&sendBuf[returnLength], userEncPrivKey, 48);
								returnLength += 48;
								delete[] userEncPrivKey;
							}
							send(MySocks[i], sendBuf, returnLength, 0);
						}
						else if(buf[0] == 3)
						{
							nbytes += recvr(MySocks[i], &buf[1], 4 + 32, 0);
							if(nbytes != 1 + 4 + 32)
							{
								SendError("Dun f*cked up", MySocks[i], sendBuf);
								continue;
							}
							
							//VERIFY RANDOM INT SIG AND LOGIN (ASSIGN DATABASE SOCKET VALUE AND SockToUser VALUE)
							uint32_t userID = ntohl(*((uint32_t*)&buf[1]));
							if(!servDB.UserExists(userID))
							{
								if(servDB.GetError().empty())
									SendError("User does not exist on this server", MySocks[i], sendBuf);
								else
									SendError("Server is having difficulties finding this user", MySocks[i], sendBuf);
								continue;
							}
							
							char* userPubKey = servDB.FetchPublicKey(userID);
							if(userPubKey == 0)
							{
								SendError(servDB.GetError(), MySocks[i], sendBuf);
							}
							else
							{
								char* SharedKey = new char[32];
								curve25519_donna(SharedKey, servPrivate, userPubKey);
								delete[] userPubKey;
								
								char* Hash = new char[32];
								uint32_t rand = servDB.FetchRandomInt(userID);
								libscrypt_scrypt(SharedKey, 32, (const char*)&rand, 4, 16384, 8, 1, Hash, 32);		//Use incrementing integer as salt so hash is always different
								
								int cmp = memcmp(&buf[5], Hash, 32);
								memset(Hash, 0, 32);
								memset(SharedKey, 0, 32);
								delete[] Hash;
								delete[] SharedKey;

								if(cmp == 0)
								{
									if(SockToUser[i-1] != 0)
									{
										servDB.LogoutUser(SockToUser[i-1]);
										SockToUser[i-1] = 0;
									}
									
									if(servDB.IsOnline(userID))
									{
										SendError("You are already signed in!!", MySocks[i], sendBuf);
										continue;
									}
									
									sendBuf[0] = '\x01';
									SockToUser[i-1] = userID;
									servDB.LoginUser(userID, (unsigned int)MySocks[i]);
									send(MySocks[i], sendBuf, 1, 0);
								}
								else
								{
									SendError("Login credentials were not correct", MySocks[i], sendBuf);
								}
							}
						}
						else if(buf[0] == 4)
						{
							nbytes += recvr(MySocks[i], &buf[1], 4, 0);
							if(nbytes != 1 + 4)
							{
								SendError("Dun f*cked up", MySocks[i], sendBuf);
								continue;
							}
							
							//SEND BACK REQUESTED USER'S PUBLIC KEY
							uint32_t userID = ntohl(*((uint32_t*)&buf[1]));
							if(!servDB.UserExists(userID))
							{
								SendError("User does not exist on this server", MySocks[i], sendBuf);
								continue;
							}
							
							char* userPubKey = servDB.FetchPublicKey(userID);
							if(userPubKey == 0)
							{
								SendError(servDB.GetError(), MySocks[i], sendBuf);
							}
							else
							{
								sendBuf[0] = '\x01';
								memcpy(&sendBuf[1], userPubKey, 32);
								send(MySocks[i], sendBuf, 33, 0);
								delete[] userPubKey;
							}
						}
						else if(buf[0] == 5)
						{
							nbytes += recvr(MySocks[i], &buf[1], 5, 0);
							if(nbytes != 1 + 4 + 1)
							{
								SendError("Dun f*cked up", MySocks[i], sendBuf);
								continue;
							}
							uint32_t encNickLen = (uint8_t)buf[5];
							if(encNickLen > 32)
							{
								SendError("Impossible request, can't deal, killing you", MySocks[i], sendBuf);
								FullLogout(&MySocks[i], &SockToUser[i-1], &master, &servDB);
								continue;
							}
							
							nbytes += recvr(MySocks[i], &buf[6], encNickLen, 0);
							if(nbytes != 1 + 4 + 1 + encNickLen)
							{
								SendError("Dun f*cked up", MySocks[i], sendBuf);
								continue;
							}
							
							//ADD PERSON TO CONTACTS (NICKNAME OPTIONAL)
							if(SockToUser[i-1] != 0)
							{
								uint32_t contactID = ntohl(*((uint32_t*)&buf[1]));
								if(!servDB.UserExists(contactID))
								{
									SendError("User does not exist on this server", MySocks[i], sendBuf);
									continue;
								}
								
								char* encNickname = (nbytes == 6 + 16 || nbytes == 6 + 32)? &buf[6] : 0;
								bool succeed = servDB.AddUserToContacts(SockToUser[i-1], contactID, encNickname, encNickLen);
								if(!succeed)
								{
									SendError(servDB.GetError(), MySocks[i], sendBuf);
								}
								else
								{
									sendBuf[0] = '\x01';
									send(MySocks[i], sendBuf, 1, 0);
								}
							}
							else
							{
								SendError("Not signed in", MySocks[i], sendBuf);
							}
						}
						else if(buf[0] == 6)
						{
							nbytes += recvr(MySocks[i], &buf[1], 4 + 16 + 48 + 16 + 48, 0);
							if(nbytes != 1 + 4 + 16 + 48 + 16 + 48)
							{
								SendError("Dun f*cked up", MySocks[i], sendBuf);
								continue;
							}
							
							//CREATE CONVERSATION WITH USER (IF USER HAS ADDED BACK)
							if(SockToUser[i-1] != 0)
							{
								uint32_t contactID = ntohl(*((uint32_t*)&buf[1]));
								if(!servDB.UserExists(contactID))
								{
									SendError("User does not exist on this server", MySocks[i], sendBuf);
									continue;
								}
								
								if(servDB.UserAddedContact(contactID, SockToUser[i-1]))
								{
									uint32_t convID = servDB.CreateConversation(SockToUser[i-1], &buf[5], &buf[21]);
									if(convID == 0)
									{
										SendError(servDB.GetError(), MySocks[i], sendBuf);
									}

									bool succeed = servDB.AddUserToConv(convID, contactID, &buf[69], &buf[85]);
									if(!succeed)
									{
										SendError(servDB.GetError(), MySocks[i], sendBuf);
									}
									else
									{
										sendBuf[0] = '\x01';
										convID = htonl(convID);
										memcpy(&sendBuf[1], &convID, 4);
										send(MySocks[i], sendBuf, 5, 0);
									}
								}
								else
								{
									SendError("Contact has not added you back yet", MySocks[i], sendBuf);
								}
							}
							else
							{
								SendError("Not signed in", MySocks[i], sendBuf);
							}
						}
						else if(buf[0] == 7)
						{
							nbytes += recvr(MySocks[i], &buf[1], 4 + 4 + 16 + 48, 0);
							if(nbytes != 1 + 4 + 4 + 16 + 48)
							{
								SendError("Dun f*cked up", MySocks[i], sendBuf);
								continue;
							}
							
							//ADD USER TO CONVERSATION (IF USER HAS ADDED ALL OTHER PARTIES IN CONV, AND EVERYONE HAS ADDED USER)
							if(SockToUser[i-1] != 0)
							{
								uint32_t convID = ntohl(*((uint32_t*)&buf[1]));
								uint32_t contactID = ntohl(*((uint32_t*)&buf[5]));
								if(!servDB.UserExists(contactID))
								{
									SendError("User does not exist on this server", MySocks[i], sendBuf);
									continue;
								}
								
								uint32_t users_num;
								uint32_t* users = servDB.FetchUsersInConv(convID, users_num);
								if(users_num == 0)
								{
									SendError(servDB.GetError(), MySocks[i], sendBuf);
								}

								bool mutualTrust = true;
								for(unsigned int j = 0; j < users_num; j++)
								{
									if(contactID == users[j])
									{
										mutualTrust = false;
										stringstream ss;
										ss << "User " << contactID << " is already a member of conv " << convID;
										err = ss.str();
										break;
									}
									if(!servDB.UserAddedContact(contactID, users[j]))
									{
										mutualTrust = false;
										stringstream ss;
										ss << "User " << contactID << " hasn't added user " << users[j];
										err = ss.str();
										break;
									}
									if(!servDB.UserAddedContact(users[j], contactID))
									{
										mutualTrust = false;
										stringstream ss;
										ss << "User " << users[j] << " hasn't added user " << contactID;
										err = ss.str();
										break;
									}
								}
								
								if(mutualTrust)
								{
									bool succeed = servDB.AddUserToConv(convID, contactID, &buf[9], &buf[25]);
									if(!succeed)
									{
										SendError(servDB.GetError(), MySocks[i], sendBuf);
									}
									else
									{
										sendBuf[0] = '\x01';
										send(MySocks[i], sendBuf, 1, 0);
									}
								}
								else
								{
									SendError(err, MySocks[i], sendBuf);
								}
							}
							else
							{
								SendError("Not signed in", MySocks[i], sendBuf);
							}
						}
						else if(buf[0] == 8)
						{
							nbytes += recvr(MySocks[i], &buf[1], 8, 0);
							if(nbytes != 1 + 8)
							{
								SendError("Dun f*cked up", MySocks[i], sendBuf);
								continue;
							}
							uint32_t msgLen = ntohl(*((uint32_t*)&buf[5]));
							if(msgLen > 4096)
							{
								//WON'T NEED TO FULL LOGOUT IF CAN MARK ENTIRE SOCKET RECV QUEUE AS READ!
								SendError("Dumb request, can't deal, killing you", MySocks[i], sendBuf);
								FullLogout(&MySocks[i], &SockToUser[i-1], &master, &servDB);
								continue;
							}
							
							nbytes += recvr(MySocks[i], &buf[9], 16 + msgLen, 0);
							if(nbytes != 1 + 8 + 16 + msgLen)
							{
								SendError("Dun f*cked up", MySocks[i], sendBuf);
								continue;
							}
							
							//BROADCAST MESSAGE TO ALL USERS OF CONVERSATION THAT ARE ONLINE, INCREASE MESSAGE COUNT OF CONV
							if(SockToUser[i-1] != 0)
							{
								uint32_t convID = ntohl(*((uint32_t*)&buf[1]));
								uint32_t senderID = SockToUser[i-1];
								uint32_t senderNet = htonl(senderID);
								sendBuf[0] = '\xFF';
								memcpy(&sendBuf[1], &buf[1], 8);						//Copy convID and msgLen to broadcast msg
								memcpy(&sendBuf[9], &senderNet, 4);						//Copy senderID 
								memcpy(&sendBuf[13], &buf[9], 16 + msgLen);				//Copy IV + msg
								
								stringstream ss;
								ss << convID;
								ofstream convFile(ss.str().c_str(), ios::out | ios::app | ios::binary);
								if(convFile.is_open())
								{
									convFile.write("\xFF", 1);
									convFile.write(&sendBuf[5], 4 + 4 + 16 + msgLen);
									convFile.close();
								}
								else
								{
									cerr << "Couldn't open conv " << convID << " file\n";
									SendError("Message not saved :(", MySocks[i], sendBuf);
									continue;
								}
								
								uint32_t n = 0;
								uint32_t* users = servDB.FetchUsersInConv(convID, n);
								if(n == 0)
									cerr << servDB.GetError() << "\n";
								
								for(unsigned int j = 0; j < n; j++)
								{
									if(servDB.IsOnline(users[j]))
									{
										unsigned int sock = servDB.FetchSocket(users[j]);
										sock = send(sock, sendBuf, 1 + 4 + 4 + 4 + 16 + msgLen, 0);
									}
								}
								if(!servDB.IncreaseConvEOF(convID, 1 + 4 + 4 + 16 + msgLen))
									cerr << servDB.GetError() << "\n";
								
								delete[] users;
							}
							else
							{
								SendError("Not signed in", MySocks[i], sendBuf);
							}
						}
						else if(buf[0] == 9)
						{
							//SEND ALL CONTACTS AND THEIR ENCRYPTED NICKNAMES (IF NOT NULL)
							if(SockToUser[i-1] != 0)
							{
								uint32_t size;
								char* contacts = servDB.FetchContacts(SockToUser[i-1], size);
								if(size == 0)
								{
									SendError(servDB.GetError(), MySocks[i], sendBuf);
								}
								else
								{
									char* dynamicSendBuf = new char[1 + 4 + size];
									dynamicSendBuf[0] = '\x01';
									uint32_t netSize = htonl(size);
									memcpy(&dynamicSendBuf[1], &netSize, 4);
									memcpy(&dynamicSendBuf[5], contacts, size);
									delete[] contacts;
									send(MySocks[i], dynamicSendBuf, 1 + 4 + size, 0);
								}
							}
							else
							{
								SendError("Not signed in", MySocks[i], sendBuf);
							}
						}
						else if(buf[0] == 10)
						{
							nbytes += recvr(MySocks[i], &buf[1], 4, 0);
							if(nbytes != 1 + 4)
							{
								SendError("Dun f*cked up", MySocks[i], sendBuf);
								continue;
							}
							
							//REMOVE USER FROM CONTACTS
							if(SockToUser[i-1] != 0)
							{
								uint32_t contactID = ntohl(*((uint32_t*)&buf[1]));
								bool succeed = servDB.RemoveContact(SockToUser[i-1], contactID);
								if(!succeed)
								{
									SendError(servDB.GetError(), MySocks[i], sendBuf);
								}
								else
								{
									sendBuf[0] = '\x01';
									send(MySocks[i], sendBuf, 1, 0);
								}
							}
							else
							{
								SendError("Not signed in", MySocks[i], sendBuf);
							}
						}
						else if(buf[0] == 11)
						{
							nbytes += recvr(MySocks[i], &buf[1], 4, 0);
							if(nbytes != 1 + 4)
							{
								SendError("Dun f*cked up", MySocks[i], sendBuf);
								continue;
							}
							
							//LEAVE A CONVERSATION
							if(SockToUser[i-1] != 0)
							{
								uint32_t convID = ntohl(*((uint32_t*)&buf[1]));
								bool succeed = servDB.LeaveConv(convID, SockToUser[i-1]);
								if(!succeed)
								{
									SendError(servDB.GetError(), MySocks[i], sendBuf);
								}
								else
								{
									sendBuf[0] = '\x01';
									send(MySocks[i], sendBuf, 1, 0);
								}
							}
							else
							{
								SendError("Not signed in", MySocks[i], sendBuf);
							}
						}
						else if(buf[0] == 12)
						{
							//SEND BACK FORMATTED CONVS LIST WITH DETAILS
							if(SockToUser[i-1] != 0)
							{
								uint32_t convs_num;
								uint32_t* convs = servDB.FetchConvs(SockToUser[i-1], convs_num);
								if(convs_num == 0)
								{
									SendError(servDB.GetError(), MySocks[i], sendBuf);
									continue;
								}
								
								sendBuf[0] = '\x01';
								uint32_t size = 5;
								for(unsigned int j = 0; j < convs_num; j++)
								{
									uint32_t conv_net = htonl(convs[j]);
									memcpy(&sendBuf[size], &conv_net, 4);
									size += 4;
									
									uint32_t init_net = htonl((uint32_t)servDB.FetchInitiator(convs[j]));
									memcpy(&sendBuf[size], &init_net, 4);
									size += 4;
									
									char* iv = servDB.FetchConvIV(convs[j], SockToUser[i-1]);
									if(iv == 0)
									{
										SendError(servDB.GetError(), MySocks[i], sendBuf);
										size = 0;
										break;
									}
									else
									{
										memcpy(&sendBuf[size], iv, 16);
										size += 16;
										delete[] iv;
									}
									
									char* encSymKey = servDB.FetchSymKey(convs[j], SockToUser[i-1]);
									if(encSymKey == 0)
									{
										SendError(servDB.GetError(), MySocks[i], sendBuf);
										size = 0;
										break;
									}
									else
									{
										memcpy(&sendBuf[size], encSymKey, 48);
										size += 48;
										delete[] encSymKey;
									}
									
									uint32_t users_num;
									uint32_t* users = servDB.FetchUsersInConv(convs[j], users_num);
									uint32_t users_num_net = htonl(users_num);
									memcpy(&sendBuf[size], &users_num_net, 4);
									size += 4;
									
									for(unsigned int k = 0; k < users_num; k++)
									{
										uint32_t user_net = htonl(users[k]);
										memcpy(&sendBuf[size], &user_net, 4);
										size += 4;
									}

									delete[] users;
								}
								delete[] convs;
								if(size == 0)
									continue;

								uint32_t size_net = htonl(size - 5);			//We want the size of the content, which doesn't include success byte and the length indicator itself
								memcpy(&sendBuf[1], &size_net, 4);
								send(MySocks[i], sendBuf, size, 0);
							}
							else
							{
								SendError("Not signed in", MySocks[i], sendBuf);
							}
						}
						else if(buf[0] == 13)
						{
							nbytes += recvr(MySocks[i], &buf[1], 4 + 4, 0);
							if(nbytes != 1 + 4 + 4)
							{
								SendError("Dun f*cked up", MySocks[i], sendBuf);
								continue;
							}
							
							//INCREASE LAST KNOWN EOF FOR USER IN CONV
							if(SockToUser[i-1] != 0)
							{
								uint32_t convID = ntohl(*((uint32_t*)&buf[1]));
								uint32_t increase = ntohl(*((uint32_t*)&buf[5]));
								if(servDB.IncUserConvEOF(SockToUser[i-1], convID, increase))
									send(MySocks[i], "\x0D", 1, 0);
								else
									SendError(servDB.GetError(), MySocks[i], sendBuf);
							}
							else
							{
								SendError("Not signed in", MySocks[i], sendBuf);
							}
						}
						else if(buf[0] == 14)
						{
							//SEND BACK ALL MISSED MESSAGES
							if(SockToUser[i-1] != 0)
							{
								uint32_t convs_num;
								uint32_t* convs = servDB.FetchConvs(SockToUser[i-1], convs_num);
								uint32_t size = 0;
								for(unsigned int j = 0; j < convs_num; j++)
								{
									unsigned int diff = servDB.FetchConvUserDif(convs[j], SockToUser[i-1]);
									while(diff > 0)
									{
										stringstream ss;
										ss << convs[j];
										ifstream convFile(ss.str().c_str(), ios::in | ios::binary);
										if(convFile.is_open())
										{
											uint32_t conv_net = htonl(convs[j]);
											convFile.seekg(servDB.FetchConvEOF(convs[j]) - diff, convFile.beg);
											convFile.read(&sendBuf[size + 5], 1);
											if(sendBuf[size + 5] == '\xFF')
											{
												memcpy(&sendBuf[size + 6], &conv_net, 4);
												convFile.read(&sendBuf[size + 10], 4 + 4 + 16);
												uint32_t msgLen = ntohl(*((uint32_t*)&sendBuf[size + 10]));
												convFile.read(&sendBuf[size + 34], msgLen);
												size += 1 + 4 + 4 + 4 + 16 + msgLen;
												diff -= 1 + 4 + 4 + 16 + msgLen;
											}
											convFile.close();
										}
										else
										{
											cerr << "Couldn't open conv " << convs[j] << " file\n";
											SendError("Internal error accessing messages", MySocks[i], sendBuf);
											continue;
										}
									}
								}
								sendBuf[0] = '\x01';
								uint32_t size_net = htonl(size);
								memcpy(&sendBuf[1], &size_net, 4);
								send(MySocks[i], sendBuf, size + 5, 0);
							}
							else
							{
								SendError("Not signed in", MySocks[i], sendBuf);
							}
						}
						else if(buf[0] == 15)
						{
							nbytes += recvr(MySocks[i], &buf[1], 4 + 1, 0);
							if(nbytes != 1 + 4 + 1)
							{
								SendError("Dun f*cked up", MySocks[i], sendBuf);
								continue;
							}
							
							//UPDATE CONTACT'S NICKNAME
							if(SockToUser[i-1] != 0)
							{
								uint32_t contactID = ntohl(*((uint32_t*)&buf[1]));
								if(servDB.UserAddedContact(SockToUser[i-1], contactID))
								{
									uint8_t encNickLen = buf[5];
									nbytes = recvr(MySocks[i], &buf[6], encNickLen, 0);
									if(nbytes != encNickLen)
									{
										SendError("Didn't receive enough bytes for nickname", MySocks[i], sendBuf);
										continue;
									}
									if(servDB.UpdateContact(SockToUser[i-1], contactID, &buf[6], encNickLen))
										send(MySocks[i], "\x01", 1, 0);
									else
										SendError(servDB.GetError(), MySocks[i], sendBuf);
								}
								else
								{
									SendError("User ID not added", MySocks[i], sendBuf);
								}
							}
							else
							{
								SendError("Not signed in", MySocks[i], sendBuf);
							}
						}
						else					//Dafuq?!?!?!
						{
							SendError("Dun f*cked up", MySocks[i], sendBuf);
						}
					}
				}
			}
		}
	}
	
	CloseSockets(MySocks, MAX_CLIENTS + 1);
	servDB.Laundry();
	FD_ZERO(&master);
	FD_ZERO(&read_fds);
	cout << "Clean close\n";
	return 0;
}

bool SeedPRNG(FortunaPRNG& fprng)
{
	//Properly Seed
	uint32_t* seed = new uint32_t[20];
	FILE* random;
	random = fopen ("/dev/urandom", "r");						//Unix provides it, why not use it
	if(random == NULL)
	{
		fprintf(stderr, "Cannot open /dev/urandom!\n");			//THIS IS BAD!!!!
		delete[] seed;
		return false;
	}
	for(int i = 0; i < 20; i++)
	{
		fread(&seed[i], sizeof(uint32_t), 1, random);
		srand(seed[i]); 		//seed the default random number generator
	}
	fclose(random);
	fprng.Seed((unsigned char*)seed, sizeof(uint32_t) * 20);
	memset(seed, 0, sizeof(uint32_t) * 20);
	delete[] seed;
	return true;
}

void CloseSockets(int* socks, unsigned int size)
{
	for(unsigned int i = 0; i < size; i++)
	{
		if(socks[i] != -1)
		{
			close(socks[i]);
			socks[i] = -1;
		}
	}
}

int recvr(int socket, char* buffer, int length, int flags)
{
	int i = 0;
	while(i < length)
	{
		int n = recv(socket, &buffer[i], length-i, flags);
		if(n <= 0)
			return n;
		i += n;
	}
	return i;
}

void FullLogout(unsigned int* sock, unsigned int* userID, fd_set* master, ServDB* servDB)
{
	shutdown(*sock, SHUT_WR);
	close(*sock);										//bye!
	FD_CLR(*sock, master);
	*sock = -1;
	if(*userID != 0)									//Was logged in
	{
		servDB->LogoutUser(*userID);
		*userID = 0;									//Remove the socket reference
	}
}

void SendError(std::string errMsg, unsigned int client, char* sendBuf)
{
	sendBuf[0] = '\0';									//Failed
	uint32_t l = htonl((uint32_t)(errMsg.size() + 1));
	memcpy(&sendBuf[1], &l, 4);
	memcpy(&sendBuf[5], errMsg.c_str(), errMsg.size());
	sendBuf[errMsg.size() + 5] = '\0';
	send(client, sendBuf, errMsg.size() + 6, 0);
}