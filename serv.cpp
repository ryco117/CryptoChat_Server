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

#define MAX_CLIENTS 32768
#define LISTEN_PORT 19486
#define MAX_BUFFER_SIZE 16384
#define MAX_SELECT_TIME 10000
#define MAX_RECV_TIME 200000

#include "request.h"

using namespace std;

						  //SET 32 RANDOM BYTES HERE FOR STATIC SERVER PRIVATE KEY OR ZEROES FOR RANDOM PRIVATE KEY EVERY TIME PROCESS RUNS
uint8_t servPrivate[32] = {'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
						   '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00'};
uint8_t	servPublic[32];
bool continueLoop;

bool SeedPRNG(FortunaPRNG& fprng);
void CloseSockets(ClientData* socks, unsigned int size);
/*int recvr(int socket, char* buffer, int length, int flags);
void FullLogout(ClientData* clientData, fd_set* master, ServDB* servDB);
void SendUserNewConv(unsigned int sock, uint32_t userID, uint32_t convID, char* sendBuf, char startByte, ServDB& servDB);
void SendError(std::string errMsg, int client, char* sendBuf);*/

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
	AES crypt;
	if(!SeedPRNG(fprng))
	{
		cerr << "Couldn't seed PRNG, aborting!\n";
		return -1;
	}
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
		fprng.GenerateBlocks(servPrivate, 2);
	
	curve25519_donna(servPublic, servPrivate, Curve25519Base);
	
	int Serv;														//Create socket for incoming/outgoing stuff
	if((Serv = socket(AF_INET, SOCK_STREAM, 0)) < 0)				//assign Serv to a file descriptor (socket) that uses IP addresses, TCP
	{
		close(Serv);
		perror("Socket");
		return -2;
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
		return -3;
	}
	
	listen(Serv, 1024);												//Listen for connections on Serv
	cout << "Listening for connections\n";
	
	//		**-FILE DESCRIPTORS-**
	fd_set master;
	FD_ZERO(&master);												//clear data in master
	FD_SET(Serv, &master);											//set master to check file descriptor Serv
	fd_set read_fds = master;										//the read_fds will check the same FDs as master
	
	ClientData* clientData = new ClientData[MAX_CLIENTS + 1];					//Struct to hold relevant client data for quick access
	clientData[0].sock = Serv;										//first socket is the server FD
	for(unsigned int i = 1; i < MAX_CLIENTS + 1; i++)				//assign all the empty ones to -1 (so we know they haven't been assigned a socket)
	{
		clientData[i].sock = -1;
		clientData[i].userID = 0;
		clientData[i].key = 0;
		clientData[i].keySize = 0;
	}
	
	timeval slctWaitTime = {0, MAX_SELECT_TIME};					//assign timeval 10000 microseconds
	timeval recvWaitTime = {0, MAX_RECV_TIME};						//assign timeval 0.2 seconds
	int fdmax = Serv;												//fdmax is the highest file descriptor value to check (because they are just ints)
	
	char* db = "Chat";
	char* addr = "localhost";
	char* user = "root";
	char* passwd = new char[128];
	memset(passwd, 0, 128);
	cout << "MySQL password: ";
	SetEcho(false);
	if(fgets(passwd, 127, stdin) == 0)
	{
		cout << "\nCouldn't read password\n";
		SetEcho(true);
		return -4;
	}
	SetEcho(true);
	printf("\n");
	passwd[strlen(passwd)-1] = 0;		//Because fgets includes '\n'
	ServDB servDB(db, addr, user, passwd);	//Connect to MySQL using login info and PASSWORD_OF_MYSQL_SERVER
	string err = servDB.GetError();
	if(!err.empty())
	{
		cerr << err << endl;
		continueLoop = false;
	}
	else
	{
		servDB.Laundry();				//Because it cleans the socks :D (needed in case of hardclose)
	}
	memset(passwd, 0, strlen(passwd));
	
	char sendBuf[MAX_BUFFER_SIZE];
	char buf[MAX_BUFFER_SIZE];
	while(continueLoop)
	{
		read_fds = master;												//assign read_fds back to the unchanged master
		slctWaitTime = {0, MAX_SELECT_TIME};
		if(select(fdmax+1, &read_fds, NULL, NULL, &slctWaitTime) == -1)	//Check for stuff to read on sockets, up to fdmax+1.. stop check after timeval (50ms)
		{
			CloseSockets(clientData, MAX_CLIENTS + 1);
			perror("Select");
			break;
		}
		for(unsigned int i = 0; i < MAX_CLIENTS + 1; i++)			//Look through all sockets
		{
			if(clientData[i].sock == -1)							//if clientData[i].sock == -1 then continue the for loop, this part of the array hasn't been assigned a socket
				continue;
			if(FD_ISSET(clientData[i].sock, &read_fds))						//check read_fds to see if there is unread data in clientData[i].sock
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
					
					for(unsigned int j = 1; j < MAX_CLIENTS + 1; j++)//assign newSocket to an unassigned ClientData element
					{
						if(clientData[j].sock == -1) 						//Not in use
						{
							FD_SET(newSocket, &master); 			//add the newSocket FD to master set
							clientData[j].sock = newSocket;
							if(clientData[j].key != 0)
							{
								memset(clientData[j].key, 0, clientData[j].keySize);
								delete[] clientData[j].key;
								clientData[j].key = 0;
							}
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
					int nbytes = recv(clientData[i].sock, buf, 1, 0);
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
						FullLogout(&clientData[i], &master, &servDB);
					}
					else
					{
						switch(buf[0])
						{
							case 0:
							{
								SendServerPublicKey(clientData[i], servPublic, sendBuf);
								break;
							}
							case 1:
							{
								CreateUser(clientData[i], servDB, sendBuf, buf, fprng, master);
								break;
							}
							case 2:
							{
								SendInfo(clientData[i], servDB, sendBuf, buf);
								break;
							}
							case 3:
							{
								Login(clientData, i, servDB, sendBuf, buf, servPrivate, master);
								break;
							}
							case 4:
							{
								SendUsersPublicKey(clientData[i], servDB, sendBuf, buf);
								break;
							}
							case 5:
							{
								AddContact(clientData[i], servDB, sendBuf, buf);
								break;
							}
							case 6:
							{
								CreateConvWithUser(clientData[i], servDB, sendBuf, buf);
								break;
							}
							case 7:
							{
								AddUserToConv(clientData[i], servDB, sendBuf, buf);
								break;
							}
							case 8:
							{
								SendMessage(clientData[i], servDB, sendBuf, buf);
								break;
							}
							case 9:
							{
								SendContacts(clientData[i], servDB, sendBuf);
								break;
							}
							case 10:
							{
								RemoveContact(clientData[i], servDB, sendBuf, buf);
								break;
							}
							case 11:
							{
								LeaveConv(clientData[i], servDB, sendBuf, buf);
								break;
							}
							case 12:
							{
								SendUserConvInfo(clientData[i], servDB, sendBuf);
								break;
							}
							case 13:
							{
								IncreaseUserEOF(clientData[i], servDB, sendBuf, buf);
								break;
							}
							case 14:
							{
								SendMissedMsgs(clientData[i], servDB, sendBuf);
								break;
							}
							case 15:
							{
								UpdateNickname(clientData[i], servDB, sendBuf, buf);
								break;
							}
							default:					//Unknown request type
							{
								SendError("Invalid request", clientData[i].sock, sendBuf);
								break;
							}
						}
					}
				}
			}
		}
	}
	
	CloseSockets(clientData, MAX_CLIENTS + 1);
	servDB.Laundry();
	FD_ZERO(&master);
	FD_ZERO(&read_fds);
	delete[] clientData;
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

void CloseSockets(ClientData* clientData, unsigned int size)
{
	for(unsigned int i = 0; i < size; i++)
	{
		if(clientData[i].sock != -1)
		{
			close(clientData[i].sock);
			clientData[i].sock = -1;
			if(clientData[i].key != 0)
			{
				memset(clientData[i].key, 0, clientData[i].keySize);
				delete[] clientData[i].key;
				clientData[i].key = 0;
				clientData[i].keySize = 0;
			}
		}
	}
}