#include "request.h"

//	REQUEST FUNCTIONS
//------------------------------------------------------------------------------------------------------------------------------
bool SendServerPublicKey(ClientData& clientData, char* servPublic, char* sendBuf)
{
	//SEND BACK SERVER PUBLIC KEY
	sendBuf[0] = '\x01';									//Can't fail
	memcpy(&sendBuf[1], servPublic, 32);
	send(clientData.sock, sendBuf, 33, 0);
	return true;
}

bool CreateUser(ClientData& clientData, ServDB& servDB, char* sendBuf, char* buf, FortunaPRNG& fprng, fd_set& master)
{
	//16 BIT TEST!!
	//----------------------------------------------------------------------------------
	if(clientData.key == 0)
	{
		buf[1] = '\x10';
		clientData.key = new unsigned char[32];
		clientData.keySize = 32;

		fprng.GenerateBlocks(clientData.key, 1);			//Hash
		fprng.GenerateBlocks(&clientData.key[16], 1);	//Salt

		memcpy(&buf[2], clientData.key, 32);
		send(clientData.sock, &buf[1], 33, 0);
		return false;
	}

	unsigned int nbytes = recvr(clientData.sock, &buf[1], 16, 0);
	if(nbytes != 16)
	{
		SendError("Invalid request", clientData.sock, sendBuf);
		memset(clientData.key, 0, clientData.keySize);
		delete[] clientData.key;
		clientData.key = 0;
		clientData.keySize = 0;
		return false;
	}

	unsigned char* theirHash = new unsigned char[16];
	libscrypt_scrypt(&buf[1], 16, &clientData.key[16], 16, 128, 3, 1, theirHash, 16);
	if(memcmp(theirHash, clientData.key, 2) != 0)
	{
		SendError("Hash test failed, closing connection", clientData.sock, sendBuf);
		FullLogout(&clientData, &master, &servDB);
		delete[] theirHash;
		return false;
	}
	delete[] theirHash;
	delete[] clientData.key;
	clientData.key = 0;
	clientData.keySize = 0;

	//Passed the hash test, now actually do that thing they wanted...
	//----------------------------------------------------------------------------------
	nbytes += recvr(clientData.sock, &buf[1], 32 + 48 + 16 + 16, 0);
	if(nbytes != 16 + 32 + 48 + 16 + 16)
	{
		SendError("Invalid request", clientData.sock, sendBuf);
		return false;
	}

	//CREATE USER FROM BASIC INFO	   (public	 private   IV		 salt)
	uint32_t userID = servDB.CreateUser(&buf[1], &buf[33], &buf[81], &buf[97]);
	if(userID == 0)
	{
		SendError(servDB.GetError(), clientData.sock, sendBuf);
		return false;
	}
	else
	{
		sendBuf[0] = '\x01';
		userID = htonl(userID);
		memcpy(&sendBuf[1], &userID, 4);
		send(clientData.sock, sendBuf, 5, 0);
	}
	return true;
}

bool SendInfo(ClientData& clientData, ServDB& servDB, char* sendBuf, char* buf)
{
	unsigned int nbytes = recvr(clientData.sock, &buf[1], 4 + 1, 0);
	if(nbytes != 4 + 1)
	{
		SendError("Invalid request", clientData.sock, sendBuf);
		return false;
	}

	//SEND BACK WHAT THEY REQUESTED FROM MYSQL
	unsigned int returnLength = 1;
	uint32_t userID = ntohl(*((uint32_t*)&buf[1]));
	if(!servDB.UserExists(userID))
	{
		SendError("User does not exist on this server", clientData.sock, sendBuf);
		return false;
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
			SendError(servDB.GetError(), clientData.sock, sendBuf);
			return false;
		}
		memcpy(&sendBuf[returnLength], userEncPrivKey, 48);
		returnLength += 48;
		delete[] userEncPrivKey;
	}
	send(clientData.sock, sendBuf, returnLength, 0);
	return true;
}

bool Login(ClientData*& clientData, unsigned int i, ServDB& servDB, char* sendBuf, char* buf, char* servPrivate, fd_set& master)
{
	unsigned int nbytes = recvr(clientData[i].sock, &buf[1], 4 + 32, 0);
	if(nbytes != 4 + 32)
	{
		SendError("Invalid request", clientData[i].sock, sendBuf);
		return false;
	}

	//VERIFY RANDOM INT SIG AND LOGIN (ASSIGN DATABASE SOCKET VALUE AND SockToUser VALUE)
	uint32_t userID = ntohl(*((uint32_t*)&buf[1]));
	if(!servDB.UserExists(userID))
	{
		if(servDB.GetError().empty())
			SendError("User does not exist on this server", clientData[i].sock, sendBuf);
		else
		{
			SendError("Server is having difficulties finding this user", clientData[i].sock, sendBuf);
			cout << servDB.GetError() << endl;
		}
		return false;
	}

	char* userPubKey = servDB.FetchPublicKey(userID);
	if(userPubKey == 0)
	{
		SendError(servDB.GetError(), clientData[i].sock, sendBuf);
		return false;
	}
	else
	{
		if(clientData[i].key != 0)
		{
			memset(clientData[i].key, 0, clientData[i].keySize);
			delete[] clientData[i].key;
		}

		clientData[i].key = new char[32];
		clientData[i].keySize = 32;
		curve25519_donna(clientData[i].key, servPrivate, userPubKey);
		delete[] userPubKey;

		char* Hash = new char[32];
		uint32_t rand = servDB.FetchRandomInt(userID);
		libscrypt_scrypt(clientData[i].key, 32, (const char*)&rand, 4, 16384, 8, 1, Hash, 32);		//Use incrementing integer as salt so hash is always different

		int cmp = memcmp(&buf[5], Hash, 32);
		memset(Hash, 0, 32);
		delete[] Hash;

		if(cmp == 0)
		{
			if(clientData[i].userID != 0)
			{
				servDB.LogoutUser(clientData[i].userID);
				clientData[i].userID = 0;
			}

			if(servDB.IsOnline(userID))
			{
				unsigned int userIndex = 0;
				for(unsigned int j = 1; j <= MAX_CLIENTS; j++)
				{
					if(clientData[j].userID == userID)
					{
						userIndex = j;
						break;
					}
				}
				if(userIndex > 0)
				{
					FullLogout(&clientData[userIndex], &master, &servDB);
					//SendError("You are already signed in!!", clientData[i].sock, sendBuf);
					if(clientData[userIndex].key != 0)
					{
						memset(clientData[userIndex].key, 0, clientData[userIndex].keySize);
						delete[] clientData[userIndex].key;
						clientData[userIndex].key = 0;
					}
				}
			}

			sendBuf[0] = '\x01';
			clientData[i].userID = userID;
			servDB.LoginUser(userID, (unsigned int)clientData[i].sock);
			send(clientData[i].sock, sendBuf, 1, 0);
		}
		else
		{
			SendError("Login credentials were not correct", clientData[i].sock, sendBuf);
			memset(clientData[i].key, 0, clientData[i].keySize);
			delete[] clientData[i].key;
			clientData[i].key = 0;
			clientData[i].keySize = 0;
			return false;
		}
	}
	return true;
}

bool SendUsersPublicKey(ClientData& clientData, ServDB& servDB, char* sendBuf, char* buf)
{
	unsigned int nbytes = recvr(clientData.sock, &buf[1], 4, 0);
	if(nbytes != 4)
	{
		SendError("Invalid request", clientData.sock, sendBuf);
		return false;
	}

	//SEND BACK REQUESTED USER'S PUBLIC KEY
	if(clientData.userID != 0)
	{
		uint32_t userID = ntohl(*((uint32_t*)&buf[1]));
		if(!servDB.UserExists(userID))
		{
			SendError("User does not exist on this server", clientData.sock, sendBuf);
			return false;
		}

		char* userPubKey = servDB.FetchPublicKey(userID);
		if(userPubKey == 0)
		{
			SendError(servDB.GetError(), clientData.sock, sendBuf);
			return false;
		}
		else
		{
			sendBuf[0] = '\x01';
			memcpy(&sendBuf[1], userPubKey, 32);
			send(clientData.sock, sendBuf, 33, 0);
			delete[] userPubKey;
		}
	}
	else
	{
		SendError("Not signed in", clientData.sock, sendBuf);
		return false;
	}
	return true;
}

bool AddContact(ClientData& clientData, ServDB& servDB, char* sendBuf, char* buf)
{
	unsigned int nbytes = recvr(clientData.sock, &buf[1], 4 + 1, 0);
	if(nbytes != 4 + 1)
	{
		SendError("Invalid request", clientData.sock, sendBuf);
		return false;
	}
	uint32_t encNickLen = (uint8_t)buf[5];
	if(encNickLen > 32)
	{
		/*SendError("Impossible request, can't deal, killing you", clientData.sock, sendBuf);
		FullLogout(&clientData, &master, &servDB);*/
		SendError("Invalid request", clientData.sock, sendBuf);
		return false;
	}

	nbytes += recvr(clientData.sock, &buf[6], encNickLen, 0);
	if(nbytes != 4 + 1 + encNickLen)
	{
		SendError("Invalid request", clientData.sock, sendBuf);
		return false;
	}

	//ADD PERSON TO CONTACTS (NICKNAME OPTIONAL)
	if(clientData.userID != 0)
	{
		uint32_t contactID = ntohl(*((uint32_t*)&buf[1]));
		if(!servDB.UserExists(contactID))
		{
			SendError("User does not exist on this server", clientData.sock, sendBuf);
			return false;
		}

		if(contactID == clientData.userID)
		{
			SendError("That's sad...", clientData.sock, sendBuf);
			return false;
		}

		char* encNickname = (nbytes == 5 + 16 || nbytes == 5 + 32)? &buf[6] : 0;
		bool succeed = servDB.AddUserToContacts(clientData.userID, contactID, encNickname, encNickLen);
		if(!succeed)
		{
			SendError(servDB.GetError(), clientData.sock, sendBuf);
			return false;
		}
		else
		{
			sendBuf[0] = '\x01';
			send(clientData.sock, sendBuf, 1, 0);
		}
	}
	else
	{
		SendError("Not signed in", clientData.sock, sendBuf);
		return false;
	}
	return true;
}

bool CreateConvWithUser(ClientData& clientData, ServDB& servDB, char* sendBuf, char* buf)
{
	unsigned int nbytes = recvr(clientData.sock, &buf[1], 4 + 16 + 48 + 16 + 48, 0);
	if(nbytes != 4 + 16 + 48 + 16 + 48)
	{
		SendError("Invalid request", clientData.sock, sendBuf);
		return false;
	}

	//CREATE CONVERSATION WITH USER (IF USER HAS ADDED BACK)
	if(clientData.userID != 0)
	{
		uint32_t contactID = ntohl(*((uint32_t*)&buf[1]));
		if(!servDB.UserExists(contactID))
		{
			SendError("User does not exist on this server", clientData.sock, sendBuf);
			return false;
		}

		if(servDB.UserAddedContact(contactID, clientData.userID))
		{
			uint32_t convID = servDB.CreateConversation(clientData.userID, &buf[5], &buf[21]);
			if(convID == 0)
			{
				SendError(servDB.GetError(), clientData.sock, sendBuf);
			}

			bool succeed = servDB.AddUserToConv(convID, contactID, &buf[69], &buf[85]);
			if(!succeed)
			{
				SendError(servDB.GetError(), clientData.sock, sendBuf);
				return false;
			}
			else
			{
				sendBuf[0] = '\x01';
				uint32_t c_net = htonl(convID);
				memcpy(&sendBuf[1], &c_net, 4);
				send(clientData.sock, sendBuf, 5, 0);

				if(servDB.IsOnline(contactID))
				{
					SendUserNewConv(servDB.FetchSocket(contactID), contactID, convID, sendBuf, '\x06', servDB);
				}
			}
		}
		else
		{
			SendError("Contact has not added you back yet", clientData.sock, sendBuf);
			return false;
		}
	}
	else
	{
		SendError("Not signed in", clientData.sock, sendBuf);
		return false;
	}
	return true;
}

bool AddUserToConv(ClientData& clientData, ServDB& servDB, char* sendBuf, char* buf)
{
	unsigned int nbytes = recvr(clientData.sock, &buf[1], 4 + 4 + 16 + 48, 0);
	if(nbytes != 4 + 4 + 16 + 48)
	{
		SendError("Invalid request", clientData.sock, sendBuf);
		return false;
	}

	//ADD USER TO CONVERSATION (IF USER HAS ADDED ALL OTHER PARTIES IN CONV, AND EVERYONE HAS ADDED USER)
	if(clientData.userID != 0)
	{
		uint32_t convID = ntohl(*((uint32_t*)&buf[1]));
		uint32_t contactID = ntohl(*((uint32_t*)&buf[5]));
		if(!servDB.UserExists(contactID))
		{
			SendError("User does not exist on this server", clientData.sock, sendBuf);
			return false;
		}
		if(!servDB.UserInConv(clientData.userID, convID))
		{
			SendError("You are not a member of this conversation", clientData.sock, sendBuf);
			return false;
		}

		uint32_t users_num;
		uint32_t* users = servDB.FetchUsersInConv(convID, users_num);
		if(users_num == 0)
		{
			SendError(servDB.GetError(), clientData.sock, sendBuf);
			return false;
		}

		bool mutualTrust = true;
		string err;
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
				SendError(servDB.GetError(), clientData.sock, sendBuf);
				return false;
			}
			else
			{
				sendBuf[0] = '\x01';
				send(clientData.sock, sendBuf, 1, 0);

				if(servDB.IsOnline(contactID))
				{
					SendUserNewConv(servDB.FetchSocket(contactID), contactID, convID, sendBuf, '\x07', servDB);
				}
			}
		}
		else
		{
			SendError(err, clientData.sock, sendBuf);
			return false;
		}
	}
	else
	{
		SendError("Not signed in", clientData.sock, sendBuf);
		return false;
	}
	return true;
}

bool SendMessage(ClientData& clientData, ServDB& servDB, char* sendBuf, char* buf)
{
	unsigned int nbytes = recvr(clientData.sock, &buf[1], 8, 0);
	if(nbytes != 8)
	{
		SendError("Invalid request", clientData.sock, sendBuf);
		return false;
	}
	uint32_t msgLen = ntohl(*((uint32_t*)&buf[5]));
	if(msgLen > 4096)
	{
		//TODO WON'T NEED TO FULL LOGOUT IF CAN MARK ENTIRE SOCKET RECV QUEUE AS READ!
		/*SendError("Dumb request, can't deal, killing you", clientData.sock, sendBuf);
		FullLogout(&clientData, &master, &servDB);*/
		SendError("Invalid request", clientData.sock, sendBuf);
		return false;
	}

	nbytes += recvr(clientData.sock, &buf[9], 16 + msgLen, 0);
	if(nbytes != 8 + 16 + msgLen)
	{
		SendError("Invalid request", clientData.sock, sendBuf);
		return false;
	}

	//BROADCAST MESSAGE TO ALL USERS OF CONVERSATION THAT ARE ONLINE, INCREASE MESSAGE COUNT OF CONV
	if(clientData.userID != 0)
	{
		uint32_t convID = ntohl(*((uint32_t*)&buf[1]));
		uint32_t senderID = clientData.userID;

		if(!servDB.UserInConv(senderID, convID))
		{
			SendError("You are not a member of this conversation", clientData.sock, sendBuf);
			return false;
		}

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
			SendError("Internal error. Message not saved :(", clientData.sock, sendBuf);
			return false;
		}

		uint32_t n = 0;
		uint32_t* users = servDB.FetchUsersInConv(convID, n);
		if(n == 0)
		{
			cerr << servDB.GetError() << "\n";
			return false;
		}

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
		SendError("Not signed in", clientData.sock, sendBuf);
		return false;
	}
	return true;
}

bool SendContacts(ClientData& clientData, ServDB& servDB, char* sendBuf)
{
	//SEND ALL CONTACTS AND THEIR ENCRYPTED NICKNAMES (IF NOT NULL)
	if(clientData.userID != 0)
	{
		uint32_t size;
		char* contacts = servDB.FetchContacts(clientData.userID, size);
		if(size == 0)
		{
			SendError(servDB.GetError(), clientData.sock, sendBuf);
			return false;
		}
		else
		{
			char* dynamicSendBuf = new char[1 + 4 + size];
			dynamicSendBuf[0] = '\x01';
			uint32_t netSize = htonl(size);
			memcpy(&dynamicSendBuf[1], &netSize, 4);
			memcpy(&dynamicSendBuf[5], contacts, size);
			delete[] contacts;
			send(clientData.sock, dynamicSendBuf, 1 + 4 + size, 0);
		}
	}
	else
	{
		SendError("Not signed in", clientData.sock, sendBuf);
		return false;
	}
	return true;
}

bool RemoveContact(ClientData& clientData, ServDB& servDB, char* sendBuf, char* buf)
{
	unsigned int nbytes = recvr(clientData.sock, &buf[1], 4, 0);
	if(nbytes != 4)
	{
		SendError("Invalid request", clientData.sock, sendBuf);
		return false;
	}

	//REMOVE USER FROM CONTACTS
	if(clientData.userID != 0)
	{
		uint32_t contactID = ntohl(*((uint32_t*)&buf[1]));
		bool succeed = servDB.RemoveContact(clientData.userID, contactID);
		if(!succeed)
		{
			SendError(servDB.GetError(), clientData.sock, sendBuf);
			return false;
		}
		else
		{
			sendBuf[0] = '\x01';
			send(clientData.sock, sendBuf, 1, 0);
		}
	}
	else
	{
		SendError("Not signed in", clientData.sock, sendBuf);
		return false;
	}
	return true;
}

bool LeaveConv(ClientData& clientData, ServDB& servDB, char* sendBuf, char* buf)
{
	unsigned int nbytes = recvr(clientData.sock, &buf[1], 4, 0);
	if(nbytes != 4)
	{
		SendError("Invalid request", clientData.sock, sendBuf);
		return false;
	}

	//LEAVE A CONVERSATION
	if(clientData.userID != 0)
	{
		uint32_t convID = ntohl(*((uint32_t*)&buf[1]));
		bool succeed = servDB.LeaveConv(convID, clientData.userID);
		if(!succeed)
		{
			SendError(servDB.GetError(), clientData.sock, sendBuf);
			return false;
		}
		else
		{
			sendBuf[0] = '\x01';
			send(clientData.sock, sendBuf, 1, 0);
		}
	}
	else
	{
		SendError("Not signed in", clientData.sock, sendBuf);
		return false;
	}
	return true;
}

bool SendUserConvInfo(ClientData& clientData, ServDB& servDB, char* sendBuf)
{
	//SEND BACK FORMATTED CONVS LIST WITH DETAILS
	if(clientData.userID != 0)
	{
		uint32_t convs_num;
		uint32_t* convs = servDB.FetchConvs(clientData.userID, convs_num);
		if(convs_num == 0)
		{
			SendError(servDB.GetError(), clientData.sock, sendBuf);
			return false;
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

			char* iv = servDB.FetchConvIV(convs[j], clientData.userID);
			if(iv == 0)
			{
				SendError(servDB.GetError(), clientData.sock, sendBuf);
				size = 0;
				break;
			}
			else
			{
				memcpy(&sendBuf[size], iv, 16);
				size += 16;
				delete[] iv;
			}

			char* encSymKey = servDB.FetchSymKey(convs[j], clientData.userID);
			if(encSymKey == 0)
			{
				SendError(servDB.GetError(), clientData.sock, sendBuf);
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
			return false;

		uint32_t size_net = htonl(size - 5);			//We want the size of the content, which doesn't include success byte and the length indicator itself
		memcpy(&sendBuf[1], &size_net, 4);
		send(clientData.sock, sendBuf, size, 0);
	}
	else
	{
		SendError("Not signed in", clientData.sock, sendBuf);
		return false;
	}
	return true;
}

bool IncreaseUserEOF(ClientData& clientData, ServDB& servDB, char* sendBuf, char* buf)
{
	unsigned int nbytes = recvr(clientData.sock, &buf[1], 4 + 4, 0);
	if(nbytes != 4 + 4)
	{
		SendError("Invalid request", clientData.sock, sendBuf);
		return false;
	}

	//INCREASE LAST KNOWN EOF FOR USER IN CONV
	if(clientData.userID != 0)
	{
		uint32_t convID = ntohl(*((uint32_t*)&buf[1]));
		uint32_t increase = ntohl(*((uint32_t*)&buf[5]));
		if(servDB.IncUserConvEOF(clientData.userID, convID, increase))
			send(clientData.sock, "\x0D", 1, 0);
		else
		{
			SendError(servDB.GetError(), clientData.sock, sendBuf);
			return false;
		}
	}
	else
	{
		SendError("Not signed in", clientData.sock, sendBuf);
		return false;
	}
	return true;
}

bool SendMissedMsgs(ClientData& clientData, ServDB& servDB, char* sendBuf)
{
	//SEND BACK ALL MISSED MESSAGES
	if(clientData.userID != 0)
	{
		uint32_t convs_num;
		uint32_t* convs = servDB.FetchConvs(clientData.userID, convs_num);
		uint32_t size = 0;
		for(unsigned int j = 0; j < convs_num; j++)
		{
			unsigned int diff = servDB.FetchConvUserDif(convs[j], clientData.userID);
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
					SendError("Internal error accessing messages", clientData.sock, sendBuf);
					return false;
				}
			}
		}
		sendBuf[0] = '\x01';
		uint32_t size_net = htonl(size);
		memcpy(&sendBuf[1], &size_net, 4);
		send(clientData.sock, sendBuf, size + 5, 0);
	}
	else
	{
		SendError("Not signed in", clientData.sock, sendBuf);
		return false;
	}
	return true;
}

bool UpdateNickname(ClientData& clientData, ServDB& servDB, char* sendBuf, char* buf)
{
	unsigned int nbytes = recvr(clientData.sock, &buf[1], 4 + 1, 0);
	if(nbytes != 4 + 1)
	{
		SendError("Invalid request", clientData.sock, sendBuf);
		return false;
	}

	//UPDATE CONTACT'S NICKNAME
	if(clientData.userID != 0)
	{
		uint32_t contactID = ntohl(*((uint32_t*)&buf[1]));
		if(servDB.UserAddedContact(clientData.userID, contactID))
		{
			uint8_t encNickLen = buf[5];
			nbytes = recvr(clientData.sock, &buf[6], encNickLen, 0);
			if(nbytes != encNickLen)
			{
				SendError("Didn't receive enough bytes for nickname", clientData.sock, sendBuf);
				return false;
			}
			if(servDB.UpdateContact(clientData.userID, contactID, &buf[6], encNickLen))
				send(clientData.sock, "\x01", 1, 0);
			else
			{
				SendError(servDB.GetError(), clientData.sock, sendBuf);
				return false;
			}
		}
		else
		{
			SendError("User ID not added", clientData.sock, sendBuf);
			return false;
		}
	}
	else
	{
		SendError("Not signed in", clientData.sock, sendBuf);
		return false;
	}
	return true;
}


//	HELPER FUNCTIONS
//------------------------------------------------------------------------------------------------------------------------------
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

void FullLogout(ClientData* clientData, fd_set* master, ServDB* servDB)
{
	shutdown(clientData->sock, SHUT_WR);
	cout <<"Logout socket " << clientData->sock << "\n";
	close(clientData->sock);								//bye!
	FD_CLR(clientData->sock, master);
	clientData->sock = -1;
	if(clientData->userID != 0)										//Was logged in
	{
		servDB->LogoutUser(clientData->userID);
		clientData->userID = 0;										//Remove the socket reference
	}
	if(clientData->key != 0)
	{
		memset(clientData->key, 0, clientData->keySize);
		delete[] clientData->key;
		clientData->key = 0;
		clientData->keySize = 0;
	}
}

void SendUserNewConv(unsigned int sock, uint32_t userID, uint32_t convID, char* sendBuf, char startByte, ServDB& servDB)
{
	sendBuf[0] = startByte;
	uint32_t conv_net = htonl(convID);
	memcpy(&sendBuf[1], &conv_net, 4);
	uint32_t init_net = htonl((uint32_t)servDB.FetchInitiator(convID));
	memcpy(&sendBuf[5], &init_net, 4);;

	char* iv = servDB.FetchConvIV(convID, userID);
	if(iv == 0)
	{
		SendError(servDB.GetError(), sock, sendBuf);
		return;
	}
	else
	{
		memcpy(&sendBuf[9], iv, 16);
		delete[] iv;
	}

	char* encSymKey = servDB.FetchSymKey(convID, userID);
	if(encSymKey == 0)
	{
		SendError(servDB.GetError(), sock, sendBuf);
		return;
	}
	else
	{
		memcpy(&sendBuf[25], encSymKey, 48);
		delete[] encSymKey;
	}

	uint32_t users_num;
	uint32_t* users = servDB.FetchUsersInConv(convID, users_num);
	uint32_t users_num_net = htonl(users_num);
	memcpy(&sendBuf[73], &users_num_net, 4);

	for(unsigned int k = 0; k < users_num; k++)
	{
		uint32_t user_net = htonl(users[k]);
		memcpy(&sendBuf[77 + (4 * k)], &user_net, 4);
	}
	delete[] users;
	send(sock, sendBuf, 77 + (4 * users_num), 0);
	return;
}

void SendError(std::string errMsg, int client, char* sendBuf)
{
	sendBuf[0] = '\0';									//Failed
	uint32_t l = htonl((uint32_t)(errMsg.size() + 1));
	memcpy(&sendBuf[1], &l, 4);
	memcpy(&sendBuf[5], errMsg.c_str(), errMsg.size());
	sendBuf[errMsg.size() + 5] = '\0';
	send(client, sendBuf, errMsg.size() + 6, 0);
}