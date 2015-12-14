#include "RequestManager.h"

RequestManager::RequestManager(ClientData* clients, ServDB* servDB, unsigned char* servPublic, unsigned char* servPrivate, FortunaPRNG* fprng, fd_set* master)
{
	assert(clients != NULL && servDB != NULL && servPublic != NULL && servPrivate != NULL && fprng != NULL && master != NULL);
	this->clients = clients;
	this->servDB = servDB;
	this->servPublic = servPublic;
	this->servPrivate = servPrivate;
	this->fprng = fprng;
	this->master = master;
}

//	REQUEST FUNCTIONS
//------------------------------------------------------------------------------------------------------------------------------
void RequestManager::SendServerPublicKey(ClientData& clientData)
{
	//SEND BACK SERVER PUBLIC KEY
	send(clientData.sock, servPublic, 32, 0);									//If they don't have the public key, signatures don't make much sense ;)
}

bool RequestManager::CreateUser(ClientData& clientData, char* sendBuf, char* buf)
{
	//16 BIT TEST!!
	//----------------------------------------------------------------------------------
	if(clientData.key == 0)
	{
		buf[1] = '\x10';
		clientData.key = new char[32];
		clientData.keySize = 32;

		fprng->GenerateBlocks((unsigned char*)clientData.key, 1);				//Hash
		fprng->GenerateBlocks((unsigned char*)&clientData.key[16], 1);			//Salt

		memcpy(&buf[2], clientData.key, 32);
		send(clientData.sock, &buf[1], 33, 0);
		return true;
	}

	unsigned int nbytes = recvr(clientData.sock, &buf[1], 16, 0);
	if(nbytes != 16)
	{
		SendError(clientData, "Invalid request");
		memset(clientData.key, 0, clientData.keySize);
		delete[] clientData.key;
		clientData.key = 0;
		clientData.keySize = 0;
		return false;
	}

	unsigned char* theirHash = new unsigned char[16];
	libscrypt_scrypt((const uint8_t*)&buf[1], 16, (const uint8_t*)&clientData.key[16], 16, 128, 3, 1, theirHash, 16);
	if(memcmp(theirHash, clientData.key, 2) != 0)
	{
		SendError(clientData, "Hash test failed, closing connection");
		FullLogout(&clientData);
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
		SendError(clientData, "Invalid request");
		return false;
	}

	//CREATE USER FROM BASIC INFO	   (public	 				  private   			   IV		 				  salt)
	uint32_t userID = servDB->CreateUser((const uint8_t*)&buf[1], (const uint8_t*)&buf[33], (const uint8_t*)&buf[81], (const uint8_t*)&buf[97]);
	if(userID == 0)
	{
		SendError(clientData, "Couldn't create account: Internal error");
		cerr << servDB->GetError() << "\n";
		return false;
	}
	else
	{
		userID = htonl(userID);
		SendSigned(clientData, 1, &userID, 4);
	}
	return true;
}

bool RequestManager::SendInfo(ClientData& clientData, char* sendBuf, char* buf)
{
	unsigned int nbytes = recvr(clientData.sock, &buf[1], 4 + 1, 0);
	if(nbytes != 4 + 1)
	{
		SendError(clientData, "Invalid request");
		return false;
	}

	//SEND BACK WHAT THEY REQUESTED FROM MYSQL
	unsigned int returnLength = 0;
	uint32_t userID = ntohl(*((uint32_t*)&buf[1]));
	if(!servDB->UserExists(userID))
	{
		SendError(clientData, "User does not exist on this server");
		return false;
	}

	if(buf[5] & 8)
	{
		uint32_t rand = servDB->FetchRandomInt(userID);
		rand = htonl(rand);
		memcpy(&sendBuf[returnLength], &rand, 4);
		returnLength += 4;
	}
	if(buf[5] & 4)
	{
		char* userSalt = servDB->FetchSalt(userID);
		memcpy(&sendBuf[returnLength], userSalt, 16);
		returnLength += 16;
		delete[] userSalt;
	}
	if(buf[5] & 2)
	{
		char* userIV = servDB->FetchIV(userID);
		memcpy(&sendBuf[returnLength], userIV, 16);
		returnLength += 16;
		delete[] userIV;
	}
	if(buf[5] & 1)
	{
		char* userEncPrivKey = servDB->FetchEncPrivateKey(userID);
		if(userEncPrivKey == 0)
		{
			SendError(clientData, "Unable to fetch private key: Internal error");
			cerr << servDB->GetError() << "\n";
			return false;
		}
		memcpy(&sendBuf[returnLength], userEncPrivKey, 48);
		returnLength += 48;
		delete[] userEncPrivKey;
	}
	SendSigned(clientData, 2, sendBuf, returnLength);
	return true;
}

bool RequestManager::Login(ClientData& clientData, char* sendBuf, char* buf)
{
	unsigned int nbytes = recvr(clientData.sock, &buf[1], 4 + 32, 0);
	if(nbytes != 4 + 32)
	{
		SendError(clientData, "Invalid request");
		return false;
	}

	//VERIFY RANDOM INT SIG AND LOGIN (ASSIGN DATABASE SOCKET VALUE AND SockToUser VALUE)
	uint32_t userID = ntohl(*((uint32_t*)&buf[1]));
	if(!servDB->UserExists(userID))
	{
		SendError(clientData, "User does not exist on this server");
		return false;
	}

	char* userPubKey = servDB->FetchPublicKey(userID);
	if(userPubKey == 0)
	{
		SendError(clientData, "Couldn't access your public key: Internal error");
		cerr << servDB->GetError() << "\n";
		return false;
	}
	else
	{
		if(clientData.key != 0)
		{
			memset(clientData.key, 0, clientData.keySize);
			delete[] clientData.key;
		}

		clientData.key = new char[32];
		clientData.keySize = 32;
		CreateSharedKey(userID, clientData.key);
		delete[] userPubKey;

		char* Hash = new char[32];
		uint32_t rand = servDB->FetchRandomInt(userID);
		libscrypt_scrypt((const uint8_t*)clientData.key, 32, (const uint8_t*)&rand, 4, 16384, 8, 1, (uint8_t*)Hash, 32);		//Use incrementing integer as salt so hash is always different

		int cmp = memcmp(&buf[5], Hash, 32);
		memset(Hash, 0, 32);
		delete[] Hash;

		if(cmp == 0)
		{
			if(clientData.userID != 0)
			{
				servDB->LogoutUser(clientData.userID);
				clientData.userID = 0;
			}

			if(servDB->IsOnline(userID))
			{
				unsigned int userIndex = servDB->FetchIndex(userID);
				SendError(clients[userIndex], "You were signed in on another connection");
				FullLogout(&clients[userIndex]);
				if(clients[userIndex].key != 0)
				{
					memset(clients[userIndex].key, 0, clients[userIndex].keySize);
					delete[] clients[userIndex].key;
					clients[userIndex].key = 0;
					clients[userIndex].keySize = 0;
				}
			}

			if(servDB->LoginUser(userID, (unsigned int)clientData.sock))
			{
				clientData.userID = userID;
				send(clientData.sock, "\x03", 1, 0);
				VERBOSE_PRINT("User ID %d was signed in\n", userID);
				return true;
			}
			else
			{
				SendError(clientData, "Unable to sign in: Internal error");
				cerr << servDB->GetError() << "\n";

				memset(clientData.key, 0, clientData.keySize);
				delete[] clientData.key;
				clientData.key = 0;
				clientData.keySize = 0;
				return false;
			}
		}
		else
		{
			SendError(clientData, "Login credentials were not correct");
			memset(clientData.key, 0, clientData.keySize);
			delete[] clientData.key;
			clientData.key = 0;
			clientData.keySize = 0;
			return false;
		}
	}
}

bool RequestManager::SendUsersPublicKey(ClientData& clientData, char* buf)
{
	unsigned int nbytes = recvr(clientData.sock, &buf[1], 4, 0);
	if(nbytes != 4)
	{
		SendError(clientData, "Invalid request");
		return false;
	}

	//SEND BACK REQUESTED USER'S PUBLIC KEY
	if(clientData.userID != 0)
	{
		uint32_t userID = ntohl(*((uint32_t*)&buf[1]));
		if(!servDB->UserExists(userID))
		{
			SendError(clientData, "User does not exist on this server");
			return false;
		}

		char* userPubKey = servDB->FetchPublicKey(userID);
		if(userPubKey == 0)
		{
			SendError(clientData, "Couldn't fetch user's public key: Internal error");
			cerr << servDB->GetError() << "\n";
			return false;
		}
		else
		{
			SendSigned(clientData, 4, userPubKey, 32);
			delete[] userPubKey;
			return true;
		}
	}
	else
	{
		SendError(clientData, "Not signed in");
		return false;
	}
}

bool RequestManager::AddContact(ClientData& clientData, char* sendBuf, char* buf)
{
	unsigned int nbytes = recvr(clientData.sock, &buf[1], 4 + 1, 0);
	if(nbytes != 4 + 1)
	{
		SendError(clientData, "Invalid request");
		return false;
	}
	uint32_t encNickLen = (uint8_t)buf[5];
	if(encNickLen > 32)
	{
		/*SendError(clientData, "Impossible request, can't deal, killing you");
		FullLogout(&clientData, &master, &servDB);*/
		SendError(clientData, "Invalid request");
		return false;
	}

	nbytes += recvr(clientData.sock, &buf[6], encNickLen, 0);
	if(nbytes != 4 + 1 + encNickLen)
	{
		SendError(clientData, "Invalid request");
		return false;
	}

	//ADD PERSON TO CONTACTS (NICKNAME OPTIONAL)
	if(clientData.userID != 0)
	{
		uint32_t contactID = ntohl(*((uint32_t*)&buf[1]));
		if(!servDB->UserExists(contactID))
		{
			SendError(clientData, "User does not exist on this server");
			return false;
		}

		if(contactID == clientData.userID)
		{
			SendError(clientData, "That's sad...");
			return false;
		}

		char* encNickname = (nbytes == 5 + 16 || nbytes == 5 + 32)? &buf[6] : 0;
		bool succeed = servDB->AddUserToContacts(clientData.userID, contactID, encNickname, encNickLen);
		if(!succeed)
		{
			SendError(clientData, "Couldn't add user to contacts: Internal error");
			cerr << servDB->GetError() << "\n";
			return false;
		}
		else
		{
			send(clientData.sock, "\x05", 1, 0);
		}
	}
	else
	{
		SendError(clientData, "Not signed in");
		return false;
	}
	return true;
}

bool RequestManager::CreateConvWithUser(ClientData& clientData, char* sendBuf, char* buf)
{
	unsigned int nbytes = recvr(clientData.sock, &buf[1], 4 + 16 + 48 + 16 + 48, 0);
	if(nbytes != 4 + 16 + 48 + 16 + 48)
	{
		SendError(clientData, "Invalid request");
		return false;
	}

	//CREATE CONVERSATION WITH USER (IF USER HAS ADDED BACK)
	if(clientData.userID != 0)
	{
		uint32_t contactID = ntohl(*((uint32_t*)&buf[1]));
		if(!servDB->UserExists(contactID))
		{
			SendError(clientData, "User does not exist on this server");
			return false;
		}

		if(servDB->UserAddedContact(contactID, clientData.userID))
		{
			uint32_t convID = servDB->CreateConversation(clientData.userID, (const uint8_t*)&buf[5], (const uint8_t*)&buf[21]);
			if(convID == 0)
			{
				SendError(clientData, "Couldn't create conversation: Internal error");
				cerr << servDB->GetError() << "\n";
				return false;
			}

			bool succeed = servDB->AddUserToConv(convID, contactID, (const uint8_t*)&buf[69], (const uint8_t*)&buf[85]);
			if(!succeed)
			{
				SendError(clientData, "Couldn't add user to conversation: Internal error");
				cerr << servDB->GetError() << "\n";
				return false;
			}
			else
			{
				uint32_t c_net = htonl(convID);
				SendSigned(clientData, 6, &c_net, 4);

				if(servDB->IsOnline(contactID))
				{
					ClientData cd = clients[servDB->FetchIndex(contactID)];
					SendUserNewConv(cd, convID, sendBuf, '\xFA');
				}
			}
		}
		else
		{
			SendError(clientData, "Contact has not added you back yet");
			return false;
		}
	}
	else
	{
		SendError(clientData, "Not signed in");
		return false;
	}
	return true;
}

bool RequestManager::AddUserToConv(ClientData& clientData, char* sendBuf, char* buf)
{
	unsigned int nbytes = recvr(clientData.sock, &buf[1], 4 + 4 + 16 + 48, 0);
	if(nbytes != 4 + 4 + 16 + 48)
	{
		SendError(clientData, "Invalid request");
		return false;
	}

	//ADD USER TO CONVERSATION (IF USER HAS ADDED ALL OTHER PARTIES IN CONV, AND EVERYONE HAS ADDED USER)
	if(clientData.userID != 0)
	{
		uint32_t convID = ntohl(*((uint32_t*)&buf[1]));
		uint32_t contactID = ntohl(*((uint32_t*)&buf[5]));
		if(!servDB->UserExists(contactID))
		{
			SendError(clientData, "User does not exist on this server");
			return false;
		}
		if(!servDB->UserInConv(clientData.userID, convID))
		{
			SendError(clientData, "You are not a member of this conversation");
			return false;
		}

		uint32_t users_num;
		uint32_t* users = servDB->FetchUsersInConv(convID, users_num);
		if(users_num == 0)
		{
			SendError(clientData, servDB->GetError());
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
			if(!servDB->UserAddedContact(contactID, users[j]))
			{
				mutualTrust = false;
				stringstream ss;
				ss << "User " << contactID << " hasn't added user " << users[j];
				err = ss.str();
				break;
			}
			if(!servDB->UserAddedContact(users[j], contactID))
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
			bool succeed = servDB->AddUserToConv(convID, contactID, (const uint8_t*)&buf[9], (const uint8_t*)&buf[25]);
			if(!succeed)
			{
				SendError(clientData, servDB->GetError());
				return false;
			}
			else
			{
				send(clientData.sock, "\x07", 1, 0);

				if(servDB->IsOnline(contactID))
				{
					ClientData cd = clients[servDB->FetchIndex(contactID)];
					SendUserNewConv(cd, convID, sendBuf, '\xF9');
				}
			}
		}
		else
		{
			SendError(clientData, err);
			return false;
		}
	}
	else
	{
		SendError(clientData, "Not signed in");
		return false;
	}
	return true;
}

bool RequestManager::SendMessage(ClientData& clientData, char* sendBuf, char* buf)
{
	unsigned int nbytes = recvr(clientData.sock, &buf[1], 8, 0);
	if(nbytes != 8)
	{
		SendError(clientData, "Invalid request");
		return false;
	}
	uint32_t msgLen = ntohl(*((uint32_t*)&buf[5]));
	if(msgLen > 4096)
	{
		//TODO: WON'T NEED TO FULL LOGOUT IF CAN MARK ENTIRE SOCKET RECV QUEUE AS READ!
		FullLogout(&clientData);
		SendError(clientData, "Invalid request");
		return false;
	}

	nbytes += recvr(clientData.sock, &buf[9], 16 + msgLen, 0);
	if(nbytes != 8 + 16 + msgLen)
	{
		SendError(clientData, "Invalid request");
		return false;
	}

	//BROADCAST MESSAGE TO ALL USERS OF CONVERSATION THAT ARE ONLINE, INCREASE MESSAGE COUNT OF CONV
	if(clientData.userID != 0)
	{
		uint32_t convID = ntohl(*((uint32_t*)&buf[1]));
		uint32_t senderID = clientData.userID;

		if(!servDB->UserInConv(senderID, convID))
		{
			SendError(clientData, "You are not a member of this conversation");
			return false;
		}

		uint32_t senderNet = htonl(senderID);
		memcpy(sendBuf, &buf[1], 8);											//Copy convID and msgLen to broadcast msg
		memcpy(&sendBuf[8], &senderNet, 4);										//Copy senderID
		memcpy(&sendBuf[12], &buf[9], 16 + msgLen);								//Copy IV + msg

		stringstream ss;
		ss << convID;
		ofstream convFile(ss.str().c_str(), ios::out | ios::app | ios::binary);
		if(convFile.is_open())
		{
			convFile.write("\xFF", 1);
			convFile.write(&sendBuf[4], 4 + 4 + 16 + msgLen);
			convFile.close();
		}
		else
		{
			cerr << "Couldn't open conv " << convID << " file\n";
			SendError(clientData, "Internal error. Message not saved :(");
			return false;
		}

		uint32_t n = 0;
		uint32_t* users = servDB->FetchUsersInConv(convID, n);
		if(n == 0)
		{
			cerr << servDB->GetError() << "\n";
			return false;
		}

		for(unsigned int j = 0; j < n; j++)
		{
			if(servDB->IsOnline(users[j]))
			{
				ClientData cd = clients[servDB->FetchIndex(users[j])];
				SendSigned(cd, '\xFF', sendBuf, 4 + 4 + 4 + 16 + msgLen);
			}
		}
		if(!servDB->IncreaseConvEOF(convID, 1 + 4 + 4 + 16 + msgLen))
			cerr << servDB->GetError() << "\n";

		delete[] users;
	}
	else
	{
		SendError(clientData, "Not signed in");
		return false;
	}
	return true;
}

bool RequestManager::SendContacts(ClientData& clientData, char* sendBuf)
{
	//SEND ALL CONTACTS AND THEIR ENCRYPTED NICKNAMES (IF NOT NULL)
	if(clientData.userID != 0)
	{
		uint32_t size;
		char* contacts = servDB->FetchContacts(clientData.userID, size);
		if(size == 0)
		{
			SendError(clientData, servDB->GetError());
			return false;
		}
		else
		{
			char* dynamicSendBuf = new char[4 + size];
			uint32_t netSize = htonl(size);
			memcpy(dynamicSendBuf, &netSize, 4);
			memcpy(&dynamicSendBuf[4], contacts, size);
			delete[] contacts;
			SendSigned(clientData, 9, dynamicSendBuf, 4 + size);
		}
	}
	else
	{
		SendError(clientData, "Not signed in");
		return false;
	}
	return true;
}

bool RequestManager::RemoveContact(ClientData& clientData, char* sendBuf, char* buf)
{
	unsigned int nbytes = recvr(clientData.sock, &buf[1], 4, 0);
	if(nbytes != 4)
	{
		SendError(clientData, "Invalid request");
		return false;
	}

	//REMOVE USER FROM CONTACTS
	if(clientData.userID != 0)
	{
		uint32_t contactID = ntohl(*((uint32_t*)&buf[1]));
		bool succeed = servDB->RemoveContact(clientData.userID, contactID);
		if(!succeed)
		{
			SendError(clientData, servDB->GetError());
			return false;
		}
		else
		{
			send(clientData.sock, "\x0A", 1, 0);
		}
	}
	else
	{
		SendError(clientData, "Not signed in");
		return false;
	}
	return true;
}

bool RequestManager::LeaveConv(ClientData& clientData, char* sendBuf, char* buf)
{
	unsigned int nbytes = recvr(clientData.sock, &buf[1], 4, 0);
	if(nbytes != 4)
	{
		SendError(clientData, "Invalid request");
		return false;
	}

	//LEAVE A CONVERSATION
	if(clientData.userID != 0)
	{
		uint32_t convID = ntohl(*((uint32_t*)&buf[1]));
		bool succeed = servDB->LeaveConv(convID, clientData.userID);
		if(!succeed)
		{
			SendError(clientData, servDB->GetError());
			return false;
		}
		else
		{
			send(clientData.sock, "\x0B", 1, 0);
		}
	}
	else
	{
		SendError(clientData, "Not signed in");
		return false;
	}
	return true;
}

bool RequestManager::SendUserConvInfo(ClientData& clientData, char* sendBuf)
{
	//SEND BACK FORMATTED CONVS LIST WITH DETAILS
	if(clientData.userID != 0)
	{
		uint32_t convs_num;
		uint32_t* convs = servDB->FetchConvs(clientData.userID, convs_num);
		if(convs_num == 0)
		{
			SendError(clientData, servDB->GetError());
			return false;
		}

		uint32_t size = 0;
		for(unsigned int j = 0; j < convs_num; j++)
		{
			uint32_t conv_net = htonl(convs[j]);
			memcpy(&sendBuf[size], &conv_net, 4);
			size += 4;

			uint32_t init_net = htonl((uint32_t)servDB->FetchInitiator(convs[j]));
			memcpy(&sendBuf[size], &init_net, 4);
			size += 4;

			char* iv = servDB->FetchConvIV(convs[j], clientData.userID);
			if(iv == 0)
			{
				SendError(clientData, servDB->GetError());
				size = 0;
				break;
			}
			else
			{
				memcpy(&sendBuf[size], iv, 16);
				size += 16;
				delete[] iv;
			}

			char* encSymKey = servDB->FetchSymKey(convs[j], clientData.userID);
			if(encSymKey == 0)
			{
				SendError(clientData, servDB->GetError());
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
			uint32_t* users = servDB->FetchUsersInConv(convs[j], users_num);
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

		SendSigned(clientData, 12, sendBuf, size);
	}
	else
	{
		SendError(clientData, "Not signed in");
		return false;
	}
	return true;
}

bool RequestManager::IncreaseUserEOF(ClientData& clientData, char* sendBuf, char* buf)
{
	unsigned int nbytes = recvr(clientData.sock, &buf[1], 4 + 4, 0);
	if(nbytes != 4 + 4)
	{
		SendError(clientData, "Invalid request");
		return false;
	}

	//INCREASE LAST KNOWN EOF FOR USER IN CONV
	if(clientData.userID != 0)
	{
		uint32_t convID = ntohl(*((uint32_t*)&buf[1]));
		uint32_t increase = ntohl(*((uint32_t*)&buf[5]));
		if(servDB->IncUserConvEOF(clientData.userID, convID, increase))
			send(clientData.sock, "\x0D", 1, 0);
		else
		{
			SendError(clientData, servDB->GetError());
			return false;
		}
	}
	else
	{
		SendError(clientData, "Not signed in");
		return false;
	}
	return true;
}

bool RequestManager::SendMissedMsgs(ClientData& clientData)
{
	//SEND BACK ALL MISSED MESSAGES
	if(clientData.userID != 0)
	{
		//Get info on all conversations user belongs to
		uint32_t convs_num;
		uint32_t* convs = servDB->FetchConvs(clientData.userID, convs_num);

		//Store information on missed messages for each conversation
		char** buffers = new char*[convs_num];
		uint32_t* sizes = new uint32_t[convs_num];
		bool* errorFree = new bool[convs_num];

		//Fill a buffer with missed messages for each conv
		uint32_t size = 0;
		for(unsigned int i = 0; i < convs_num; i++)
		{
			if((errorFree[i] = GetMissedConvMsgs(clientData.userID, convs[i], buffers[i], sizes[i])) == true)
				size += sizes[i];
		}

		//Setup header
		char* sendBuf = new char[size];

		//Copy elements to buffer, free memory
		size = 0;
		for(unsigned int i = 0; i < convs_num; i++)
		{
			if(errorFree[i])
			{
				memcpy(&sendBuf[size], buffers[i], sizes[i]);
				size += sizes[i];
				delete[] buffers[i];
			}
		}
		delete[] buffers;
		delete[] sizes;
		delete[] errorFree;

		//Send away
		SendSigned(clientData, 14, sendBuf, size);
		delete[] sendBuf;

		return true;
	}
	else
	{
		SendError(clientData, "Not signed in");
		return false;
	}
}

bool RequestManager::UpdateNickname(ClientData& clientData, char* sendBuf, char* buf)
{
	unsigned int nbytes = recvr(clientData.sock, &buf[1], 4 + 1, 0);
	if(nbytes != 4 + 1)
	{
		SendError(clientData, "Invalid request");
		return false;
	}

	//UPDATE CONTACT'S NICKNAME
	if(clientData.userID != 0)
	{
		uint32_t contactID = ntohl(*((uint32_t*)&buf[1]));
		if(servDB->UserAddedContact(clientData.userID, contactID))
		{
			uint8_t encNickLen = buf[5];
			nbytes = recvr(clientData.sock, &buf[6], encNickLen, 0);
			if(nbytes != encNickLen)
			{
				SendError(clientData, "Didn't receive enough bytes for nickname");
				return false;
			}
			if(servDB->UpdateContact(clientData.userID, contactID, &buf[6], encNickLen))
				send(clientData.sock, "\x0F", 1, 0);
			else
			{
				SendError(clientData, servDB->GetError());
				return false;
			}
		}
		else
		{
			SendError(clientData, "User ID not added");
			return false;
		}
	}
	else
	{
		SendError(clientData, "Not signed in");
		return false;
	}
	return true;
}

bool RequestManager::SetUserEOF(ClientData& clientData, char* sendBuf, char* buf)
{
	unsigned int nbytes = recvr(clientData.sock, &buf[1], 4 + 4, 0);
	if(nbytes != 4 + 4)
	{
		SendError(clientData, "Invalid request");
		return false;
	}

	//SET LAST KNOWN EOF FOR USER IN CONV TO X
	if(clientData.userID != 0)
	{
		uint32_t convID = ntohl(*((uint32_t*)&buf[1]));
		uint32_t val = ntohl(*((uint32_t*)&buf[5]));
		if(servDB->SetUserConvEOF(clientData.userID, convID, val))
			send(clientData.sock, "\x10", 1, 0);
		else
		{
			SendError(clientData, servDB->GetError());
			return false;
		}
	}
	else
	{
		SendError(clientData, "Not signed in");
		return false;
	}
	return true;
}


//	HELPER FUNCTIONS
//------------------------------------------------------------------------------------------------------------------------------
int RequestManager::recvr(int socket, char* buffer, int length, int flags)
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

void RequestManager::FullLogout(ClientData* clientData)
{
	shutdown(clientData->sock, SHUT_WR);
	VERBOSE_PRINT("Logout socket %d\n", clientData->sock);
	close(clientData->sock);													//bye!
	FD_CLR(clientData->sock, master);
	clientData->sock = -1;
	if(clientData->userID != 0)													//Was logged in
	{
		servDB->LogoutUser(clientData->userID);
		clientData->userID = 0;													//Remove the socket reference
	}
	if(clientData->key != 0)
	{
		memset(clientData->key, 0, clientData->keySize);
		delete[] clientData->key;
		clientData->key = 0;
		clientData->keySize = 0;
	}
}

void RequestManager::SendUserNewConv(ClientData& clientData, uint32_t convID, char* sendBuf, unsigned char type)
{
	uint32_t conv_net = htonl(convID);
	memcpy(&sendBuf[0], &conv_net, 4);
	uint32_t init_net = htonl((uint32_t)servDB->FetchInitiator(convID));
	memcpy(&sendBuf[4], &init_net, 4);;

	char* iv = servDB->FetchConvIV(convID, clientData.userID);
	if(iv == 0)
	{
		SendError(clientData, servDB->GetError());
		return;
	}
	else
	{
		memcpy(&sendBuf[8], iv, 16);
		delete[] iv;
	}

	char* encSymKey = servDB->FetchSymKey(convID, clientData.userID);
	if(encSymKey == 0)
	{
		return;
	}
	else
	{
		memcpy(&sendBuf[24], encSymKey, 48);
		delete[] encSymKey;
	}

	uint32_t users_num;
	uint32_t* users = servDB->FetchUsersInConv(convID, users_num);
	uint32_t users_num_net = htonl(users_num);
	memcpy(&sendBuf[72], &users_num_net, 4);

	for(unsigned int k = 0; k < users_num; k++)
	{
		uint32_t user_net = htonl(users[k]);
		memcpy(&sendBuf[76 + (4 * k)], &user_net, 4);
	}
	delete[] users;
	SendSigned(clientData, type, sendBuf, 76 + (4 * users_num));
	return;
}

bool RequestManager::GetMissedConvMsgs(uint32_t userID, uint32_t convID, char*& buffer, uint32_t& size)
{
	unsigned int convEOF = servDB->FetchConvEOF(convID);
	unsigned int eof = servDB->FetchUserConvEOF(convID, userID);
	if(convEOF == (unsigned int)(-1) || eof == (unsigned int)(-1))
	{
		cerr << servDB->GetError();
		return false;
	}

	//Need at least 11/10 X the EOF diff. to guarentee large enough buffer
	buffer = new char[((convEOF-eof)*11)/10];
	size = 0;

	stringstream ss;
	ss << convID;
	ifstream convFile(ss.str().c_str(), ios::in | ios::binary);
	if(convFile.is_open())
	{
		while(eof < convEOF)
		{
			uint32_t conv_net = htonl(convID);
			convFile.seekg(eof, convFile.beg);
			convFile.read(&buffer[size], 1);
			if(buffer[size] == '\xFF')											//Regular message
			{
				memcpy(&buffer[size + 1], &conv_net, 4);
				convFile.read(&buffer[size + 5], 4 + 4 + 16);
				uint32_t msgLen = ntohl(*((uint32_t*)&buffer[size + 5]));
				convFile.read(&buffer[size + 29], msgLen);
				size += 1 + 4 + 4 + 4 + 16 + msgLen;
				eof += 1 + 4 + 4 + 16 + msgLen;
			}
			else
			{
				cerr << "Unknown message type " << +buffer[size] << " at position " << eof << endl;
				convFile.close();
				delete[] buffer;
				return false;
			}
		}
		convFile.close();
		return true;
	}
	else
	{
		cerr << "Couldn't open conv " << convID << " file\n";
		delete[] buffer;
		return false;
	}
}

void RequestManager::SendSigned(ClientData& clientData, unsigned char type, const void* buffer, unsigned int len)
{
	char header[37];
	header[0] = type;
	uint32_t size_net = htonl(len);
	memcpy(&header[1], &size_net, 4);

	if(clientData.key != NULL && clientData.keySize == 32)						//Sign if we have a shared key
		libscrypt_scrypt((const unsigned char*)clientData.key, 32, (const unsigned char*)buffer, len, 16384, 8, 1, (unsigned char*)&header[5], 32);

	send(clientData.sock, header, 37, 0);
	send(clientData.sock, buffer, len, 0);
}

void RequestManager::SendError(ClientData& clientData, string errMsg)
{
	//TODO: Encrypt error message before sending
	SendSigned(clientData, 0, errMsg.c_str(), errMsg.length());
}

void RequestManager::CreateSharedKey(uint32_t userID, char* keyBuffer)
{
	char* userPubKey = servDB->FetchPublicKey(userID);
	curve25519_donna((unsigned char*)keyBuffer, (const unsigned char*)servPrivate, (const unsigned char*)userPubKey);
}
