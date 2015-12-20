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
//------------------------------------------------------------------------------
void RequestManager::SendServerPublicKey(ClientData& clientData)
{
	//SEND BACK SERVER PUBLIC KEY
	send(clientData.sock, servPublic, 32, 0);									//If they don't have the public key, signatures don't make much sense ;)
	VERBOSE_PRINT("Server public key sent\n");
}

bool RequestManager::CreateUser(ClientData& clientData, unsigned int index, const char* buf, unsigned int length)
{
	//16 BIT TEST!!
	//--------------------------------------------------------------------------
	if(clientData.key == 0)
	{
		char BitTest[33];
		BitTest[0] = '\x10';													//16 bits
		clientData.key = new char[32];
		clientData.haveSymmetricKey = false;									//This is for testing hashes, not a shared key

		fprng->GenerateBlocks((unsigned char*)clientData.key, 1);				//Hash
		fprng->GenerateBlocks((unsigned char*)&clientData.key[16], 1);			//Salt

		memcpy(&BitTest[1], clientData.key, 32);
		send(clientData.sock, BitTest, 33, 0);
		VERBOSE_PRINT("Challenge sent\n");
		return true;
	}

	if(length != 16 + 32 + 48 + 16 + 16)
	{
		SendError(clientData, "Invalid request");
		VERBOSE_PRINT("CreateUser: Incorrect length\n");
		memset(clientData.key, 0, 32);
		delete[] clientData.key;
		clientData.key = 0;
		clientData.haveSymmetricKey = false;
		return false;
	}

	unsigned char theirHash[16];
	libscrypt_scrypt((const uint8_t*)buf, 16, (const uint8_t*)&clientData.key[16], 16, 128, 3, 1, theirHash, 16);
	if(memcmp(theirHash, clientData.key, 2) != 0)
	{
		SendError(clientData, "Hash test failed, closing connection");
		VERBOSE_PRINT("CreateUser: Hash test failed\n");
		FullLogout(&clientData);
		return false;
	}
	delete[] clientData.key;
	clientData.key = 0;
	clientData.haveSymmetricKey = false;

	//Passed the hash test, now actually do that thing they wanted...
	//CREATE USER FROM BASIC INFO		( public	 			   private   				 IV		 				   salt)
	uint32_t userID = servDB->CreateUser((const uint8_t*)&buf[16], (const uint8_t*)&buf[48], (const uint8_t*)&buf[96], (const uint8_t*)&buf[112]);
	if(userID == 0)
	{
		SendError(clientData, "Couldn't create account: Internal error");
		cerr << servDB->GetError() << "\n";
		return false;
	}
	else
	{
		clientData.key = new char[32];
		if(CreateSharedKey(userID, clientData.key))
		{
			clientData.haveSymmetricKey = true;
			servDB->LoginUser(userID, index);
		}
		else
		{
			delete[] clientData.key;
			cerr << "Created user " << userID << " but couldn't make shared key\n";
		}

		userID = htonl(userID);
		SendEncrypted(clientData, 1, &userID, 4);
		VERBOSE_PRINT("Created user ID %d\n", ntohl(userID));
		return true;
	}
}

bool RequestManager::SendInfo(ClientData& clientData, const char* buf, unsigned int length)
{
	if(length != 4 + 1)
	{
		SendError(clientData, "Invalid request");
		VERBOSE_PRINT("SendInfo: Incorrect length\n");
		return false;
	}

	//SEND BACK WHAT THEY REQUESTED FROM MYSQL
	unsigned int returnLength = 0;
	uint32_t userID = ntohl(*((uint32_t*)buf));
	if(!servDB->UserExists(userID))
	{
		SendError(clientData, "User does not exist on this server");
		VERBOSE_PRINT("SendInfo: User doesn't exist\n");
		return false;
	}

	if(buf[4] & 8)
	{
		uint32_t rand = servDB->FetchRandomInt(userID);
		rand = htonl(rand);
		memcpy(WORKSPACE, &rand, 4);
		returnLength += 4;
	}
	if(buf[4] & 4)
	{
		char* userSalt = servDB->FetchSalt(userID);
		if(userSalt == 0)
		{
			SendError(clientData, "Unable to fetch salt: Internal error");
			cerr << servDB->GetError() << "\n";
			return false;
		}

		memcpy(&WORKSPACE[returnLength], userSalt, 16);
		returnLength += 16;
		delete[] userSalt;
	}
	if(buf[4] & 2)
	{
		char* userIV = servDB->FetchIV(userID);
		if(userIV == 0)
		{
			SendError(clientData, "Unable to fetch initialization vector: Internal error");
			cerr << servDB->GetError() << "\n";
			return false;
		}

		memcpy(&WORKSPACE[returnLength], userIV, 16);
		returnLength += 16;
		delete[] userIV;
	}
	if(buf[4] & 1)
	{
		char* userEncPrivKey = servDB->FetchEncPrivateKey(userID);
		if(userEncPrivKey == 0)
		{
			SendError(clientData, "Unable to fetch private key: Internal error");
			cerr << servDB->GetError() << "\n";
			return false;
		}

		memcpy(&WORKSPACE[returnLength], userEncPrivKey, 48);
		returnLength += 48;
		delete[] userEncPrivKey;
	}

	SendEncrypted(clientData, 2, WORKSPACE, returnLength);
	VERBOSE_PRINT("Sent information %d to %d\n", buf[4], userID);
	return true;
}

bool RequestManager::Login(ClientData& clientData, unsigned int index, const char* buf, unsigned int length)
{
	if(length != 4 + 32)
	{
		SendError(clientData, "Invalid request");
		VERBOSE_PRINT("Login: Incorrect length\n");
		return false;
	}

	//VERIFY RANDOM INT SIG AND LOGIN (ASSIGN DATABASE INDEX VALUE and ClientData userID field)
	uint32_t userID = ntohl(*((uint32_t*)buf));
	if(!servDB->UserExists(userID))
	{
		SendError(clientData, "User does not exist on this server");
		VERBOSE_PRINT("Login: User doesn't exist\n");
		return false;
	}

	if(clientData.userID != 0)
	{
		servDB->LogoutUser(clientData.userID);
		clientData.userID = 0;
	}

	if(clientData.key != 0)
	{
		memset(clientData.key, 0, 32);
		delete[] clientData.key;
	}
	clientData.key = new char[32];
	clientData.haveSymmetricKey = false;

	if(!CreateSharedKey(userID, clientData.key))
	{
		SendError(clientData, "Couldn't access your public key: Internal error");
		cerr << servDB->GetError() << "\n";
		delete[] clientData.key;
		clientData.key = 0;
		return false;
	}
	else
	{
		clientData.haveSymmetricKey = true;
		char Hash[32];
		uint32_t rand = servDB->FetchRandomInt(userID);
		libscrypt_scrypt((const uint8_t*)clientData.key, 32, (const uint8_t*)&rand, 4, 16384, 8, 1, (uint8_t*)Hash, 32);	//Use incrementing integer as salt so hash is always different each login

		int cmp = memcmp(&buf[4], Hash, 32);
		memset(Hash, 0, 32);

		if(cmp == 0)
		{
			if(servDB->IsOnline(userID))
			{
				unsigned int userIndex = servDB->FetchIndex(userID);
				SendError(clients[userIndex], "You were signed in on another connection");
				VERBOSE_PRINT("Login: User signed in from second client\n");
				FullLogout(&clients[userIndex]);
			}

			if(servDB->LoginUser(userID, index))
			{
				clientData.userID = userID;
				WORKSPACE[0] = 0;
				SendEncrypted(clientData, 3, WORKSPACE, 0);						//When padded becomes 16 bytes of value 16, then encrypted with shared key
				VERBOSE_PRINT("Login: User ID %d was signed in\n", userID);
				return true;
			}
			else
			{
				SendError(clientData, "Unable to sign in: Internal error");
				cerr << servDB->GetError() << "\n";

				memset(clientData.key, 0, 32);
				delete[] clientData.key;
				clientData.key = 0;
				clientData.haveSymmetricKey = false;
				return false;
			}
		}
		else
		{
			SendError(clientData, "Login credentials were not correct");
			VERBOSE_PRINT("Login: Incorrect signature\n");
			memset(clientData.key, 0, 32);
			delete[] clientData.key;
			clientData.key = 0;
			clientData.haveSymmetricKey = false;
			return false;
		}
	}
}

bool RequestManager::SendUsersPublicKey(ClientData& clientData, const char* buf, unsigned int length)
{
	if(length != 4)
	{
		SendError(clientData, "Invalid request");
		VERBOSE_PRINT("SendUsersPublicKey: Incorrect length\n");
		return false;
	}

	//SEND BACK REQUESTED USER'S PUBLIC KEY
	if(clientData.userID != 0)
	{
		uint32_t userID = ntohl(*((uint32_t*)buf));
		if(!servDB->UserExists(userID))
		{
			SendError(clientData, "User does not exist on this server");
			VERBOSE_PRINT("SendUsersPublicKey: User doesn't exist\n");
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
			SendEncrypted(clientData, 4, userPubKey, 32);
			delete[] userPubKey;
			VERBOSE_PRINT("Public key sent\n");
			return true;
		}
	}
	else
	{
		SendError(clientData, "Not signed in");
		VERBOSE_PRINT("SendUsersPublicKey: User not signed in\n");
		return false;
	}
}

bool RequestManager::AddContact(ClientData& clientData, const char* buf, unsigned int length)
{
	uint32_t encNickLen = (uint8_t)buf[4];
	if(encNickLen > 32)
	{
		SendError(clientData, "Invalid request");
		VERBOSE_PRINT("AddContact: Incorrect length\n");
		FullLogout(&clientData);
		return false;
	}

	if(length != 4 + 1 + encNickLen)
	{
		SendError(clientData, "Invalid request");
		VERBOSE_PRINT("AddContact: Incorrect length\n");
		return false;
	}

	//ADD PERSON TO CONTACTS (NICKNAME OPTIONAL)
	if(clientData.userID != 0)
	{
		uint32_t contactID = ntohl(*((uint32_t*)buf));
		if(!servDB->UserExists(contactID))
		{
			SendError(clientData, "User does not exist on this server");
			VERBOSE_PRINT("AddContact: User doesn't exist\n");
			return false;
		}

		if(contactID == clientData.userID)
		{
			SendError(clientData, "That's sad...");
			return false;
		}

		const char* encNickname = (length == 5 + 16 || length == 5 + 32)? &buf[5] : 0;
		bool succeed = servDB->AddUserToContacts(clientData.userID, contactID, encNickname, encNickLen);
		if(!succeed)
		{
			SendError(clientData, "Couldn't add user to contacts: Internal error");
			cerr << servDB->GetError() << "\n";
			return false;
		}
		else
		{
			WORKSPACE[0] = 0;
			SendEncrypted(clientData, 5, WORKSPACE, 0);
			VERBOSE_PRINT("User %d added %d as a contact\n", clientData.userID, contactID);
			return true;
		}
	}
	else
	{
		SendError(clientData, "Not signed in");
		VERBOSE_PRINT("AddContact: User not signed in\n");
		return false;
	}
}

bool RequestManager::CreateConvWithUser(ClientData& clientData, const char* buf, unsigned int length)
{
	if(length != 4 + 16 + 48 + 16 + 48)
	{
		SendError(clientData, "Invalid request");
		VERBOSE_PRINT("CreateConvWithUser: Incorrect length\n");
		return false;
	}

	//CREATE CONVERSATION WITH USER (IF USER HAS ADDED BACK)
	if(clientData.userID != 0)
	{
		uint32_t contactID = ntohl(*((uint32_t*)buf));
		if(!servDB->UserExists(contactID))
		{
			SendError(clientData, "User does not exist on this server");
			VERBOSE_PRINT("CreateConvWithUser: User doesn't exist\n");
			return false;
		}

		if(servDB->UserAddedContact(contactID, clientData.userID))
		{
			uint32_t convID = servDB->CreateConversation(clientData.userID, (const uint8_t*)&buf[4], (const uint8_t*)&buf[20]);
			if(convID == 0)
			{
				SendError(clientData, "Couldn't create conversation: Internal error");
				cerr << servDB->GetError() << "\n";
				return false;
			}

			bool succeed = servDB->AddUserToConv(convID, contactID, (const uint8_t*)&buf[68], (const uint8_t*)&buf[84]);
			if(!succeed)
			{
				SendError(clientData, "Couldn't add user to conversation: Internal error");
				cerr << servDB->GetError() << "\n";
				return false;
			}
			else
			{
				uint32_t c_net = htonl(convID);
				SendEncrypted(clientData, 6, &c_net, 4);

				if(servDB->IsOnline(contactID))
				{
					ClientData cd = clients[servDB->FetchIndex(contactID)];
					SendUserNewConv(cd, convID, -6);
				}
				VERBOSE_PRINT("Created conversation ID %d\n", convID);
				return true;
			}
		}
		else
		{
			SendError(clientData, "Contact has not added you back yet");
			VERBOSE_PRINT("CreateConvWithUser: Contact hasn't added user back\n");
			return false;
		}
	}
	else
	{
		SendError(clientData, "Not signed in");
		VERBOSE_PRINT("CreateConvWithUser: Not signed in\n");
		return false;
	}
}

bool RequestManager::AddUserToConv(ClientData& clientData, const char* buf, unsigned int length)
{
	if(length != 4 + 4 + 16 + 48)
	{
		SendError(clientData, "Invalid request");
		VERBOSE_PRINT("AddUserToConv: Incorrect length\n");
		return false;
	}

	//ADD USER TO CONVERSATION (IF USER HAS ADDED ALL OTHER PARTIES IN CONV, AND EVERYONE HAS ADDED USER)
	if(clientData.userID != 0)
	{
		uint32_t convID = ntohl(*((uint32_t*)buf));
		uint32_t contactID = ntohl(*((uint32_t*)&buf[4]));
		if(!servDB->UserExists(contactID))
		{
			SendError(clientData, "User does not exist on this server");
			VERBOSE_PRINT("AddUserToConv: User doesn't exist\n");
			return false;
		}
		if(!servDB->UserInConv(clientData.userID, convID))
		{
			SendError(clientData, "You are not a member of this conversation");
			VERBOSE_PRINT("AddUserToConv: User is not a member of conv\n");
			return false;
		}

		uint32_t users_num;
		uint32_t* users = servDB->FetchUsersInConv(convID, users_num);
		if(users == 0)
		{
			SendError(clientData, "Couldn't add user to conversation: Internal error");
			cerr << servDB->GetError() << "\n";
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
			bool succeed = servDB->AddUserToConv(convID, contactID, (const uint8_t*)&buf[8], (const uint8_t*)&buf[24]);
			if(!succeed)
			{
				SendError(clientData, "Couldn't add contact to conversation: Internal error");
				cerr << servDB->GetError() << "\n";
				return false;
			}
			else
			{
				WORKSPACE[0] = 0;
				SendEncrypted(clientData, 7, WORKSPACE, 0);

				if(servDB->IsOnline(contactID))
				{
					ClientData cd = clients[servDB->FetchIndex(contactID)];
					SendUserNewConv(cd, convID, -7);
				}
				VERBOSE_PRINT("User %d added to conv %d\n", contactID, convID);
				return true;
			}
		}
		else
		{
			SendError(clientData, err);
			VERBOSE_PRINT("AddUserToConv: Mutual trust error\n");
			return false;
		}
	}
	else
	{
		SendError(clientData, "Not signed in");
		VERBOSE_PRINT("AddUserToConv: User not signed in\n");
		return false;
	}
}

bool RequestManager::SendMessage(ClientData& clientData, const char* buf, unsigned int length)
{
	uint32_t msgLen = ntohl(*((uint32_t*)&buf[4]));
	if(msgLen > 4096)
	{
		SendError(clientData, "Invalid request");
		VERBOSE_PRINT("SendMessage: Incorrect length\n");
		FullLogout(&clientData);
		return false;
	}

	if(length != 4 + 4 + 16 + msgLen)
	{
		SendError(clientData, "Invalid request");
		VERBOSE_PRINT("SendMessage: Incorrect length\n");
		return false;
	}

	//BROADCAST MESSAGE TO ALL USERS OF CONVERSATION THAT ARE ONLINE, INCREASE CONV EOF
	if(clientData.userID != 0)
	{
		uint32_t convID = ntohl(*((uint32_t*)buf));
		uint32_t senderID = clientData.userID;

		if(!servDB->UserInConv(senderID, convID))
		{
			SendError(clientData, "You are not a member of this conversation");
			VERBOSE_PRINT("SendMessage: User is not a member of conv\n");
			return false;
		}

		uint32_t senderNet = htonl(senderID);
		memcpy(WORKSPACE, buf, 8);												//Copy convID and msgLen to broadcast msg
		memcpy(&WORKSPACE[8], &senderNet, 4);									//Copy senderID
		memcpy(&WORKSPACE[12], &buf[8], 16 + msgLen);							//Copy IV + msg

		stringstream ss;
		ss << convID;
		ofstream convFile(ss.str().c_str(), ios::out | ios::app | ios::binary);
		if(convFile.is_open())
		{
			convFile.write("\xFF", 1);
			convFile.write(&WORKSPACE[4], 4 + 4 + 16 + msgLen);
			convFile.close();
		}
		else
		{
			SendError(clientData, "Message not saved: Internal error");
			cerr << "Couldn't open conv " << convID << " file\n";
			return false;
		}
		if(!servDB->IncreaseConvEOF(convID, 1 + 4 + 4 + 16 + msgLen))
			cerr << servDB->GetError() << "\n";

		//TODO: Make quick index files/tables for easily jumping back 100-ish messages from current file or user eof

		uint32_t n = 0;
		uint32_t* users = servDB->FetchUsersInConv(convID, n);
		if(users == 0)
		{
			cerr << servDB->GetError() << "\n";
			return false;
		}

		for(unsigned int j = 0; j < n; j++)
		{
			if(servDB->IsOnline(users[j]))
			{
				ClientData cd = clients[servDB->FetchIndex(users[j])];
				char type = (users[j] == senderID)? 8 : -1;
				SendEncrypted(cd, type, WORKSPACE, 4 + 4 + 4 + 16 + msgLen);
			}
		}
		delete[] users;
		VERBOSE_PRINT("Message sent by user %d in conv %d\n", senderID, convID);
		return true;
	}
	else
	{
		SendError(clientData, "Not signed in");
		VERBOSE_PRINT("SendMessage: User not signed in\n");
		return false;
	}
}

bool RequestManager::SendContacts(ClientData& clientData)
{
	//SEND ALL CONTACTS AND THEIR ENCRYPTED NICKNAMES (IF NOT NULL)
	if(clientData.userID != 0)
	{
		uint32_t size;
		char* contacts = servDB->FetchContacts(clientData.userID, size);
		if(contacts == 0)
		{
			SendError(clientData, "Couldn't fetch contacts: Internal error");
			cerr << servDB->GetError() << "\n";
			return false;
		}
		else
		{
			SendEncrypted(clientData, 9, contacts, size);
			VERBOSE_PRINT("Contacts for user %d sent\n", clientData.userID);
			delete[] contacts;
			return true;
		}
	}
	else
	{
		SendError(clientData, "Not signed in");
		VERBOSE_PRINT("SendContacts: User not signed in\n");
		return false;
	}
}

bool RequestManager::RemoveContact(ClientData& clientData, const char* buf, unsigned int length)
{
	if(length != 4)
	{
		SendError(clientData, "Invalid request");
		VERBOSE_PRINT("RemoveContact: Incorreect length\n");
		return false;
	}

	//REMOVE USER FROM CONTACTS
	if(clientData.userID != 0)
	{
		uint32_t contactID = ntohl(*((uint32_t*)buf));
		bool succeed = servDB->RemoveContact(clientData.userID, contactID);
		if(!succeed)
		{
			SendError(clientData, "Couldn't remove contact: Internal error");
			cerr << servDB->GetError() << "\n";
			return false;
		}
		else
		{
			WORKSPACE[0] = 0;
			SendEncrypted(clientData, 10, WORKSPACE, 0);
			VERBOSE_PRINT("RemoveContact: User not signed in\n");
			return true;
		}
	}
	else
	{
		SendError(clientData, "Not signed in");
		VERBOSE_PRINT("RemoveContact: User not signed in\n");
		return false;
	}
}

bool RequestManager::LeaveConv(ClientData& clientData, const char* buf, unsigned int length)
{
	if(length != 4)
	{
		SendError(clientData, "Invalid request");
		VERBOSE_PRINT("LeaveConv: Incorrect length\n");
		return false;
	}

	//LEAVE A CONVERSATION
	if(clientData.userID != 0)
	{
		uint32_t convID = ntohl(*((uint32_t*)buf));
		bool succeed = servDB->LeaveConv(convID, clientData.userID);
		if(!succeed)
		{
			SendError(clientData, "Couldn't leave conversation: Internal error");
			cerr << servDB->GetError() << "\n";
			return false;
		}
		else
		{
			WORKSPACE[0] = 0;
			SendEncrypted(clientData, 11, WORKSPACE, 0);
			VERBOSE_PRINT("User %d left conv %d\n", clientData.userID, convID);
			return true;
		}
	}
	else
	{
		SendError(clientData, "Not signed in");
		VERBOSE_PRINT("LeaveConv: User not signed in\n");
		return false;
	}
}

bool RequestManager::SendUserConvInfo(ClientData& clientData)
{
	//SEND BACK FORMATTED CONVS LIST WITH DETAILS
	if(clientData.userID != 0)
	{
		uint32_t convs_num;
		uint32_t* convs = servDB->FetchConvs(clientData.userID, convs_num);
		if(convs == 0)
		{
			SendError(clientData, "Couldn't fetch conversation info: Internal error");
			cerr << servDB->GetError() << "\n";
			return false;
		}

		//ASSUMING SIZE WILL BE LESS THAN MAX_BUFFER_SIZE...
		//TODO:(...should implement piecewise SendEncrypted using last block as new IV to do CBC across multiple sends())
		uint32_t size = 0;
		bool failed = false;
		for(unsigned int j = 0; j < convs_num; j++)
		{
			uint32_t conv_net = htonl(convs[j]);
			memcpy(&WORKSPACE[size], &conv_net, 4);
			size += 4;

			uint32_t init_net = htonl((uint32_t)servDB->FetchInitiator(convs[j]));
			memcpy(&WORKSPACE[size], &init_net, 4);
			size += 4;

			char* iv = servDB->FetchConvIV(convs[j], clientData.userID);
			if(iv == 0)
			{
				SendError(clientData, "Unable to fetch initialization vector: Internal error");
				cerr << servDB->GetError() << "\n";
				failed = true;
				break;
			}
			else
			{
				memcpy(&WORKSPACE[size], iv, 16);
				size += 16;
				delete[] iv;
			}

			char* encSymKey = servDB->FetchSymKey(convs[j], clientData.userID);
			if(encSymKey == 0)
			{
				SendError(clientData, "Unable to fetch symmetric key: Internal error");
				cerr << servDB->GetError() << "\n";
				failed = true;
				break;
			}
			else
			{
				memcpy(&WORKSPACE[size], encSymKey, 48);
				size += 48;
				delete[] encSymKey;
			}

			uint32_t users_num;
			uint32_t* users = servDB->FetchUsersInConv(convs[j], users_num);
			uint32_t users_num_net = htonl(users_num);
			memcpy(&WORKSPACE[size], &users_num_net, 4);
			size += 4;

			for(unsigned int k = 0; k < users_num; k++)
			{
				uint32_t user_net = htonl(users[k]);
				memcpy(&WORKSPACE[size], &user_net, 4);
				size += 4;
			}
			delete[] users;
		}
		delete[] convs;

		if(failed)
			return false;

		SendEncrypted(clientData, 12, WORKSPACE, size);
		VERBOSE_PRINT("Conv info sent\n");
		return true;
	}
	else
	{
		SendError(clientData, "Not signed in");
		VERBOSE_PRINT("SendUserConvInfo: User not signed in\n");
		return false;
	}
}

bool RequestManager::IncreaseUserEOF(ClientData& clientData, const char* buf, unsigned int length)
{
	if(length != 4 + 4)
	{
		SendError(clientData, "Invalid request");
		VERBOSE_PRINT("IncreaseUserEOF: Incorrect length\n");
		return false;
	}

	//INCREASE LAST KNOWN EOF FOR USER IN CONV
	if(clientData.userID != 0)
	{
		uint32_t convID = ntohl(*((uint32_t*)buf));
		if(!servDB->UserInConv(clientData.userID, convID))
		{
			SendError(clientData, "You are not a member of this conversation");
			VERBOSE_PRINT("IncreaseUserEOF: User is not a member of conv\n");
			return false;
		}

		uint32_t increase = ntohl(*((uint32_t*)&buf[4]));
		if(servDB->IncUserConvEOF(clientData.userID, convID, increase))
		{
			WORKSPACE[0] = 0;
			SendEncrypted(clientData, 13, WORKSPACE, 0);
			VERBOSE_PRINT("EOF of conv %d was increased\n", convID);
			return true;
		}
		else
		{
			SendError(clientData, "Unable to increase current conversation progress: Internal error");
			cerr << servDB->GetError() << "\n";
			return false;
		}
	}
	else
	{
		SendError(clientData, "Not signed in");
		VERBOSE_PRINT("IncreaseUserEOF: User not signed in\n");
		return false;
	}
}

/*bool RequestManager::SendMissedMsgs(ClientData& clientData)
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
		SendEncrypted(clientData, 14, sendBuf, size);
		delete[] sendBuf;

		return true;
	}
	else
	{
		SendError(clientData, "Not signed in");
		return false;
	}
}*/

bool RequestManager::SendMissedConvMsgs(ClientData& clientData, const char* buf, unsigned int length)
{
	if(length != 4)
	{
		SendError(clientData, "Invalid request");
		VERBOSE_PRINT("SendMissedConvMsgs: Incorrect length\n");
		return false;
	}

	//SEND BACK ALL MISSED MESSAGES FOR CONV
	if(clientData.userID != 0)
	{
		uint32_t convID = ntohl(*((uint32_t*)buf));
		if(!servDB->UserInConv(clientData.userID, convID))
		{
			SendError(clientData, "You are not a member of this conversation");
			VERBOSE_PRINT("SendMissedConvMsgs: User is not a member of conv\n");
			return false;
		}

		unsigned int convEOF = servDB->FetchConvEOF(convID);
		unsigned int eof = servDB->FetchUserConvEOF(convID, clientData.userID);
		if(convEOF == (unsigned int)(-1) || eof == (unsigned int)(-1))
		{
			SendError(clientData, "Could not access conversation: Internal error");
			cerr << servDB->GetError() << "\n";
			return false;
		}

		//TODO:Again, can be fixed with multiple send ability for SendEncrypted + index files for less ridiculous requests...
		assert(((convEOF - eof) + 4) <= MAX_BUFFER_SIZE);						//Only works ATM with only one data type :/

		stringstream ss;
		ss << convID;
		ifstream convFile(ss.str().c_str(), ios::in | ios::binary);
		if(convFile.is_open())
		{
			memcpy(WORKSPACE, buf, 4);											//ConvID network byte order
			uint32_t size = 4;
			convFile.seekg(eof, convFile.beg);
			while(eof < convEOF)
			{
				convFile.read(&WORKSPACE[size], 1);
				if(WORKSPACE[size] == '\xFF')									//Regular text message
				{
					size++;
					convFile.read(&WORKSPACE[size], 4 + 4 + 16);				//Read msgLen + senderID + IV
					uint32_t msgLen = ntohl(*((uint32_t*)&WORKSPACE[size]));
					convFile.read(&WORKSPACE[size + 24], msgLen);
					size += 4 + 4 + 16 + msgLen;
					eof += 1 + 4 + 4 + 16 + msgLen;
				}
				else
				{
					SendError(clientData, "Couldn't fetch messages: Internal error\nPossible fix by clearing message history for conversation");
					cerr << "Unknown message type " << +WORKSPACE[size] << " at position " << eof << endl;
					convFile.close();
					return false;
				}
			}

			SendEncrypted(clientData, 14, WORKSPACE, size);
			convFile.close();
			VERBOSE_PRINT("User %d received missed messages for %d\n", clientData.userID, convID);
			return true;
		}
		else
		{
			SendError(clientData, "Couldn't fetch messages: Internal error");
			cerr << "Couldn't open conv " << convID << " file\n";
			return false;
		}
	}
	else
	{
		SendError(clientData, "Not signed in");
		VERBOSE_PRINT("SendMissedConvMsgs: User not signed in\n");
		return false;
	}
}

bool RequestManager::UpdateNickname(ClientData& clientData, const char* buf, unsigned int length)
{
	if(length < 4 + 1)															//Guarentee we can access elements 0-4
	{
		SendError(clientData, "Invalid request");
		VERBOSE_PRINT("UpdateNickname: Incorrect length\n");
		return false;
	}

	//UPDATE CONTACT'S NICKNAME
	if(clientData.userID != 0)
	{
		uint32_t contactID = ntohl(*((uint32_t*)buf));
		if(servDB->UserAddedContact(clientData.userID, contactID))
		{
			SendError(clientData, "This user hasn't been added");
			VERBOSE_PRINT("UpdateNickname: User hasn't added contact\n");
			return false;
		}

		uint8_t encNickLen = (uint8_t)buf[4];
		if(length != 4 + 1 + encNickLen)
		{
			SendError(clientData, "Invalid request");
			VERBOSE_PRINT("UpdateNickname: Incorrect length\n");
			return false;
		}

		if(servDB->UpdateContact(clientData.userID, contactID, &buf[5], encNickLen))
		{
			WORKSPACE[0] = 0;
			SendEncrypted(clientData, 15, WORKSPACE, 0);
			VERBOSE_PRINT("User updated contact's nickname length\n");
			return true;
		}
		else
		{
			SendError(clientData, "Couldn't update nickname: Internal error");
			cerr << servDB->GetError() << "\n";
			return false;
		}
	}
	else
	{
		SendError(clientData, "Not signed in");
		VERBOSE_PRINT("UpdateNickname: User not signed in\n");
		return false;
	}
}

bool RequestManager::SetUserEOF(ClientData& clientData, const char* buf, unsigned int length)
{
	if(length != 4 + 4)
	{
		SendError(clientData, "Invalid request");
		VERBOSE_PRINT("SetUserEOF: Incorrect length\n");
		return false;
	}

	//SET LAST KNOWN EOF FOR USER IN CONV TO X
	if(clientData.userID != 0)
	{
		uint32_t convID = ntohl(*((uint32_t*)buf));
		uint32_t val = ntohl(*((uint32_t*)&buf[4]));

		if(servDB->SetUserConvEOF(clientData.userID, convID, val))
		{
			WORKSPACE[0] = 0;
			SendEncrypted(clientData, 16, WORKSPACE, 0);
			VERBOSE_PRINT("User %d set eof of conv %d\n", clientData.userID, convID);
			return true;
		}
		else
		{
			SendError(clientData, "Couldn't set conversation progress: Internal error");
			cerr << servDB->GetError() << "\n";
			return false;
		}
	}
	else
	{
		SendError(clientData, "Not signed in");
		VERBOSE_PRINT("SetUserEOF: User not signed in\n");
		return false;
	}
}


//	HELPER FUNCTIONS
//------------------------------------------------------------------------------------------------------------------------------
int RequestManager::recvr(int socket, void* buffer, int length, int flags)
{
	int i = 0;
	char* b = (char*)buffer;
	while(i < length)
	{
		int n = recv(socket, &b[i], length-i, flags);
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
		memset(clientData->key, 0, 32);
		delete[] clientData->key;
		clientData->key = 0;
		clientData->haveSymmetricKey = false;
	}
}

void RequestManager::SendUserNewConv(ClientData& clientData, uint32_t convID, char type)
{
	uint32_t conv_net = htonl(convID);
	memcpy(WORKSPACE, &conv_net, 4);
	uint32_t init_net = htonl((uint32_t)servDB->FetchInitiator(convID));
	memcpy(&WORKSPACE[4], &init_net, 4);

	char* iv = servDB->FetchConvIV(convID, clientData.userID);
	if(iv == 0)
	{
		//SendError(clientData, "Unable to fetch initialization vector: Internal error");
		cerr << servDB->GetError() << "\n";
		return;
	}
	else
	{
		memcpy(&WORKSPACE[8], iv, 16);
		delete[] iv;
	}

	char* encSymKey = servDB->FetchSymKey(convID, clientData.userID);
	if(encSymKey == 0)
	{
		cerr << servDB->GetError() << "\n";
		return;
	}
	else
	{
		memcpy(&WORKSPACE[24], encSymKey, 48);
		delete[] encSymKey;
	}

	uint32_t users_num;
	uint32_t* users = servDB->FetchUsersInConv(convID, users_num);
	if(users == 0)
	{
		cerr << servDB->GetError() << "\n";
		return;
	}

	uint32_t users_num_net = htonl(users_num);
	memcpy(&WORKSPACE[72], &users_num_net, 4);
	for(unsigned int k = 0; k < users_num; k++)
	{
		uint32_t user_net = htonl(users[k]);
		memcpy(&WORKSPACE[76 + (4 * k)], &user_net, 4);
	}
	delete[] users;

	SendEncrypted(clientData, type, WORKSPACE, 76 + (4 * users_num));
	return;
}

void RequestManager::SendEncrypted(ClientData& clientData, char type, const void* buffer, unsigned int len)
{
	unsigned char header[21];
	header[0] = type;
	unsigned int headerSize = 5;
	const char* sendBuffer = (const char*)buffer;

	if(HaveSymmetricKey(clientData))											//Encrypt if we have a shared key
	{
		unsigned int newLen = PaddedSize(len);
		headerSize += 16;

		fprng->GenerateBlocks(&header[5] ,1);
		aes.Encrypt((const char*)buffer, len, &header[5], (const uint8_t*)clientData.key, WORKSPACE);
		len = newLen;
		sendBuffer = WORKSPACE;
	}

	uint32_t size_net = htonl(len);
	memcpy(&header[1], &size_net, 4);

	send(clientData.sock, header, headerSize, 0);
	send(clientData.sock, sendBuffer, len, 0);
}

void RequestManager::SendError(ClientData& clientData, string errMsg)
{
	SendEncrypted(clientData, 0, errMsg.c_str(), errMsg.length()+1);			//Include null terminator...
}

bool RequestManager::CreateSharedKey(uint32_t userID, char* keyBuffer)
{
	char* userPubKey = servDB->FetchPublicKey(userID);
	if(userPubKey == 0)
		return false;

	curve25519_donna((unsigned char*)keyBuffer, (const unsigned char*)servPrivate, (const unsigned char*)userPubKey);
	delete[] userPubKey;
	return true;
}

bool RequestManager::HaveSymmetricKey(ClientData& clientData)
{
	return (clientData.haveSymmetricKey && clientData.key != NULL);				//The former should imply the later, but best to make sure
}

bool RequestManager::EncryptedRequest(char type)
{
	bool requests[17] = {false, false, false, false, true, true, true, true, true, false, true, true, false, true, true, false, true};
	return requests[type];
}

