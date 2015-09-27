#include "ServDB.h"

ServDB::ServDB(const char* db, const char* server, const char* user, const char* password, unsigned int port = 0)
{
	conn = mysqlpp::Connection(false);
	err.clear();
	if(!conn.connect(db, server, user, password, port))
	{
		err = std::string("DB connection failed: ") + conn.error();
		return;
	}
	
	mysqlpp::Query query = conn.query();
	query << "CREATE TABLE IF NOT EXISTS users ( user_id int NOT NULL AUTO_INCREMENT, pub_key char(44) NOT NULL, priv_key char(64) NOT NULL, iv char(24) NOT NULL, salt char(24) NOT NULL, sock_num mediumint NOT NULL, random_int int NOT NULL, PRIMARY KEY (user_id) )";
	mysqlpp::SimpleResult res = query.execute();
	if(!res)
	{
		err = std::string("users table creation failed: ") + query.error();
		return;
	}
	query.reset();
	query << "CREATE TABLE IF NOT EXISTS conversations ( conv_id int NOT NULL AUTO_INCREMENT, creator_id int NOT NULL, msg_eof int NOT NULL, PRIMARY KEY (conv_id) )";
	res = query.execute();
	if(!res)
	{
		err = std::string("conversations table creation failed: ") + query.error();
		return;
	}
	query.reset();
	query << "SET GLOBAL wait_timeout=2419200";
	res = query.execute();
	if(!res)
	{
		err = std::string("Could not set wait_timeout: ") + query.error();
		return;
	}
	query.reset();
	query << "SET GLOBAL interactive_timeout=2419200";
	res = query.execute();
	if(!res)
		err = std::string("Could not set interactive_timeout") + query.error();
	return;
}

std::string ServDB::GetError()
{
	return err;
}

unsigned int ServDB::CreateUser(const uint8_t publicKey[32], const uint8_t encPrivateKey[48], const uint8_t iv[16], const uint8_t salt[16])
{
	mysqlpp::Query query = conn.query();
	
	//Convert to base64
	char* pub_key = Base64Encode(publicKey, 32);
	char* priv_key = Base64Encode(encPrivateKey, 48);
	char* iv64 = Base64Encode(iv, 16);
	char* salt64 = Base64Encode(salt, 16);
	
	//Insert that huge thing right there!!
	query << "INSERT INTO users (user_id, pub_key, priv_key, iv, salt, sock_num, random_int) VALUES \
	(\"\",\"" << pub_key << "\", \"" << priv_key << "\", \"" << iv64 << "\", \"" << salt64 << "\", \"0\", \"1\")";
	
	//Free memory Base64Encode took
	delete[] pub_key;
	delete[] priv_key;
	delete[] iv64;
	delete[] salt64;
	
	//Execute and save result
	mysqlpp::SimpleResult res = query.execute();
	if(!res)
	{
		err = "User creation failed";
		return 0;
	}
	unsigned int userID = res.insert_id();
	query.reset();
	
	//I feel like assuming this just works...
	query << "CREATE TABLE UserConvs_" << userID << "(conv_id INT not null, last_msg_eof INT not null, PRIMARY KEY (conv_id))";
	query.execute();
	query.reset();
	query << "CREATE TABLE UserContacts_" << userID << "(user_id INT not null, nickname VARCHAR(44) null, PRIMARY KEY (user_id))";
	query.execute();
	
	return userID;
}

char* ServDB::FetchPublicKey(unsigned int userID)
{
	mysqlpp::Query query = conn.query();
	query << "SELECT pub_key FROM users WHERE user_id = " << mysqlpp::quote << userID;
	if(mysqlpp::StoreQueryResult res = query.store())
	{
		unsigned int len;
		char* r = Base64Decode(res[0][0].c_str(), len);
		if(r == 0 || len != 32)
		{
			err = "Bad storage, corrupted value ";
			err += res[0][0].c_str();
			if(r)
				delete[] r;
			
			return 0;
		}
		return r;
	}
	else
	{
		err = std::string("FetchPublicKey: ") + query.error();
		return 0;
	}
}

char* ServDB::FetchEncPrivateKey(unsigned int userID)
{
	mysqlpp::Query query = conn.query();
	query << "SELECT priv_key FROM users WHERE user_id = " << mysqlpp::quote << userID;
	if(mysqlpp::StoreQueryResult res = query.store())
	{
		unsigned int len;
		char* r = Base64Decode(res[0][0].c_str(), len);
		if(r == 0 || len != 48)
		{
			err = "Bad storage, corrupted value";
			if(r)
				delete[] r;
			return 0;
		}
		return r;
	}
	else
	{
		err = std::string("FetchEncPrivateKey: ") + query.error();
		return 0;
	}
}

char* ServDB::FetchIV(unsigned int userID)
{
	mysqlpp::Query query = conn.query();
	query << "SELECT iv FROM users WHERE user_id = " << mysqlpp::quote << userID;
	if(mysqlpp::StoreQueryResult res = query.store())
	{
		unsigned int len;
		char* r = Base64Decode(res[0][0].c_str(), len);
		if(r == 0 || len != 16)
		{
			err = "Bad storage, corrupted value";
			if(r)
				delete[] r;
			return 0;
		}
		return r;
	}
	else
	{
		err = std::string("FetchIV: ") + query.error();
		return 0;
	}
}

char* ServDB::FetchSalt(unsigned int userID)
{
	mysqlpp::Query query = conn.query();
	query << "SELECT salt FROM users WHERE user_id = " << mysqlpp::quote << userID;
	if(mysqlpp::StoreQueryResult res = query.store())
	{
		unsigned int len;
		char* r = Base64Decode(res[0][0].c_str(), len);
		if(r == 0 || len != 16)
		{
			err = "Bad storage, corrupted value";
			if(r)
				delete[] r;
			return 0;
		}
		return r;
	}
	else
	{
		err = std::string("FetchSalt: ") + query.error();
		return 0;
	}
}

unsigned int ServDB::FetchSocket(unsigned int userID)
{
	mysqlpp::Query query = conn.query();
	query << "SELECT sock_num FROM users WHERE user_id = " << mysqlpp::quote << userID;
	if(mysqlpp::StoreQueryResult res = query.store())
	{
		return res[0][0];
	}
	else
	{
		err = std::string("FetchSocket: ") + query.error();
		return 0;
	}
}

unsigned int ServDB::FetchRandomInt(unsigned int userID)
{
	mysqlpp::Query query = conn.query();
	query << "SELECT random_int FROM users WHERE user_id = " << mysqlpp::quote << userID;
	if(mysqlpp::StoreQueryResult res = query.store())
	{
		return res[0][0];
	}
	else
	{
		err = std::string("FetchRandomInt: ") + query.error();
		return 0;
	}
}

bool ServDB::AddUserToContacts(unsigned int userID, unsigned int contactID, const char* nickname = 0, unsigned int nickLen = 0)
{
	mysqlpp::Query query = conn.query();
	query << "INSERT INTO UserContacts_" << userID << " (user_id, nickname) VALUES (";
	query << mysqlpp::quote << contactID << ", ";
	if(nickname != 0 && nickLen != 0)
	{
		char* n64 = Base64Encode(nickname, nickLen);
		query << mysqlpp::quote << n64 << ")";
		delete[] n64;
	}
	else
	{
		query << "NULL)";
	}
	
	mysqlpp::SimpleResult res = query.execute();
	if(!res)
	{
		err = "Could not add contact";
		return false;
	}
	return true;
}

bool ServDB::UpdateContact(unsigned int userID, unsigned int contactID, const char* nickname = 0, unsigned int nickLen = 0)
{
	mysqlpp::Query query = conn.query();
	query << "UPDATE UserContacts_" << userID << " set nickname=";
	if(nickname != 0 && nickLen != 0)
	{
		char* n64 = Base64Encode(nickname, nickLen);
		query << mysqlpp::quote << n64;
		delete[] n64;
	}
	else
	{
		query << "NULL";
	}
	query << " WHERE user_id=" << mysqlpp::quote << contactID;
	
	mysqlpp::SimpleResult res = query.execute();
	if(!res)
	{
		err = "Could not add contact";
		return false;
	}
	return true;
}

unsigned int ServDB::CreateConversation(unsigned int userID, const uint8_t iv[16], const uint8_t encSymKey[48])
{
	mysqlpp::Query query = conn.query();
	query << "INSERT INTO conversations (conv_id, creator_id, msg_eof) VALUES \
	(\"\"," << mysqlpp::quote << userID << ", \"0\")";
	
	//Execute and save result
	mysqlpp::SimpleResult res = query.execute();
	if(!res)
	{
		err = "Conversation creation failed";
		return 0;
	}
	unsigned int convID = res.insert_id();
	query.reset();
	
	query << "INSERT INTO UserConvs_" << userID << "(conv_id, last_msg_eof) VALUES \
	(" << mysqlpp::quote << convID << ", \"0\")";
	res = query.execute();
	if(!res)
	{
		err = "Conversation creation failed";
		//NEED CLEAN UP
		return 0;
	}
	query.reset();
	
	query << "CREATE TABLE Conv_" << convID << "(user_id INT not null, sym_key CHAR(64) not null, iv CHAR(24) not null, PRIMARY KEY (user_id))";
	res = query.execute();
	if(!res)
	{
		err = "Conversation creation failed";
		//NEED CLEAN UP
		return 0;
	}
	query.reset();
	
	char* sym_key = Base64Encode(encSymKey, 48);
	char* iv64 = Base64Encode(iv, 16);
	query << "INSERT INTO Conv_" << convID << "(user_id, sym_key, iv) VALUES (" \
		<< mysqlpp::quote << userID << ", " << mysqlpp::quote << sym_key << ", " << mysqlpp::quote << iv64 << ")";
	res = query.execute();
	if(!res)
	{
		err = "Conversation creation failed";
		//NEED CLEAN UP
		return 0;
	}
	delete[] sym_key;
	delete[] iv64;
	
	return convID;
}

bool ServDB::AddUserToConv(unsigned int convID, unsigned int userID, const uint8_t iv[16], const uint8_t encSymKey[48])
{
	mysqlpp::Query query = conn.query();
	
	char* sym_key = Base64Encode(encSymKey, 48);
	char* iv64 = Base64Encode(iv, 16);
	query << "INSERT INTO Conv_" << convID << "(user_id, sym_key, iv) VALUES \
	(" << mysqlpp::quote << userID << ", " << mysqlpp::quote << sym_key << ", " << mysqlpp::quote << iv64 << ")";
	
	//Execute and save result
	mysqlpp::SimpleResult res = query.execute();
	query.reset();
	
	delete[] sym_key;
	delete[] iv64;
	
	if(!res)
	{
		std::stringstream ss;
		ss << "User addition to conv " << convID << "failed";
		err = ss.str();
		return false;
	}
	
	query << "INSERT INTO UserConvs_" << userID << "(conv_id, last_msg_eof) VALUES \
	(" << mysqlpp::quote << convID << ", \"0\")";
	query.execute();
	
	return true;
}

unsigned int ServDB::FetchInitiator(unsigned int convID)
{
	mysqlpp::Query query = conn.query();
	query << "SELECT creator_id FROM conversations WHERE conv_id = " << mysqlpp::quote << convID;
	if(mysqlpp::StoreQueryResult res = query.store())
	{
		return res[0][0];
	}
	else
	{
		err = std::string("FetchInitiator: ") + query.error();
		return 0;
	}
}

char* ServDB::FetchContacts(unsigned int userID, unsigned int& size)
{
	mysqlpp::Query query = conn.query();
	query << "SELECT * FROM UserContacts_" << userID;
	if(mysqlpp::StoreQueryResult res = query.store())
	{
		size = res.num_rows();
		if(size == 0)
		{
			err = "No contacts added";
			return 0;
		}
		
		char** rows = new char*[size];
		unsigned int total = 0;
		for(unsigned int i = 0; i < size; i++)
		{
			if(res[i][1].is_null())
			{
				rows[i] = new char[37];
				uint32_t contactID = res[i][0];
				char* publicKey = FetchPublicKey(contactID);
				contactID = htonl(contactID);
				memcpy(rows[i], &contactID, 4);
				memcpy(&rows[i][4], publicKey, 32);
				rows[i][36] = '\0';
				
				total += 37;
				delete[] publicKey;
			}
			else
			{
				unsigned int len;
				char* nickname = Base64Decode(res[i][1].c_str(), len);
				if(nickname == 0 || (len % 16) != 0)
				{
					delete[] nickname;
					std::stringstream ss;
					ss << "Bad storage, corrupted nickname for contact " << res[i][0];
					err = ss.str();
					
					for(unsigned int j = 0; j < i; j++)
					{
						delete[] rows[i];
					}
					delete[] rows;
					size = 0;
					return 0;
				}
				
				rows[i] = new char[37 + len];
				uint32_t contactID = res[i][0];
				char* publicKey = FetchPublicKey(contactID);
				contactID = htonl(contactID);
				memcpy(rows[i], &contactID, 4);
				memcpy(&rows[i][4], publicKey, 32);
				rows[i][36] = (unsigned char)len;
				memcpy(&rows[i][37], nickname, len);
				
				total += 37 + len;
				delete[] nickname;
				delete[] publicKey;
			}
		}
		
		char* contacts = new char[total];
		unsigned int x = 0;
		for(unsigned int i = 0; i < size; i++)
		{
			unsigned int len = (uint8_t)rows[i][36];
			memcpy(&contacts[x], rows[i], 37 + len);
			x += 37 + len;
			delete[] rows[i];
		}
		delete[] rows;
		size = total;
		return contacts;
	}
	else
	{
		err = query.error();
		size = 0;
		return 0;
	}
}

unsigned int* ServDB::FetchConvs(unsigned int userID, unsigned int& n)	
{
	mysqlpp::Query query = conn.query();
	query << "SELECT conv_id FROM UserConvs_" << userID;
	if(mysqlpp::StoreQueryResult res = query.store())
	{
		n = res.num_rows();
		if(n == 0)
		{
			err = "No conversations created";
			return 0;
		}
		
		unsigned int* convs = new unsigned int[n];
		for(unsigned int i = 0; i < n; i++)
		{
			convs[i] = res[i][0];
		}
		return convs;
	}
	else
	{
		err = query.error();
		n = 0;
		return 0;
	}
}

unsigned int* ServDB::FetchUsersInConv(unsigned int convID, unsigned int& n)
{
	mysqlpp::Query query = conn.query();
	query << "SELECT user_id FROM Conv_" << convID;
	if(mysqlpp::StoreQueryResult res = query.store())
	{
		n = res.num_rows();
		unsigned int* users = new unsigned int[n];
		for(unsigned int i = 0; i < n; i++)
		{
			users[i] = (unsigned int)res[i][0];
		}
		return users;
	}
	else
	{
		err = std::string("FetchUsersInConv: ") + query.error();
		n = 0;
		return 0;
	}
}

unsigned int ServDB::FetchConvEOF(unsigned int convID)
{
	mysqlpp::Query query = conn.query();
	query << "SELECT msg_eof FROM conversations WHERE conv_id = " << mysqlpp::quote << convID;
	if(mysqlpp::StoreQueryResult res = query.store())
	{
		return res[0][0];
	}
	else
	{
		err = std::string("FetchConvEOF: ") + query.error();
		return 4294967295;
	}
}

unsigned int ServDB::FetchConvUserDif(unsigned int convID, unsigned int userID)
{
	mysqlpp::Query query = conn.query();
	query << "SELECT last_msg_eof FROM UserConvs_" << userID << " WHERE conv_id = " << mysqlpp::quote << convID;
	if(mysqlpp::StoreQueryResult res = query.store())
	{
		unsigned int convLen = FetchConvEOF(convID);
		if(convLen == 4294967295)		//-1
			return 4294967295;
		else
			return (convLen - (unsigned int)res[0][0]);
	}
	else
	{
		err = std::string("FetchConvUserDif: ") + query.error();
		return 4294967295;
	}
}

char* ServDB::FetchSymKey(unsigned int convID, unsigned int userID)
{
	mysqlpp::Query query = conn.query();
	query << "SELECT sym_key FROM Conv_" << convID << " WHERE user_id = " << mysqlpp::quote << userID;
	if(mysqlpp::StoreQueryResult res = query.store())
	{
		unsigned int len;
		char* r = Base64Decode(res[0][0].c_str(), len);
		if(r == 0 || len != 48)
		{
			err = "Bad storage, corrupted value ";
			err += res[0][0].c_str();
			if(r)
				delete[] r;
			return 0;
		}
		return r;
	}
	else
	{
		err = std::string("FetchSymKey: ") + query.error();
		return 0;
	}
}

char* ServDB::FetchConvIV(unsigned int convID, unsigned int userID)
{
	mysqlpp::Query query = conn.query();
	query << "SELECT iv FROM Conv_" << convID << " WHERE user_id = " << mysqlpp::quote << userID;
	if(mysqlpp::StoreQueryResult res = query.store())
	{
		unsigned int len;
		char* r = Base64Decode(res[0][0].c_str(), len);
		if(r == 0 || len != 16)
		{
			err = "Bad storage, corrupted value ";
			err += res[0][0].c_str();
			if(r)
				delete[] r;
			return 0;
		}
		return r;
	}
	else
	{
		err = std::string("FetchConvIV: ") + query.error();
		return 0;
	}
}

bool ServDB::RemoveContact(unsigned int userID, unsigned int contactID)
{
	mysqlpp::Query query = conn.query();
	query << "DELETE FROM UserContacts_" << userID << " WHERE user_id=" << mysqlpp::quote << contactID;
	mysqlpp::SimpleResult res = query.execute();
	if(!res)
	{
		err = "Remove contact failed";
		return false;
	}
	return true;
}

bool ServDB::LeaveConv(unsigned int convID, unsigned int userID)
{
	mysqlpp::Query query = conn.query();
	query << "DELETE FROM UserConvs_" << userID << " WHERE conv_id=" << mysqlpp::quote << convID;
	mysqlpp::SimpleResult res = query.execute();
	if(!res)
	{
		err = "Leave conversation failed";
		return false;
	}
	query.reset();
	query << "DELETE FROM Conv_" << convID << " WHERE user_id=" << mysqlpp::quote << userID;
	query.execute();
	return true;
}

bool ServDB::IsOnline(unsigned int userID)
{
	return (FetchSocket(userID) != 0);
}

bool ServDB::UserExists(unsigned int userID)
{
	mysqlpp::Query query = conn.query();
	query << "SELECT user_id FROM users WHERE user_id=" << mysqlpp::quote << userID;
	mysqlpp::StoreQueryResult res = query.store();
	if(res)
	{
		err.clear();
		int n = res.num_rows();
		if(n == 0)
			return false;
		else
			return true;
	}
	else
	{
		err = std::string("Could not check status of user: ") + query.error();
		return false;
	}
}

bool ServDB::LogoutUser(unsigned int userID)
{
	mysqlpp::Query query = conn.query();
	query << "UPDATE users SET sock_num=\"0\" WHERE user_id=" << mysqlpp::quote << userID;
	mysqlpp::SimpleResult res = query.execute();
	if(!res)
	{
		err = "Logout failed";
		return false;
	}
	return true;
}

bool ServDB::LoginUser(unsigned int userID, unsigned int sock)
{
	mysqlpp::Query query = conn.query();
	query << "UPDATE users SET sock_num=" << mysqlpp::quote << sock << ", random_int=random_int+1 WHERE user_id = " << mysqlpp::quote << userID;
	mysqlpp::SimpleResult res = query.execute();
	if(!res)
	{
		err = "Login failed, server issue";
		return false;
	}
	return true;
}

bool ServDB::UserAddedContact(unsigned int userID, unsigned int contactID)
{
	mysqlpp::Query query = conn.query();
	query << "SELECT * FROM UserContacts_" << userID << " WHERE user_id = " << mysqlpp::quote << contactID;
	mysqlpp::StoreQueryResult res = query.store();
	if(res && res.num_rows() == 1)
		return true;
	else
		return false;
}

bool ServDB::IncreaseConvEOF(unsigned int convID, unsigned int size)
{
	mysqlpp::Query query = conn.query();
	query << "UPDATE conversations SET msg_eof=msg_eof+" << size << " WHERE conv_id = " << mysqlpp::quote << convID;
	mysqlpp::SimpleResult res = query.execute();
	if(!res)
	{
		err = "Couldn't increase messages number";
		return false;
	}
	return true;
}

bool ServDB::IncUserConvEOF(unsigned int userID, unsigned int convID, unsigned int size)
{
	mysqlpp::Query query = conn.query();
	query << "UPDATE UserConvs_" << userID << " SET last_msg_eof=last_msg_eof+" << size << " WHERE conv_id = " << mysqlpp::quote << convID;
	mysqlpp::SimpleResult res = query.execute();
	if(!res)
	{
		err = "Couldn't increase messages number";
		return false;
	}
	return true;
}

bool ServDB::Laundry()
{
	mysqlpp::Query query = conn.query();
	query << "UPDATE users SET sock_num=\"0\"";
	mysqlpp::SimpleResult res = query.execute();
	if(!res)
	{
		err = "Couldn't clear all sock_num";
		return false;
	}
	return true;
}