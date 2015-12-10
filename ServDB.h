#ifndef SERVDB_H
#define SERVDB_H

#include <mysql++.h>
#include <string>
#include <iostream>
#include <arpa/inet.h>

#include "crypto/base64.h"

class ServDB
{
private:
	mysqlpp::Connection conn;
	std::string err;
public:
	ServDB(const char* db, const char* server, const char* user, const char* password, unsigned int port = 0);
	std::string GetError();
	unsigned int CreateUser(const uint8_t publicKey[32], const uint8_t encPrivateKey[48], const uint8_t iv[16], const uint8_t salt[16]);
	char* FetchPublicKey(unsigned int userID);
	char* FetchEncPrivateKey(unsigned int userID);
	char* FetchIV(unsigned int userID);
	char* FetchSalt(unsigned int userID);
	unsigned int FetchSocket(unsigned int userID);
	unsigned int FetchRandomInt(unsigned int userID);
	bool AddUserToContacts(unsigned int userID, unsigned int contactID, const char* nickname = 0, unsigned int nickLen = 0);
	bool UpdateContact(unsigned int userID, unsigned int contactID, const char* nickname = 0, unsigned int nickLen = 0);
	unsigned int CreateConversation(unsigned int userID, const uint8_t iv[16], const uint8_t encSymKey[48]);
	bool AddUserToConv(unsigned int convID, unsigned int userID, const uint8_t iv[16], const uint8_t encSymKey[48]);
	unsigned int FetchInitiator(unsigned int convID);
	char* FetchContacts(unsigned int userID, unsigned int& size);
	unsigned int* FetchConvs(unsigned int userID, unsigned int& n);
	unsigned int* FetchUsersInConv(unsigned int convID, unsigned int& n);
	unsigned int FetchConvEOF(unsigned int convID);
	unsigned int FetchUserConvEOF(unsigned int convID, unsigned int userID);
	char* FetchSymKey(unsigned int convID, unsigned int userID);
	char* FetchConvIV(unsigned int convID, unsigned int userID);
	bool RemoveContact(unsigned int userID, unsigned int contactID);
	bool LeaveConv(unsigned int convID, unsigned int userID);
	bool IsOnline(unsigned int userID);
	bool UserExists(unsigned int userID);
	bool ConvExists(unsigned int convID);
	bool UserInConv(unsigned int userID, unsigned int convID);
	bool LogoutUser(unsigned int userID);
	bool LoginUser(unsigned int userID, unsigned int sock);
	bool UserAddedContact(unsigned int userID, unsigned int contactID);
	bool IncreaseConvEOF(unsigned int convID, unsigned int size);
	bool IncUserConvEOF(unsigned int userID, unsigned int convID, unsigned int size);
	bool SetUserConvEOF(unsigned int userID, unsigned int convID, unsigned int size);
	bool Laundry();		//Because its cleaning socks....
};
#endif
