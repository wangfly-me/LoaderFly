#ifndef _AES_H
#define _AES_H
#include <exception>
#include <cstring>
#include <string>
#define BLOCK_SIZE 16
using namespace std;

class AES
{
public:
	enum
	{
		ECB = 0, CBC = 1, CFB = 2
	};

private:
	enum
	{
		DEFAULT_BLOCK_SIZE = 16
	};
	enum
	{
		MAX_BLOCK_SIZE = 32, MAX_ROUNDS = 14, MAX_KC = 8, MAX_BC = 8
	};
public:
	AES();
	virtual ~AES();
private:
	//Key Initialization Flag
	bool m_bKeyInit;
	//Encryption (m_Ke) round key
	int m_Ke[MAX_ROUNDS + 1][MAX_BC];
	//Decryption (m_Kd) round key
	int m_Kd[MAX_ROUNDS + 1][MAX_BC];
	//Key Length
	int m_keylength;
	//Block Size
	int m_blockSize;
	//Number of Rounds
	int m_iROUNDS;
	//Chain Block
	char m_chain0[MAX_BLOCK_SIZE];
	char m_chain[MAX_BLOCK_SIZE];
	//Auxiliary private use buffers
	int tk[MAX_KC];
	int a[MAX_BC];
	int t[MAX_BC];
private:
	void Xor(char* buff, char const* chain);
	void DefEncryptBlock(char const* in, char* result);
	void DefDecryptBlock(char const* in, char* result);
	void EncryptBlock(char const* in, char* result);
	void DecryptBlock(char const* in, char* result);
public:
	void MakeKey(char const* key, char const* chain, int keylength =
		DEFAULT_BLOCK_SIZE, int blockSize = DEFAULT_BLOCK_SIZE);
	void Encrypt(char const* in, char* result, size_t n, int iMode = ECB);
	void Decrypt(char const* in, char* result, size_t n, int iMode = ECB);
};

#endif // __RIJNDAEL_H__