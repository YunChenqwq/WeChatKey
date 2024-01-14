#include<cstdio>
#include<iostream>
#include<Windows.h>
#include<string>
#include <tlhelp32.h>
#include<psapi.h>
#include"WeChatVesion.h"
#pragma comment(lib, "version.lib")
using namespace std;
void RaiseToDebug()
{
	HANDLE hToken;
	HANDLE hProcess = GetCurrentProcess();  // 获取当前进程句柄

	if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		TOKEN_PRIVILEGES tkp;
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid))
		{
			tkp.PrivilegeCount = 1;
			tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			//通知系统修改进程权限
			BOOL bREt = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
		}
		CloseHandle(hToken);
	}
}
void* GetModuleAddress(const char* moduleName) {
	HMODULE hModule = GetModuleHandle(moduleName);
	if (hModule == NULL) {
		// 处理模块未找到的情况  
		return NULL;
	}
	return (void*)hModule;
}

BOOL set_wechat_offsets(char* version, DWORD& account_offset, DWORD& mobile_offset, ULONGLONG& key_offset) {
	int i;
	for (i = 0; i < 20; i++) {
		if (strcmp(version, wechat_version_info[i].version) == 0) {
			account_offset = wechat_version_info[i].account_offset;
			mobile_offset = wechat_version_info[i].mobile_offset;
			key_offset = wechat_version_info[i].key_offset;
			return TRUE;
		}
	}
	return FALSE;
}


int main()
{
	WeChatMeassage msg;
	RaiseToDebug(); //获取DEBUG权限
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	char buffer[32];
	char version[9];
	char szPath[MAX_PATH];
	DWORD WeChatWinDllBase = NULL;
	DWORD WeChatNameOffset = NULL;
	DWORD WeChatMobileOffset = NULL;
	ULONGLONG WeChatKeyOffset = NULL;
	DWORD WeChatAccountOffset = NULL;
	memset(buffer, 0, sizeof buffer);
	memset(version, 0, sizeof version);
	char szAppFullPath[_MAX_PATH] = { 0 };
	if (INVALID_HANDLE_VALUE == hSnapshot) {
		cout << "打开进程句柄失败:" << GetLastError() << endl;
	}
	DWORD oldProtect = 0;
	PROCESSENTRY32 pe = { sizeof(pe) };
	for (BOOL ret = Process32First(hSnapshot, &pe); ret; ret = Process32Next(hSnapshot, &pe)) {
		if (strcmp(pe.szExeFile, "WeChat.exe") == 0) {
			CloseHandle(hSnapshot);
			//printf("ProcessId:%d\n", pe.th32ProcessID);
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);


			HMODULE hMod = NULL;
			DWORD cb = 0;
			if (EnumProcessModules((HANDLE)hProcess, &hMod, sizeof(hMod), &cb))
			{
				//dwRet = GetModuleFileName(hMod, szPath, MAX_PATH);
				DWORD dwRet = GetModuleFileNameEx(hProcess, hMod, szPath, MAX_PATH);
				if (dwRet == 0)
				{

					CloseHandle(hProcess);
				}
				else {
					DWORD dwLen = GetFileVersionInfoSize(szPath, NULL);

					char* pszAppVersion = new char[dwLen + 1];
					if (pszAppVersion)
					{
						memset(pszAppVersion, 0, sizeof(char) * (dwLen + 1));
						GetFileVersionInfoA(szPath, NULL, dwLen, pszAppVersion);
						UINT nLen(0);
						VS_FIXEDFILEINFO* pFileInfo(NULL);
						VerQueryValueA(pszAppVersion, "\\", (LPVOID*)&pFileInfo, &nLen);

						if (pFileInfo)
						{
							sprintf_s(buffer, "%d.%d.%d.%d", HIWORD(pFileInfo->dwFileVersionMS), LOWORD(pFileInfo->dwFileVersionMS), HIWORD(pFileInfo->dwFileVersionLS), LOWORD(pFileInfo->dwFileVersionLS));
							memcpy(version, buffer, 8);
							if (!set_wechat_offsets(version, WeChatAccountOffset, WeChatMobileOffset, WeChatKeyOffset))
							{
								cout << "当前版本为:" << buffer << " 未找到相应偏移信息" << endl;
								return 0;
							}
							cout << "Wechatversion: " << version << endl;
							//printf("WeChatAccountOffset  =  %x\n", WeChatAccountOffset);
							//printf("WeChatMobileOffset  =  %x\n", WeChatMobileOffset);
							//printf("WeChatKeyOffset  =  %x\n", WeChatKeyOffset);

							HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, pe.th32ProcessID);
							MODULEENTRY32 mi;
							mi.dwSize = sizeof(MODULEENTRY32);
							BOOL bRet = Module32First(hModuleSnap, &mi);
							while (bRet)
							{
								WeChatMeassage msg;
								if (strcmp("WeChatWin.dll", mi.szModule) == 0) {
									WeChatWinDllBase = (DWORD)mi.modBaseAddr;
									memset(msg.KeyHexBuffer, 0, sizeof(msg.KeyHexBuffer));
									memset(msg.webchatkey, 0, sizeof(msg.webchatkey));
									memset(msg.KeyAddress, 0, sizeof(msg.KeyAddress));
									SIZE_T nSize = 127;
									CloseHandle(hProcess);
									hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
									DWORD dwOldProt, dwNewProt = 0;
									BOOL nRead = FALSE;
									nRead = ReadProcessMemory(hProcess, (LPCVOID)(mi.modBaseAddr + WeChatAccountOffset), msg.accoutbuffer, 127, &nSize);

									//	VirtualProtectEx(hProcess, (void*)(LPCVOID)(mi.modBaseAddr + WeChatMobileOffset), 127, PAGE_READWRITE, &dwOldProt);
									nRead = ReadProcessMemory(hProcess, (LPCVOID)(mi.modBaseAddr + WeChatMobileOffset), msg.wechatmobile, 127, &nSize);

									//VirtualProtectEx(hProcess, (void*)(LPCVOID)(mi.modBaseAddr + WeChatKeyOffset),256, PAGE_READWRITE, &dwOldProt);

									ULONGLONG BASE2 = (ULONGLONG)mi.modBaseAddr + WeChatKeyOffset;//key的保存地址
								//	cout << BASE2 << endl;
									nRead = ReadProcessMemory(hProcess, (LPCVOID)(mi.modBaseAddr + WeChatKeyOffset), msg.KeyAddress, 5, &nSize);
									ULONGLONG keyBaseValue;
									ReadProcessMemory(hProcess, (LPCVOID)BASE2, &keyBaseValue, sizeof(ULONGLONG), NULL);

									//cout << keyBaseValue << endl;
									// 读取字节集
									ReadProcessMemory(hProcess, (LPCVOID)keyBaseValue, &msg.webchatkey, sizeof(msg.webchatkey), NULL);
									//nRead = ReadProcessMemory(hProcess, (LPVOID)lpBaseAddress2, webchatkey, 32, &nSize);
									CloseHandle(hProcess);
									//AsciiToHex(webchatkey, KeyHexBuffer,32);
									if (nRead) {
										DWORD nSize = 0;
										printf("Accout:%s\n", msg.accoutbuffer);
										printf("Mobile:%s\n", msg.wechatmobile);
										printf("WeChat Key:");
										for (unsigned char d : msg.webchatkey) {
											printf("%02X", d);
										}

										//Request(25, RecvData->UUID, RecvData->TASKUUID, sendbuffersize, 0, sendbuffer, NULL);

									}
									else {
										cout << "ERROR: " << GetLastError() << endl;
										break;
									}
								}
								bRet = Module32Next(hModuleSnap, &mi);
							}
							CloseHandle(hModuleSnap);
						}
					}

				}



			}
			CloseHandle(hProcess);
		}
		//printf("%-6d %s\n", pe.th32ProcessID, pe.szExeFile);
	}
}