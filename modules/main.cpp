#include <iostream>
#include <iomanip>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>

using std::wcout;
using std::endl;
using std::wstring;
using std::setw;

int main(int argc, char * argv[])
{
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPALL | TH32CS_SNAPMODULE32, 0);

	PROCESSENTRY32 process;
	ZeroMemory(&process, sizeof(process));
	process.dwSize = sizeof(process);

	if (Process32First(h, &process))
	{
		do
		{
			wstring procName = process.szExeFile;
			//change the filter here!
			if (/*wstring::npos == procName.find(L"devenv") && */wstring::npos == procName.find(L"t"))
				continue;

			HANDLE procHandle = CreateToolhelp32Snapshot(TH32CS_SNAPALL | TH32CS_SNAPMODULE32, process.th32ProcessID);
			if (procHandle != INVALID_HANDLE_VALUE)
			{
				MODULEENTRY32 info;
				ZeroMemory(&info, sizeof(info));
				info.dwSize = sizeof(info);

				if (Module32First(procHandle, &info))
				{
					do
					{
						wstring s = info.szModule;
						wcout << "Process: " << setw(30) << process.szExeFile << "    Module: " << setw(30) << s << endl;
					} while (Module32Next(procHandle, &info));
				}
			}
			CloseHandle(procHandle);
		} while (Process32Next(h, &process));
	}

	CloseHandle(h);

	return 0;
}