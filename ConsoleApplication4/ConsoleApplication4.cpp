#undef UNICODE
#undef _UNICODE
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <windows.h>
#include <string>
#include <fstream>
#include <vector>
#include <tlhelp32.h>
#include <psapi.h> 
#include <algorithm> 

typedef int  (*t_PyRun_SimpleString_Generic)(const char* command, void* flags);
typedef void (*t_PyEval_InitThreads)();
typedef int  (*t_PyGILState_Ensure)();
typedef void (*t_PyGILState_Release)(int);

struct ShellcodeData {
    t_PyEval_InitThreads           pPyEval_InitThreads;
    t_PyGILState_Ensure            pPyGILState_Ensure;
    t_PyGILState_Release           pPyGILState_Release;
    t_PyRun_SimpleString_Generic   pPyRun_SimpleString;
};

uintptr_t GetModuleBaseAddress(DWORD procId, const char* modName) {
    uintptr_t modBaseAddr = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
    if (hSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 modEntry; modEntry.dwSize = sizeof(modEntry);
        if (Module32First(hSnap, &modEntry)) {
            do { if (!_stricmp(modEntry.szModule, modName)) { modBaseAddr = (uintptr_t)modEntry.modBaseAddr; break; } } while (Module32Next(hSnap, &modEntry));
        } CloseHandle(hSnap);
    } return modBaseAddr;
}

uintptr_t GetRemoteProcAddress(HANDLE hProcess, uintptr_t moduleBase, const char* funcName) {
    IMAGE_DOS_HEADER dosHeader;
    if (!ReadProcessMemory(hProcess, (LPCVOID)moduleBase, &dosHeader, sizeof(dosHeader), NULL) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS ntHeaders;
    if (!ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + dosHeader.e_lfanew), &ntHeaders, sizeof(ntHeaders), NULL) || ntHeaders.Signature != IMAGE_NT_SIGNATURE) return 0;
    IMAGE_DATA_DIRECTORY exportDir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.Size == 0) return 0;
    IMAGE_EXPORT_DIRECTORY exportTable;
    if (!ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + exportDir.VirtualAddress), &exportTable, sizeof(exportTable), NULL)) return 0;

    std::vector<DWORD> nameRVAs(exportTable.NumberOfNames);
    ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + exportTable.AddressOfNames), nameRVAs.data(), exportTable.NumberOfNames * sizeof(DWORD), NULL);
    std::vector<DWORD> funcRVAs(exportTable.NumberOfFunctions);
    ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + exportTable.AddressOfFunctions), funcRVAs.data(), exportTable.NumberOfFunctions * sizeof(DWORD), NULL);
    std::vector<WORD> nameOrdinals(exportTable.NumberOfNames);
    ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + exportTable.AddressOfNameOrdinals), nameOrdinals.data(), exportTable.NumberOfNames * sizeof(WORD), NULL);

    for (DWORD i = 0; i < exportTable.NumberOfNames; ++i) {
        char currentFuncName[256] = { 0 };
        ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + nameRVAs[i]), currentFuncName, sizeof(currentFuncName) - 1, NULL);
        if (_stricmp(currentFuncName, funcName) == 0) {
            DWORD funcRVA = funcRVAs[nameOrdinals[i]];
            if (funcRVA >= exportDir.VirtualAddress && funcRVA < exportDir.VirtualAddress + exportDir.Size) {
                char forwardedName[256] = { 0 };
                ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + funcRVA), forwardedName, sizeof(forwardedName) - 1, NULL);
                char* dllName = strtok(forwardedName, ".");
                char* functionName = strtok(NULL, ".");
                if (dllName && functionName) {
                    std::cout << "[INFO] Forwarded Export tespit edildi -> " << dllName << "." << functionName << std::endl;
                    return GetRemoteProcAddress(hProcess, (uintptr_t)GetModuleHandleA(dllName), functionName);
                }
            }
            return moduleBase + funcRVA;
        }
    }

    std::cout << "[INFO] Fonksiyon '" << funcName << "' isimle bulunamadi. Ordinal brute-force (hayalet arama) denemesi..." << std::endl;
    for (DWORD i = 0; i < exportTable.NumberOfFunctions; ++i) {
        DWORD funcRVA = funcRVAs[i];
        if (funcRVA == 0) continue;

        if (funcRVA >= exportDir.VirtualAddress && funcRVA < exportDir.VirtualAddress + exportDir.Size) {
            char potentialName[256] = { 0 };
            ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + funcRVA), potentialName, sizeof(potentialName) - 1, NULL);
            if (strstr(potentialName, funcName)) {
                std::cout << "[INFO] Ordinal brute-force ile potansiyel eslesme bulundu: #" << i << " -> " << potentialName << std::endl;
                char* dllName = strtok(potentialName, ".");
                char* realFuncName = strtok(NULL, ".");
                if (dllName && realFuncName) {
                    return GetRemoteProcAddress(hProcess, (uintptr_t)GetModuleHandleA(dllName), realFuncName);
                }
            }
        }
    }

    return 0; 
}


uintptr_t PatternScan(HANDLE hProcess, uintptr_t begin, uintptr_t end, const char* pattern, const char* mask) {
    uintptr_t current_chunk = begin; SIZE_T bytes_read;
    while (current_chunk < end) {
        char buffer[4096];
        if (!ReadProcessMemory(hProcess, (LPCVOID)current_chunk, &buffer, sizeof(buffer), &bytes_read)) { current_chunk += sizeof(buffer); continue; }
        if (bytes_read == 0) break;
        for (size_t i = 0; i < bytes_read; ++i) {
            bool found = true;
            for (size_t j = 0; j < strlen(mask) && i + j < bytes_read; ++j) { if (mask[j] != '?' && pattern[j] != buffer[i + j]) { found = false; break; } }
            if (found) { return current_chunk + i; }
        }
        current_chunk += bytes_read;
    } return 0;
}
uintptr_t SignatureScanModule(HANDLE hProcess, DWORD procId, const char* modName, const char* pattern, const char* mask) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId); if (hSnap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32 modEntry; modEntry.dwSize = sizeof(MODULEENTRY32);
    if (Module32First(hSnap, &modEntry)) {
        do {
            if (modName == nullptr || _stricmp(modEntry.szModule, modName) == 0) {
                uintptr_t result = PatternScan(hProcess, (uintptr_t)modEntry.modBaseAddr, (uintptr_t)modEntry.modBaseAddr + modEntry.modBaseSize, pattern, mask);
                if (result) { CloseHandle(hSnap); return result; }
                if (modName != nullptr) break;
            }
        } while (Module32Next(hSnap, &modEntry));
    } CloseHandle(hSnap); return 0;
}


void DoInjection(HWND hTargetWnd, bool useFlags) {
    const char* pythonExecFunctionName = useFlags ? "PyRun_SimpleStringFlags" : "PyRun_SimpleString";
    std::cout << "\n[" << (useFlags ? "F2" : "F3") << "] Basildi. Hedef fonksiyon: " << pythonExecFunctionName << std::endl;
    DWORD procId = 0; GetWindowThreadProcessId(hTargetWnd, &procId); if (procId == 0) return;
    std::cout << "Hedef Process ID: " << procId << std::endl;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, procId); if (!hProcess) return;

    ShellcodeData data = { 0 };

    data.pPyRun_SimpleString = (t_PyRun_SimpleString_Generic)GetRemoteProcAddress(hProcess, GetModuleBaseAddress(procId, "python27.dll"), pythonExecFunctionName);

    if (!data.pPyRun_SimpleString) {
        std::cout << "[MODIE] Adim 2: Fonksiyon EAT'de bulunamadi. Imza taramasi (Hayalet Avcisi) baslatiliyor..." << std::endl;
        const char* sig = useFlags ? "\x55\x8B\xEC\x83\xEC\x0C\x53\x56\x8B\x75\x0C" : "\x55\x8B\xEC\x83\xEC\x08\x8B\x45\x08\x50\xE8";
        const char* mask = "xxxxxxxxxxx";
        data.pPyRun_SimpleString = (t_PyRun_SimpleString_Generic)SignatureScanModule(hProcess, procId, "python27.dll", sig, mask);
    }

    if (data.pPyRun_SimpleString) {
        uintptr_t pythonBase = GetModuleBaseAddress(procId, "python27.dll");
        if (pythonBase) {
            data.pPyEval_InitThreads = (t_PyEval_InitThreads)GetRemoteProcAddress(hProcess, pythonBase, "PyEval_InitThreads");
            data.pPyGILState_Ensure = (t_PyGILState_Ensure)GetRemoteProcAddress(hProcess, pythonBase, "PyGILState_Ensure");
            data.pPyGILState_Release = (t_PyGILState_Release)GetRemoteProcAddress(hProcess, pythonBase, "PyGILState_Release");
        }
    }

    if (!data.pPyRun_SimpleString || !data.pPyEval_InitThreads) { std::cerr << "HATA: Kritik fonksiyonlar hiçbir yontemle bulunamadi!" << std::endl; CloseHandle(hProcess); return; }
    std::cout << "[MODIE] '" << pythonExecFunctionName << "' adresi basariyla alindi: 0x" << std::hex << (uintptr_t)data.pPyRun_SimpleString << std::dec << std::endl;

    std::ifstream file("test2.py");
    std::string pyCode((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    BYTE shellcode[] = { 0x55, 0x8B, 0xEC, 0x56, 0x8B, 0x75, 0x08, 0xFF, 0x56, 0x00, 0xFF, 0x56, 0x04, 0x50, 0x6A, 0x00, 0x8D, 0x4E, 0x10, 0x51, 0xFF, 0x56, 0x0C, 0x83, 0xC4, 0x08, 0x58, 0x50, 0xFF, 0x56, 0x08, 0x83, 0xC4, 0x04, 0x5E, 0x8B, 0xE5, 0x5D, 0xC2, 0x04, 0x00 };
    size_t totalSize = sizeof(shellcode) + sizeof(data) + pyCode.length() + 1;
    void* remoteMem = VirtualAllocEx(hProcess, NULL, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    uintptr_t remoteDataAddr = (uintptr_t)remoteMem + sizeof(shellcode);
    std::vector<BYTE> buffer(totalSize);
    memcpy(buffer.data(), shellcode, sizeof(shellcode)); memcpy(buffer.data() + sizeof(shellcode), &data, sizeof(data));
    memcpy(buffer.data() + sizeof(shellcode) + sizeof(data), pyCode.c_str(), pyCode.length() + 1);
    WriteProcessMemory(hProcess, remoteMem, buffer.data(), totalSize, NULL);
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, (LPVOID)remoteDataAddr, 0, NULL);
    if (hThread) {
        std::cout << "[SUCCES] Shellcode thread'i basariyla baslatildi." << std::endl; WaitForSingleObject(hThread, INFINITE); CloseHandle(hThread);
    }
    else { std::cerr << "Thread olusturulamadi! Hata: " << GetLastError() << std::endl; }
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE); CloseHandle(hProcess);
    std::cout << "------------------------------------------" << std::endl;
}

int main() {
    std::cout << "[MODIE Injector v8.0 - Ordinal/Signature Hunter] Hazir." << std::endl;
    std::cout << " F2: PyRun_SimpleStringFlags | F3: PyRun_SimpleString " << std::endl;
    std::cout << "------------------------------------------" << std::endl;
    while (true) {
        if (GetAsyncKeyState(VK_F2) & 1) DoInjection(GetForegroundWindow(), true);
        if (GetAsyncKeyState(VK_F3) & 1) DoInjection(GetForegroundWindow(), false);
        Sleep(100);
    } return 0;
}