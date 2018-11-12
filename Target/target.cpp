#include<Windows.h>
#include<stdio.h>

int main() {
	DWORD pid = GetCurrentProcessId();
	printf("pid: %d", pid);
	getchar();
	ExitProcess(1);
}