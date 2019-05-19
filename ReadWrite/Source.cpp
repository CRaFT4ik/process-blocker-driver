#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <locale.h>

#define BUFFERSIZE 1000

void read(char *path)
{
	HANDLE hFile;
	DWORD  dwBytesRead = 0;
	char   ReadBuffer[BUFFERSIZE] = { 0 };

	hFile = CreateFile(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("ERROR: OpenFile\n");
		return;
	}

	if (FALSE == ReadFile(hFile, &ReadBuffer, BUFFERSIZE - 1, &dwBytesRead, NULL))
		printf("ERROR: ReadFile\n");
	else
		printf("Success. Content:\n%s\n", ReadBuffer);

	CloseHandle(hFile);
}

void write(char *path, char *content)
{
	HANDLE hFile;
	DWORD dwBytesToWrite = (DWORD) strlen(content);
	DWORD dwBytesWritten = 0;
	BOOL bErrorFlag = FALSE;

	hFile = CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("ERROR: OpenFile\n");
		return;
	}

    printf("Writing %d bytes to %s\n", dwBytesToWrite, path);

    if (FALSE == WriteFile(hFile, content, dwBytesToWrite, &dwBytesWritten, NULL))
		printf("ERROR: WriteFile\n");
    else
        if (dwBytesWritten != dwBytesToWrite)
            printf("WARNING: dwBytesWritten != dwBytesToWrite\n");
        else
            printf("Wrote %d bytes to %s successfully\n", dwBytesWritten, path);

    CloseHandle(hFile);
}

int main(int argc, char *argv[])
{
	setlocale(LC_ALL, "rus");

	if (argc > 2)
	{
		if (strcmp(argv[1], "-r") == 0)
		{
			if (argc < 3) goto help;
			else read(argv[2]);
		} else if (strcmp(argv[1], "-w") == 0)
		{
			if (argc < 4) goto help;
			else write(argv[2], argv[3]);
		}
		return 0;
	}

help:
	printf("Usage: -r [path] OR -w [PATH] [CONTENT]\n");
	return 0;
}