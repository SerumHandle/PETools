#include"header.h"


int _cdecl main(int argc, char* argv[])
{
	LPVOID pFileBuffer = NULL;
	ReadPEFile("test.dll", &pFileBuffer);
	ExPrintRelocation();
	ExPrintImport();
	ExPrintBound();
	ExPrintExport();
	return 0;
}