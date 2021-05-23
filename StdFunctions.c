#include"PETools.h"

extern TOOLS_POINTER_GROUP g_pointerGroup = { NULL };


//初始化指针组(写入指针组)
BOOL _stdcall InitPointerGroup(IN LPVOID pFileBuffer)
{
	if (pFileBuffer == NULL) {
		
		AsSendErrorMessage("[%s]:FileBuffer is NULL.", __FUNCTION__);
		return FALSE;
	}
	//标准变量
	PIMAGE_DOS_HEADER pDOSHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	//拓展变量
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;
	PIMAGE_BASE_RELOCATION pBaseRelocation = NULL;
	//标准变量赋值
	DWORD pBase = (DWORD)pFileBuffer;
	pDOSHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		AsSendErrorMessage("[%s]:This is not a standard PE file.", __FUNCTION__);
		return FALSE;
	}
	pNTHeader = (PIMAGE_NT_HEADERS)(pBase + pDOSHeader->e_lfanew);
	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE) {
		AsSendErrorMessage("[%s]:This is not a standard PE file.", __FUNCTION__);
		return FALSE;
	}
	pFileHeader = (PIMAGE_FILE_HEADER)&pNTHeader->FileHeader;
	pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&pNTHeader->OptionalHeader;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((__int32)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
	g_pointerGroup.m_pDOSHeader = pDOSHeader;
	g_pointerGroup.m_pNTHeader = pNTHeader;
	g_pointerGroup.m_pFileHeader = pFileHeader;
	g_pointerGroup.m_pOptionalHeader = pOptionalHeader;
	g_pointerGroup.m_pSectionHeader = pSectionHeader;
	//扩展变量赋值
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pBase + RVAToFOA(pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pBase + RVAToFOA(pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
	pBaseRelocation = (PIMAGE_BASE_RELOCATION)(pBase + RVAToFOA(pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress));
	g_pointerGroup.m_pExportDirectory = pExportDirectory;
	g_pointerGroup.m_pImportDescriptor = pImportDescriptor;
	g_pointerGroup.m_pBaseRelocation = pBaseRelocation;
	return TRUE;
}
//载入器所属函数(写入指针组)
DWORD _stdcall ReadPEFile(IN LPCSTR lpszFile, OUT LPVOID* pFileBuffer)
{
	if (lpszFile == NULL) {
		AsSendErrorMessage("[%s]:Filepath is invailed.", __FUNCTION__);
		return FALSE;
	}
	FILE* pFile = NULL;
	pFile = fopen(lpszFile, "rb");
	if (pFile == NULL) {
		AsSendErrorMessage("[%s]:Open File failed.\n", __FUNCTION__);
		return FALSE;
	}
	//计算文件长度
	DWORD dwFileSize = NULL;
	fseek(pFile, 0, SEEK_END);
	dwFileSize = ftell(pFile);
	g_pointerGroup.m_dwLengthOfFile = dwFileSize;
//短文件读取方式
	//分配内存空间
	LPVOID pBuffer = (LPVOID)malloc(sizeof(BYTE) * dwFileSize);
	if (pBuffer == NULL) {
		AsSendErrorMessage("[%s]:Malloc failure.\n", __FUNCTION__);
		return FALSE;
	}
	memset(pBuffer, 0, sizeof(BYTE) * dwFileSize);
//长文件读取方式
	//...........

	//读取文件至内存
	*pFileBuffer = pBuffer;
	fseek(pFile, 0, SEEK_SET);
	DWORD dwReadOver = fread(pBuffer, 1, dwFileSize, pFile);
	fclose(pFile);
	//初始化指针组
	InitPointerGroup(pBuffer);
	return dwReadOver;
}
//存盘(读取指针组)
DWORD _stdcall MemeryToFile(IN LPVOID pMemBuffer, OUT LPCSTR lpszFile)
{
	if (!AsCheckPointers()) {
		AsSendErrorMessage("[%s]:Pointer Group Error.", __FUNCTION__);
		return FALSE;
	}
	DWORD dwFileSize = g_pointerGroup.m_dwLengthOfFile;
	//新建文件
	FILE* pFile = NULL;
	pFile = fopen(lpszFile, "wb");
	if (pFile == NULL) {
		AsSendErrorMessage("[%s]:Open File failed.", __FUNCTION__);
		return FALSE;
	}
	//函数实现
	DWORD dwWriteOver = fwrite(pMemBuffer, 1, dwFileSize, pFile);
	fclose(pFile);
	return dwWriteOver;
}
//RVA转FOA(读取指针组)
DWORD _stdcall RVAToFOA(IN DWORD dwRva)
{
	//暂时不进行错误检查
	//if (!AsCheckPointers()) {
	//	AsSendErrorMessage("[%s]:Pointer Group Error.", __FUNCTION__);
	//	return FALSE;
	//}
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = g_pointerGroup.m_pOptionalHeader;
	PIMAGE_FILE_HEADER pFileHeader = g_pointerGroup.m_pFileHeader;
	PIMAGE_SECTION_HEADER pSectionHeader = g_pointerGroup.m_pSectionHeader;
	//函数
	if (dwRva <= pOptionalHeader->SizeOfHeaders) {
		return dwRva;
	}
	for (int i = 0; i < pFileHeader->NumberOfSections; i++) {
		if (dwRva
			>= (pSectionHeader[i].VirtualAddress)
			&& dwRva 
			<= (pSectionHeader[i].VirtualAddress + pSectionHeader[i].SizeOfRawData)
			) {
			return dwRva - pSectionHeader[i].VirtualAddress + pSectionHeader[i].PointerToRawData;
		}
	}
	AsSendErrorMessage("[%s]:RVA is out of sections.", __FUNCTION__);
	return NULL;
}
//追加新节
BOOL _stdcall AddNewSection(IN DWORD dwSizeOfSection, IN LPSTR lpszName, OUT LPVOID* pFileBuffer);
//(相邻/连续)节合并
BOOL _stdcall MergeSec(IN DWORD dwStart, IN DWORD dwEnd, OUT LPVOID* pNewImageBuffer);
//扩大目标节
BOOL _stdcall ExpandSec(OUT LPVOID* pNewImageBuffer);