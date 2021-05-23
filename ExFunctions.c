#include"PETools.h"
const char* i_dataDirectory[] = {
	"IMAGE_DIRECTORY_ENTRY_EXPORT",
	"IMAGE_DIRECTORY_ENTRY_IMPORT",
	"IMAGE_DIRECTORY_ENTRY_RESOURCE",
	"IMAGE_DIRECTORY_ENTRY_EXCEPTION",
	"IMAGE_DIRECTORY_ENTRY_SECURITY",
	"IMAGE_DIRECTORY_ENTRY_BASERELOC",
	"IMAGE_DIRECTORY_ENTRY_DEBUG",
	"IMAGE_DIRECTORY_ENTRY_COPYRIGHT",
	"IMAGE_DIRECTORY_ENTRY_GLOBALPTR",
	"IMAGE_DIRECTORY_ENTRY_TLS",
	"IMAGE_DIRECTORY_ENTRY_LOAD_IMPORT",
	"IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT",
	"IMAGE_DIRECTORY_ENTRY_IAT",
	"IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
	"IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR",
	"IMAGE_DIRECTORY_ENTRY_RESERVE"
};
VOID _stdcall ExPrintExport()
{
	DWORD pBase = g_pointerGroup.m_pDOSHeader;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = g_pointerGroup.m_pExportDirectory;
	//
	char* ptrName = NULL;
	SHORT* pNameOridinal = NULL;
	LPVOID* ptrFunction = NULL;
	DWORD ordinal = NULL;
	//
	pNameOridinal = (SHORT*)(pBase + RVAToFOA(pExportDirectory->AddressOfNameOrdinals));
	printf("=======================ExportDirectory===========================\n");
	printf("\tOrdinal\tHint\tRVA\t\tName\n");
	for (int i = 0; i < pExportDirectory->NumberOfFunctions; i++)
	{
		//着重理解其中的指针使用
		ptrFunction = (LPVOID)((DWORD*)(pBase + RVAToFOA(pExportDirectory->AddressOfFunctions)))[i];
		printf("\t|%d", i + pExportDirectory->Base);
		for (int n = 0; n < pExportDirectory->NumberOfNames; n++) {
			if (i == pNameOridinal[n]) {
				ptrName = (char*)(pBase + RVAToFOA(((DWORD*)(pBase + RVAToFOA(pExportDirectory->AddressOfNames)))[n]));
				ordinal = pNameOridinal[n] + pExportDirectory->Base;
				printf("\t|%d", n);
				printf("\t|0x%p", ptrFunction);
				printf("\t|%s\n", ptrName);
				goto Next;
			}
		}
		printf("\t|");
		printf("\t|0x%p", ptrFunction);
		printf("\t|{NONAME}\n");
	Next:;
	}
	return;
}
VOID _stdcall ExPrintBound()
{
	DWORD count = NULL;
	DWORD pBase = (DWORD)(g_pointerGroup.m_pDOSHeader);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = g_pointerGroup.m_pOptionalHeader;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = g_pointerGroup.m_pImportDescriptor;
	DWORD pBoundBase = NULL;
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBound = NULL;
	//检查导入表绑定属性
	printf("========================BoundImportTable===================\n");
	for (int i = 0; pImportDescriptor[i].FirstThunk != NULL && pImportDescriptor[i].OriginalFirstThunk != NULL; i++) {
		if (pImportDescriptor[i].TimeDateStamp == -1) count++;
	}
	printf("BoundDllCount:%d\n", count);
	if (count == NULL) return;
	//打印
	pBound = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)(pBase +
		RVAToFOA(pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress));
	pBoundBase = pBound;
	//
	while (*(__int64*)pBound != NULL) {
		printf("BoundImportDescriptor:\n");
		printf("\tName:%s\n", pBoundBase + pBound->OffsetModuleName);
		printf("\tTimeStamp:%p\n", pBound->TimeDateStamp);
		DWORD countBound = pBound->NumberOfModuleForwarderRefs;
		(DWORD)pBound += sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR);
		if (pBound->NumberOfModuleForwarderRefs == 0) {
			printf("BoundForwarderRef:NULL\n\n");
			continue;
		}
		printf("BoundForwarderRef:\n");
		for (int n = 0; n < countBound; n++) {
			printf("\tName:%s\n", pBoundBase + (IMAGE_BOUND_FORWARDER_REF*)pBound->OffsetModuleName);
			printf("\tTimeStamp:%p\n", pBound->TimeDateStamp);
			(DWORD)pBound += sizeof(IMAGE_BOUND_FORWARDER_REF);
		}
		printf("\n");
	}
}

VOID _stdcall ExPrintRelocation()
{
	printf("==================RelocationTable==================\n");
	if (!AsCheckPointers()) {
		AsSendErrorMessage("[%s]:Pointer Group Error.", __FUNCTION__);
		return;
	}
	PIMAGE_BASE_RELOCATION pBaseRelocation = g_pointerGroup.m_pBaseRelocation;
	DWORD pBase = g_pointerGroup.m_pDOSHeader;
	//
	PIMAGE_BASE_RELOCATION pReloc = pBaseRelocation;
	//
	DWORD number = NULL;
	SHORT* pBlock = NULL;
	for (pReloc; *(__int64*)pReloc != NULL; (DWORD)pReloc += pReloc->SizeOfBlock) {
		number = (pReloc->SizeOfBlock - 8) / 2;
		pBlock = (DWORD)pReloc + 8;
		printf("VirtualAddress:0x%p\nSizeOfBlock:0x%.4X\n", pReloc->VirtualAddress, pReloc->SizeOfBlock);
		for (int n = 0; n < number; n +=8) {
			for (int j = 0; j < 8; j++) {
				if ((pBlock[n + j] & 0xf000) == 0x3000) {
					printf("%.4X\t", pBlock[n + j] & 0x0fff);
				}
				else printf("null\t");
			}
			printf("\n");
		}
	}
	return;
	
}

VOID _stdcall ExPrintImport()
{
	DWORD pBase = (DWORD)(g_pointerGroup.m_pDOSHeader);
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = g_pointerGroup.m_pImportDescriptor;
	PIMAGE_THUNK_DATA pIAT = NULL;
	PIMAGE_THUNK_DATA pINT = NULL;
	//
	printf("==================ImportTable==================\n");
	for (int i = 0; pImportDescriptor[i].OriginalFirstThunk != NULL && pImportDescriptor[i].FirstThunk != NULL; i++) {
		pIAT = pBase + RVAToFOA(pImportDescriptor[i].FirstThunk);
		pINT = pBase + RVAToFOA(pImportDescriptor[i].OriginalFirstThunk);
		//
		printf("NameOfDll:%s\n", pBase + RVAToFOA(pImportDescriptor[i].Name));
		printf("Functions:\n");
		for (int n = 0; (DWORD)(pINT[n].u1.AddressOfData) != NULL; n++) {
			if (pINT[n].u1.AddressOfData & 0x80000000) {
				printf("Ordinal:%d\n", pINT[n].u1.Ordinal - 0x80000000);
			}
			else {
				printf("Name:%s\n", ((PIMAGE_IMPORT_BY_NAME)(pBase + RVAToFOA(pINT[n].u1.AddressOfData)))->Name);
			}
		}
		printf("\n");
	}
}

