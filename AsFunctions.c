#include"PETools.h"

//辅助函数:检查指针组
BOOL _stdcall AsCheckPointers()
{
	if (g_pointerGroup.m_pDOSHeader == NULL) {
		return FALSE;
	}
	return TRUE;
}

VOID _cdecl AsSendErrorMessage(IN LPSTR lpszErrorMessage, ...)
{
	//switch()
	//printf源码(重载printf)
	va_list arg;
	int done;

	va_start(arg, lpszErrorMessage);
	done = vprintf(lpszErrorMessage, arg);
	va_end(arg);

	return done;
}

//辅助函数:计算表长度
DWORD _stdcall AsCalcTableSize(DWORD dwTableCase)
{
	DWORD dwSize = NULL;
	DWORD pBase = g_pointerGroup.m_pDOSHeader;
	switch (dwTableCase)
	{
	//导入表计算验证完毕
	case IMAGE_DIRECTORY_ENTRY_IMPORT:
	{
		PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = g_pointerGroup.m_pImportDescriptor;
		for (int i = 0; pImportDescriptor[i].FirstThunk != NULL
			&& pImportDescriptor[i].OriginalFirstThunk != NULL; i++) {
			dwSize += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		}
		dwSize += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		break;
	}
	//导出表计算验证完毕
	case IMAGE_DIRECTORY_ENTRY_EXPORT:
	{
		PIMAGE_EXPORT_DIRECTORY pExportDirectory = g_pointerGroup.m_pExportDirectory;
		if (pExportDirectory == pBase) goto EndExport;
		dwSize =
			sizeof(IMAGE_EXPORT_DIRECTORY)
			+ sizeof(DWORD) * pExportDirectory->NumberOfFunctions
			+ (sizeof(short) + sizeof(DWORD)) * pExportDirectory->NumberOfNames;
	EndExport:
		break;
	}
	//重定位表计算验证完毕
	case IMAGE_DIRECTORY_ENTRY_BASERELOC:
	{
		PIMAGE_BASE_RELOCATION pBaseRelocation = g_pointerGroup.m_pBaseRelocation;
		PIMAGE_BASE_RELOCATION pBlock = pBaseRelocation;

		for (pBlock; *(__int64*)pBlock != 0; (DWORD)pBlock += (DWORD)(pBlock->SizeOfBlock));
		(DWORD)pBlock -= (DWORD)pBaseRelocation;
		dwSize = (DWORD)pBlock + 8;
		break;
	}
	//绑定导入表计算验证完毕
	case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
	{
		PIMAGE_OPTIONAL_HEADER pOptionalHeader = g_pointerGroup.m_pOptionalHeader;
		DWORD dllCount = 0;
		DWORD pBoundBase = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)(pBase +
			RVAToFOA(pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress));
		PIMAGE_BOUND_IMPORT_DESCRIPTOR pBound = pBoundBase;
		PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = g_pointerGroup.m_pImportDescriptor;
		//
		for (int i = 0; pImportDescriptor[i].FirstThunk != NULL
			&& pImportDescriptor[i].OriginalFirstThunk != NULL; i++) {
			if (pImportDescriptor[i].TimeDateStamp == -1) dllCount++;
		}

		while (*(__int64*)pBound != NULL) {
			DWORD countBound = pBound->NumberOfModuleForwarderRefs;
				for (int n = 0; n < countBound; n++) {
					(DWORD)pBound += sizeof(IMAGE_BOUND_FORWARDER_REF);
			}
			(DWORD)pBound += sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR) *(countBound + 1);
		}
		dwSize = (DWORD)pBound - (DWORD)pBoundBase + 8;
		break;
	}
	default:
	{
		break;
	}
	}
	return dwSize;
}