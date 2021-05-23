//
//该版本为Console接口测试版
//面向结构设计思想
//

//库文件包含
#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include<windows.h>
#include<stdlib.h>
#include<string.h>
#include<stdio.h>
//=================================================================================

typedef struct {
	//标准全局变量声明
	PIMAGE_DOS_HEADER m_pDOSHeader;
	PIMAGE_NT_HEADERS m_pNTHeader;
	PIMAGE_FILE_HEADER m_pFileHeader;
	PIMAGE_OPTIONAL_HEADER m_pOptionalHeader;
	PIMAGE_SECTION_HEADER m_pSectionHeader;
	DWORD m_dwLengthOfFile;
	//拓展全局变量声明
	PIMAGE_EXPORT_DIRECTORY m_pExportDirectory;
	PIMAGE_IMPORT_DESCRIPTOR m_pImportDescriptor;
	PIMAGE_BASE_RELOCATION m_pBaseRelocation;
} TOOLS_POINTER_GROUP;
extern TOOLS_POINTER_GROUP g_pointerGroup;
//===================================================================================
//宏函数

//对齐
#define Align(x, y) (((x)/(y) + 1)*(y))

//ShellCode函数
//CHAR shellCode[];
//const DWORD codeLength;
//注入ShellCode函数
//int _declspec(naked) InjectFunc(OUT SHELLCODE* pShellCode);

//========================================================================================================================
//标准PE工具函数

//初始化指针组
BOOL _stdcall InitPointerGroup(IN LPVOID pFileBuffer);
//载入器所属函数
DWORD _stdcall ReadPEFile(IN LPCSTR lpszFile, OUT LPVOID* pFileBuffer);
//存盘
DWORD _stdcall MemeryToFile(IN LPVOID pMemBuffer, IN size_t size, OUT LPCSTR lpszFile);
//RVA转FOA
DWORD _stdcall RVAToFOA(IN DWORD dwRva);
//与尾部添加新节
BOOL _stdcall AddNewSection(IN DWORD dwSizeOfSection, IN LPSTR lpszName, OUT LPVOID* pFileBuffer);
//(相邻/连续)节合并
BOOL _stdcall MergeSec(IN DWORD dwStart, IN DWORD dwEnd, OUT LPVOID* pNewImageBuffer);
//扩大目标节
BOOL _stdcall ExpandSec(OUT LPVOID* pNewImageBuffer);


//拓展PE工具函数
//=======================================================================================================//

//测试函数:打印NT头
VOID _stdcall ExPrintNTHeaders();
//测试函数:向指定段空闲区添加代码
BOOL _stdcall ExAddCodeInSec(IN DWORD NumberOfSec);
//测试函数:打印目录项
VOID _stdcall ExPrintDriectory();
//测试函数:打印导出表
VOID _stdcall ExPrintExport();
//测试函数:打印重定位表
VOID _stdcall ExPrintRelocation();
//测试函数:打印导入表
VOID _stdcall ExPrintImport();
//测试函数:打印绑定导入表
VOID _stdcall ExPrintBound();
//测试函数:移动重定位表
VOID _stdcall ExMoveRelocation(DWORD dwOrdinalOfSection);
//测试函数:移动导出表
VOID _stdcall ExMoveExports(DWORD dwOrdinalOfSection);
//测试函数:移动导入表(仅仅导入表，不包括子表，方便导入表注入)
VOID _stdcall ExMoveImport(DWORD dwOrdinalOfSection, DWORD PreOrdianl);
//测试函数:查询目标函数
VOID _stdcall QueryFunctionByName(LPCSTR lpszFuncName);
VOID _stdcall QueryFunctionByOrdinal(SHORT oridinal);


//辅助工具函数
//===========================================================================================//

//辅助函数:检查指针组
BOOL _stdcall AsCheckPointers();

VOID _cdecl AsSendErrorMessage(IN LPSTR lpszErrorMessage, ...);

//辅助函数:计算表长度
DWORD _stdcall AsCalcTableSize(DWORD dwTableCase);
