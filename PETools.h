//
//�ð汾ΪConsole�ӿڲ��԰�
//����ṹ���˼��
//

//���ļ�����
#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include<windows.h>
#include<stdlib.h>
#include<string.h>
#include<stdio.h>
//=================================================================================

typedef struct {
	//��׼ȫ�ֱ�������
	PIMAGE_DOS_HEADER m_pDOSHeader;
	PIMAGE_NT_HEADERS m_pNTHeader;
	PIMAGE_FILE_HEADER m_pFileHeader;
	PIMAGE_OPTIONAL_HEADER m_pOptionalHeader;
	PIMAGE_SECTION_HEADER m_pSectionHeader;
	DWORD m_dwLengthOfFile;
	//��չȫ�ֱ�������
	PIMAGE_EXPORT_DIRECTORY m_pExportDirectory;
	PIMAGE_IMPORT_DESCRIPTOR m_pImportDescriptor;
	PIMAGE_BASE_RELOCATION m_pBaseRelocation;
} TOOLS_POINTER_GROUP;
extern TOOLS_POINTER_GROUP g_pointerGroup;
//===================================================================================
//�꺯��

//����
#define Align(x, y) (((x)/(y) + 1)*(y))

//ShellCode����
//CHAR shellCode[];
//const DWORD codeLength;
//ע��ShellCode����
//int _declspec(naked) InjectFunc(OUT SHELLCODE* pShellCode);

//========================================================================================================================
//��׼PE���ߺ���

//��ʼ��ָ����
BOOL _stdcall InitPointerGroup(IN LPVOID pFileBuffer);
//��������������
DWORD _stdcall ReadPEFile(IN LPCSTR lpszFile, OUT LPVOID* pFileBuffer);
//����
DWORD _stdcall MemeryToFile(IN LPVOID pMemBuffer, IN size_t size, OUT LPCSTR lpszFile);
//RVAתFOA
DWORD _stdcall RVAToFOA(IN DWORD dwRva);
//��β������½�
BOOL _stdcall AddNewSection(IN DWORD dwSizeOfSection, IN LPSTR lpszName, OUT LPVOID* pFileBuffer);
//(����/����)�ںϲ�
BOOL _stdcall MergeSec(IN DWORD dwStart, IN DWORD dwEnd, OUT LPVOID* pNewImageBuffer);
//����Ŀ���
BOOL _stdcall ExpandSec(OUT LPVOID* pNewImageBuffer);


//��չPE���ߺ���
//=======================================================================================================//

//���Ժ���:��ӡNTͷ
VOID _stdcall ExPrintNTHeaders();
//���Ժ���:��ָ���ο�������Ӵ���
BOOL _stdcall ExAddCodeInSec(IN DWORD NumberOfSec);
//���Ժ���:��ӡĿ¼��
VOID _stdcall ExPrintDriectory();
//���Ժ���:��ӡ������
VOID _stdcall ExPrintExport();
//���Ժ���:��ӡ�ض�λ��
VOID _stdcall ExPrintRelocation();
//���Ժ���:��ӡ�����
VOID _stdcall ExPrintImport();
//���Ժ���:��ӡ�󶨵����
VOID _stdcall ExPrintBound();
//���Ժ���:�ƶ��ض�λ��
VOID _stdcall ExMoveRelocation(DWORD dwOrdinalOfSection);
//���Ժ���:�ƶ�������
VOID _stdcall ExMoveExports(DWORD dwOrdinalOfSection);
//���Ժ���:�ƶ������(����������������ӱ����㵼���ע��)
VOID _stdcall ExMoveImport(DWORD dwOrdinalOfSection, DWORD PreOrdianl);
//���Ժ���:��ѯĿ�꺯��
VOID _stdcall QueryFunctionByName(LPCSTR lpszFuncName);
VOID _stdcall QueryFunctionByOrdinal(SHORT oridinal);


//�������ߺ���
//===========================================================================================//

//��������:���ָ����
BOOL _stdcall AsCheckPointers();

VOID _cdecl AsSendErrorMessage(IN LPSTR lpszErrorMessage, ...);

//��������:�������
DWORD _stdcall AsCalcTableSize(DWORD dwTableCase);
