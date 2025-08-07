#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <ntstrsafe.h>

#ifdef __cplusplus
extern "C"
{
#endif
	typedef struct _LDR_DATA_TABLE_ENTRY
	{
		/* 0x0000 */ struct _LIST_ENTRY InLoadOrderLinks;
		/* 0x0010 */ struct _LIST_ENTRY InMemoryOrderLinks;
		/* 0x0020 */ struct _LIST_ENTRY InInitializationOrderLinks;
		/* 0x0030 */ void* DllBase;
		/* 0x0038 */ void* EntryPoint;
		/* 0x0040 */ unsigned long SizeOfImage;
		/* 0x0048 */ struct _UNICODE_STRING FullDllName;
		/* 0x0058 */ struct _UNICODE_STRING BaseDllName;

	} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY; /* size: 0x0120 */
	typedef struct _SYSTEM_MODULE
	{
		ULONG_PTR Reserved[2];
		PVOID Base;
		ULONG Size;
		ULONG Flags;
		USHORT Index;
		USHORT Unknown;
		USHORT LoadCount;
		USHORT ModuleNameOffset;
		CHAR ImageName[256];
	} SYSTEM_MODULE, * PSYSTEM_MODULE;

	typedef struct _SYSTEM_MODULE_INFORMATION
	{
		ULONG_PTR ulModuleCount;
		SYSTEM_MODULE Modules[1];
	} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

	NTSTATUS ZwQuerySystemInformation(
		DWORD32 systemInformationClass,
		PVOID systemInformation,
		ULONG systemInformationLength,
		PULONG returnLength);

	NTSTATUS ObReferenceObjectByName(
		PUNICODE_STRING objectName,
		ULONG attributes,
		PACCESS_STATE accessState,
		ACCESS_MASK desiredAccess,
		POBJECT_TYPE objectType,
		KPROCESSOR_MODE accessMode,
		PVOID parseContext, PVOID* object);

	extern POBJECT_TYPE* IoDriverObjectType;


#ifdef __cplusplus
}
#endif