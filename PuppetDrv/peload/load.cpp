#include"load.h"

int laod::LoadRealPE(PUCHAR data, ULONG64 len)
{
	

	ULONG dwImageSize = len;
	unsigned char* pMemory = (unsigned char*)ExAllocatePool(NonPagedPool, dwImageSize);
	if (!pMemory)  
	{
		return 0;
	}
	memcpy(pMemory, data, dwImageSize);

	PUCHAR imageBase = FileToImage(pMemory);
	if (!imageBase) return FALSE;

	int ret= FixRelocation(imageBase);
	if (!ret) return FALSE;

	ret = FixIat(imageBase);
	if (!ret) return FALSE;
	
	FixCookie(imageBase);

	CallDriverEntry(imageBase);

	ExFreePool(pMemory);
}

PUCHAR laod::FileToImage(PUCHAR fileBuffer)
{
	if (!fileBuffer) return NULL;

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)fileBuffer;
	PIMAGE_NT_HEADERS pNts = (PIMAGE_NT_HEADERS)((PUCHAR)fileBuffer + pDos->e_lfanew);

	//创建imageBuffer
	ULONG sizeofImage = pNts->OptionalHeader.SizeOfImage;
	PUCHAR imageBuffer =(PUCHAR)ExAllocatePool(NonPagedPool, sizeofImage);
	if (!imageBuffer)
	{
		return 0;
	}
	memset(imageBuffer, 0, sizeofImage);

	//复制PE头
	memcpy(imageBuffer, fileBuffer, pNts->OptionalHeader.SizeOfHeaders);

	ULONG NumberOfSections = pNts->FileHeader.NumberOfSections;

	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNts);

	//拉伸PE 结构
	for (ULONG i = 0; i < NumberOfSections; i++)
	{
		memcpy(imageBuffer + pSection->VirtualAddress, fileBuffer + pSection->PointerToRawData, pSection->SizeOfRawData);
		pSection++;
	}

	return imageBuffer;
}

int laod::FixRelocation(PUCHAR imageBuffer)
{

	PIMAGE_NT_HEADERS pNts = RtlImageNtHeader(imageBuffer);
	if (!pNts) return FALSE;

	PIMAGE_DATA_DIRECTORY iRelocation = &pNts->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	PIMAGE_BASE_RELOCATION pBase = (PIMAGE_BASE_RELOCATION)(imageBuffer + iRelocation->VirtualAddress);

	while (pBase->SizeOfBlock && pBase->VirtualAddress)
	{

		PIMAGE_RELOC RelocationBlock = (PIMAGE_RELOC)((PUCHAR)pBase + sizeof(IMAGE_BASE_RELOCATION));

		UINT32	NumberOfRelocations = (pBase->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

		for (int i = 0; i < NumberOfRelocations; i++)
		{
			if (RelocationBlock[i].Type == IMAGE_REL_BASED_DIR64)
			{

				// 64 位
				PUINT64	Address = (PUINT64)((PUINT8)imageBuffer + pBase->VirtualAddress + RelocationBlock[i].Offset);
				UINT64	Delta = (UINT64) (*Address - pNts->OptionalHeader.ImageBase + (PUINT8)imageBuffer);
				*Address = Delta;
			}
			else if (RelocationBlock[i].Type == IMAGE_REL_BASED_HIGHLOW)
			{

				PUINT32	Address = (PUINT32)((PUINT8)imageBuffer + pBase->VirtualAddress + (RelocationBlock[i].Offset));
				UINT32	Delta = (UINT64)(*Address - pNts->OptionalHeader.ImageBase + (PUINT8)imageBuffer);
				*Address = Delta;
			}
		}

		pBase = (PIMAGE_BASE_RELOCATION)((PUCHAR)pBase + pBase->SizeOfBlock);
	}

	return 1;
}

int laod::FixIat(PUCHAR imageBuffer)
{
	if (!imageBuffer) return FALSE;

	PIMAGE_NT_HEADERS pNts = RtlImageNtHeader(imageBuffer);
	if (!pNts) return FALSE;

	PIMAGE_DATA_DIRECTORY pimportDir = &pNts->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR import = (PIMAGE_IMPORT_DESCRIPTOR)(imageBuffer + pimportDir->VirtualAddress);

	BOOLEAN isSuccess = TRUE;

	for (; import->Name; import++)
	{
		PUCHAR libName = (imageBuffer + import->Name);


		ULONG_PTR base= QueryModule(libName, NULL);


		if (!base)
		{
			isSuccess = FALSE;
			break;
		}

		PIMAGE_THUNK_DATA pThuckName = (PIMAGE_THUNK_DATA)(imageBuffer + import->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pThuckFunc = (PIMAGE_THUNK_DATA)(imageBuffer + import->FirstThunk);

		for (; pThuckName->u1.ForwarderString; ++pThuckName, ++pThuckFunc)
		{
			PIMAGE_IMPORT_BY_NAME FuncName = (PIMAGE_IMPORT_BY_NAME)(imageBuffer + pThuckName->u1.AddressOfData);

			ULONG_PTR func = ExportTableFuncByName((char*)base, FuncName->Name);
			if (func)
			{
				pThuckFunc->u1.Function = (ULONG_PTR)func;
			}
			else
			{
				isSuccess = FALSE;
				break;
			}
		}

		if (!isSuccess) break;

	}

	return isSuccess;
}

VOID laod::FixCookie(PUCHAR imageBuffer)
{
	if (!imageBuffer) return;

	PIMAGE_NT_HEADERS pNts = RtlImageNtHeader(imageBuffer);
	if (!pNts) return ;

	PIMAGE_DATA_DIRECTORY pConfigDir = &pNts->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];

	PIMAGE_LOAD_CONFIG_DIRECTORY config = (PIMAGE_LOAD_CONFIG_DIRECTORY)(pConfigDir->VirtualAddress + imageBuffer);

	*(PULONG_PTR)(config->SecurityCookie) += 10;
}

void laod::CallDriverEntry(PUCHAR imageBuffer)
{
	PIMAGE_NT_HEADERS pNts = RtlImageNtHeader(imageBuffer);

	ULONG_PTR entry = pNts->OptionalHeader.AddressOfEntryPoint;
	DriverEntryProc EntryPointFunc = (DriverEntryProc)(imageBuffer + entry);
	NTSTATUS status = EntryPointFunc(NULL, NULL);
	if (!NT_SUCCESS(status))
	{
		return;
	}


	//清空PE头
	memset(imageBuffer, 0, PAGE_SIZE);

}

ULONG64 laod::ExportTableFuncByName(const char* pData, const char* funcName)
{
	PIMAGE_DOS_HEADER pHead = (PIMAGE_DOS_HEADER)pData;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pData + pHead->e_lfanew);
	int numberRvaAndSize = pNt->OptionalHeader.NumberOfRvaAndSizes;
	PIMAGE_DATA_DIRECTORY pDir = (PIMAGE_DATA_DIRECTORY)&pNt->OptionalHeader.DataDirectory[0];

	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pData + pDir->VirtualAddress);

	ULONG64 funcAddr = 0;
	for (int i = 0; i < pExport->NumberOfNames; i++)
	{
		int* funcAddress =(int*) (pData + pExport->AddressOfFunctions);
		int* names = (int*)(pData + pExport->AddressOfNames);
		short* fh = (short*)(pData + pExport->AddressOfNameOrdinals);
		int index = -1;
		char* name = (char*)(pData + names[i]);

		if (strcmp(name, funcName) == 0)
		{
			index = fh[i];
		}



		if (index != -1)
		{
			funcAddr =(ULONG64) (pData + funcAddress[index]);
			break;
		}


	}

	if (!funcAddr)
	{
		KdPrint(("没有找到函数%s\r\n", funcName));

	}
	else
	{
		KdPrint(("找到函数%s addr %p\r\n", funcName, funcAddr));
	}


	return funcAddr;
}

ULONG_PTR laod::QueryModule(PUCHAR moduleName, ULONG_PTR* moduleSize)
{
	if (moduleName == NULL) return 0;

	RTL_PROCESS_MODULES rtlMoudles = { 0 };
	PRTL_PROCESS_MODULES SystemMoudles = &rtlMoudles;
	BOOLEAN isAllocate = FALSE;
	//测量长度
	ULONG* retLen = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, SystemMoudles, sizeof(RTL_PROCESS_MODULES), (PULONG)&retLen);

	//分配实际长度内存
	if (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		SystemMoudles = (PRTL_PROCESS_MODULES)ExAllocatePool(PagedPool, (SIZE_T)(retLen + sizeof(RTL_PROCESS_MODULES)));
		if (!SystemMoudles) return 0;

		memset(SystemMoudles, 0, (SIZE_T)(retLen + sizeof(RTL_PROCESS_MODULES)));

		status = ZwQuerySystemInformation(SystemModuleInformation, SystemMoudles, (SIZE_T)(retLen + sizeof(RTL_PROCESS_MODULES)), (PULONG)&retLen);

		if (!NT_SUCCESS(status))
		{
			ExFreePool(SystemMoudles);
			return 0;
		}

		isAllocate = TRUE;
	}

	PUCHAR kernelModuleName = NULL;
	ULONG_PTR moudleBase = 0;

	do
	{


		if (_stricmp((const char*)moduleName, "ntoskrnl.exe") == 0 || _stricmp((const char*)moduleName, "ntkrnlpa.exe") == 0)
		{
			PRTL_PROCESS_MODULE_INFORMATION moudleInfo = &SystemMoudles->Modules[0];
			moudleBase = (ULONG_PTR)(moudleInfo->ImageBase);
			if (moduleSize) *moduleSize = moudleInfo->ImageSize;

			break;
		}


		kernelModuleName =(PUCHAR) ExAllocatePool(PagedPool,(SIZE_T) (strlen((const char*)moduleName) + 1));
		memset(kernelModuleName, 0, strlen((const char*)moduleName) + 1);
		memcpy(kernelModuleName, moduleName, strlen((const char*)moduleName));
		_strupr((char*)kernelModuleName);


		for (int i = 0; i < SystemMoudles->NumberOfModules; i++)
		{
			PRTL_PROCESS_MODULE_INFORMATION moudleInfo = &SystemMoudles->Modules[i];

			PUCHAR pathName = (PUCHAR)_strupr(( char*)moudleInfo->FullPathName);
			/*		DbgPrintEx(77, 0, "baseName = %s,fullPath = %s\r\n",
						moudleInfo->FullPathName + moudleInfo->OffsetToFileName, moudleInfo->FullPathName);*/


			if (strstr((const char*)pathName, (const char*)kernelModuleName))
			{
				moudleBase =(ULONG_PTR) moudleInfo->ImageBase;
				if (moduleSize) *moduleSize = moudleInfo->ImageSize;
				break;
			}

		}

	} while (0);


	if (kernelModuleName)
	{
		ExFreePool(kernelModuleName);
	}

	if (isAllocate)
	{
		ExFreePool(SystemMoudles);
	}

	return moudleBase;
}

