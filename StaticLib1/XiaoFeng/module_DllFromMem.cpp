#include "module_DllFromMem.h"

CDllFromMem::CDllFromMem()
{
	m_hBaseAddress = NULL;
	m_hInstance = NULL;
	m_ntHead = NULL;
}

CDllFromMem::~CDllFromMem()
{

	if (m_hBaseAddress)
	{
		
		m_dllMain(m_hInstance,DLL_PROCESS_DETACH,NULL);
		VirtualFree(m_hBaseAddress,0,MEM_RELEASE);
	}

	
}
HANDLE CDllFromMem::LoadLibraryFromRs(HINSTANCE hInstance, DWORD nRsId, BOOL bIsCALL)
{
	m_hInstance = hInstance;
	LPVOID lpFileData = NULL;
	// 得到指定的资源文件在内存中的位置 
	HRSRC hrec = FindResource(m_hInstance, MAKEINTRESOURCE(nRsId), L"RT_RCDATA");
	if (NULL != hrec)
	{
		// 将资源文件载入内存 
		HRSRC hResLoad = (HRSRC)LoadResource(m_hInstance, hrec);
		if (NULL != hResLoad)
		{
			DWORD nDataLength = SizeofResource(m_hInstance, hrec);

			lpFileData = (void*)LockResource(hResLoad);
		}
		else
		{
			return NULL;
		}
	}
	else
	{
		return NULL;
	}

	m_pDosHeader = (PIMAGE_DOS_HEADER)lpFileData;

	//m_pNTHeader
	m_ntHead = (PIMAGE_NT_HEADERS)((PBYTE)lpFileData + m_pDosHeader->e_lfanew);


	//检查dos头的标记 和PE头
	if (m_pDosHeader->e_magic != IMAGE_DOS_SIGNATURE && m_ntHead->Signature != IMAGE_NT_SIGNATURE)
	{
		MessageBoxA(NULL, ("指定的资源不是有效的DLL文件!"), ("装入动态链接库出错"),MB_OK|MB_ICONERROR);
		return NULL;
	}

	//计算所需的加载空间 分配虚拟内存
	int SizeOfImage = m_ntHead->OptionalHeader.SizeOfImage;

	m_hBaseAddress = VirtualAlloc((LPVOID)(m_ntHead->OptionalHeader.ImageBase), SizeOfImage,/*MEM_COMMIT*/MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!m_hBaseAddress)
	{
		m_hBaseAddress = VirtualAlloc(NULL, SizeOfImage, MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	}
	VirtualAlloc(m_hBaseAddress, SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	//复制dll数据，并对齐每个段

	// 计算需要复制的PE头+段表字节数
	int SizeOfHeaders = m_ntHead->OptionalHeader.SizeOfHeaders;
	int FileAlignment = m_ntHead->OptionalHeader.FileAlignment;
	//复制头和段信息
	memcpy(m_hBaseAddress, lpFileData,SizeOfHeaders);


	m_pSectionHeader = (PIMAGE_SECTION_HEADER)(sizeof(IMAGE_NT_HEADERS) + (PBYTE)m_ntHead);
	int NumberOfSections = m_ntHead->FileHeader.NumberOfSections;
	LPVOID desc,src;
	int iSize;
	//复制每个节
	for (int i = 0; i < NumberOfSections; i++) //拷贝区段
	{
		src = (PBYTE)lpFileData + m_pSectionHeader[i].PointerToRawData;
		if (m_pSectionHeader[i].SizeOfRawData == 0 || m_pSectionHeader[i].VirtualAddress == 0)
		{
			continue;
		}
		// 定位该节在内存中的位置
		if (i < NumberOfSections - 1)
		{
			iSize = m_pSectionHeader[i + 1].PointerToRawData - m_pSectionHeader[i].PointerToRawData;
		}
		else
		{
			iSize = m_pSectionHeader[i].SizeOfRawData;
		}
		desc = (LPVOID)((PBYTE)m_hBaseAddress + m_pSectionHeader[i].VirtualAddress);
		// 复制段数据到虚拟内存	
		memcpy(desc, src, iSize);
	}
	m_pDosHeader = (PIMAGE_DOS_HEADER)m_hBaseAddress;
	m_ntHead = (PIMAGE_NT_HEADERS)((PBYTE)m_hBaseAddress + (m_pDosHeader->e_lfanew));
	m_pSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)m_ntHead + sizeof(IMAGE_NT_HEADERS));
	//以下是重定位
	
	if (m_ntHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)  //如果没有重定位表表示不用重定位，跳过重定位代码
	{
		/* 重定位表的结构：
	// DWORD sectionAddress, DWORD size (包括本节需要重定位的数据)
	// 例如 1000节需要修正5个重定位数据的话，重定位表的数据是
	// 00 10 00 00   14 00 00 00      xxxx xxxx xxxx xxxx xxxx 0000
	// -----------   -----------      ----
	// 给出节的偏移  总尺寸=8+6*2     需要修正的地址           用于对齐4字节
	// 重定位表是若干个相连，如果address 和 size都是0 表示结束
	// 需要修正的地址是12位的，高4位是形态字，intel cpu下是3
	*/
	//假设NewBase是0x600000,而文件中设置的缺省ImageBase是0x400000,则修正偏移量就是0x200000

		//注意重定位表的位置可能和硬盘文件中的偏移地址不同，应该使用加载后的地址
		PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)((PBYTE)m_hBaseAddress
			+ m_ntHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pLoc->VirtualAddress != 0) //开始扫描重定位表
		{
			WORD* pLocData = (WORD*)((PBYTE)pLoc + sizeof(IMAGE_BASE_RELOCATION));

			//计算本节需要修正的重定位项（地址）的数目
			DWORD nNumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			if (nNumberOfReloc ==0) break;
			//pLocData = Offset
			for (int i = 0; i < (int)nNumberOfReloc; i++)
			{
				// 每个WORD由两部分组成。高4位指出了重定位的类型，WINNT.H中的一系列IMAGE_REL_BASED_xxx定义了重定位类型的取值。
				// 低12位是相对于VirtualAddress域的偏移，指出了必须进行重定位的位置。
				if ((DWORD)(pLocData[i] & 0x0000F000) != 0x0000A000)
				{
					// 64位dll重定位，IMAGE_REL_BASED_DIR64
					// 对于IA-64的可执行文件，重定位似乎总是IMAGE_REL_BASED_DIR64类型的。
#ifdef _WIN64
					//m_hBaseAddress = pNewBase
					ULONGLONG* pAddress = (ULONGLONG*)((PBYTE)m_hBaseAddress + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
					ULONGLONG ullDelta = (ULONGLONG)m_hBaseAddress - m_ntHead->OptionalHeader.ImageBase;
					*pAddress += ullDelta;
#endif
				}
				else if ((DWORD)(pLocData[i] & 0x0000F000) == 0x00003000) //这是一个需要修正的地址
				{
					// 32位dll重定位，IMAGE_REL_BASED_HIGHLOW
					// 对于x86的可执行文件，所有的基址重定位都是IMAGE_REL_BASED_HIGHLOW类型的。
#ifndef _WIN64
					DWORD* pAddress = (DWORD*)((PBYTE)m_hBaseAddress + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
					DWORD dwDelta = (DWORD)m_hBaseAddress - m_ntHead->OptionalHeader.ImageBase;
					*pAddress += dwDelta;
#endif
				}
			}
			//转移到下一个节进行处理
			pLoc = (IMAGE_BASE_RELOCATION*)((PBYTE)pLoc + pLoc->SizeOfBlock);
		}
		
	}
	//重定位结束
	
	//以下是重建IAT
	// 引入表实际上是一个 IMAGE_IMPORT_DESCRIPTOR 结构数组，全部是0表示结束
	// 数组定义如下：
	// 
	// DWORD   OriginalFirstThunk;         // 0表示结束，否则指向未绑定的IAT结构数组
	// DWORD   TimeDateStamp; 
	// DWORD   ForwarderChain;             // -1 if no forwarders
	// DWORD   Name;                       // 给出dll的名字
	// DWORD   FirstThunk;                 // 指向IAT结构数组的地址(绑定后，这些IAT里面就是实际的函数地址)
	char MsgError[256] = { 0 };
	unsigned long nOffset = m_ntHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (nOffset) //如果没用导入表则跳过
	{
		HMODULE lib;
		IMAGE_THUNK_DATA * pRealIAT,*INTable;
		IMAGE_IMPORT_DESCRIPTOR* pID = (IMAGE_IMPORT_DESCRIPTOR*)((PBYTE)m_hBaseAddress + nOffset);
		
		while(pID->Name)//(pID->FirstThunk)
		{
			//获取dll的名字
			lib = LoadLibraryA((char*)(pID->Name + (PBYTE)m_hBaseAddress));
			if (lib == NULL) //装载库出错
			{
				wsprintfA(MsgError, ("装入动态链接库%s出错!"),(char *)(pID->Name+(PBYTE)m_hBaseAddress));
				MessageBoxA(NULL,MsgError, ("错误"),MB_OK|MB_ICONERROR);
				return NULL;
			}
			pRealIAT = (IMAGE_THUNK_DATA*)(pID->FirstThunk + (PBYTE)m_hBaseAddress);
			INTable = (IMAGE_THUNK_DATA*)((pID->OriginalFirstThunk ? pID->OriginalFirstThunk : pID->FirstThunk) + (PBYTE)m_hBaseAddress);

			//获取DLL中每个导出函数的地址，填入IAT
			//每个IAT结构是 ：
			// union { PBYTE  ForwarderString;
			//   PDWORD Function;
			//   DWORD Ordinal;
			//   PIMAGE_IMPORT_BY_NAME  AddressOfData;
			// } u1;
			// 长度是一个DWORD ，正好容纳一个地址。
			while (INTable->u1.AddressOfData)
			{
				if ((DWORD)INTable->u1.Function == 0)
				{
					break;
				}
				FARPROC lpFunction = NULL;

				if (INTable->u1.Ordinal & IMAGE_ORDINAL_FLAG) //这里的值给出的是导出序号
				{
					lpFunction = GetProcAddress(lib, (LPCSTR)(INTable->u1.Ordinal & 0x0000FFFF));
				}
				else//按照名字导入
				{
					//获取此IAT项所描述的函数名称
					PIMAGE_IMPORT_BY_NAME pByName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)m_hBaseAddress + (INTable->u1.AddressOfData));

					lpFunction = GetProcAddress(lib, (char*)pByName->Name);
				}
				if (lpFunction != NULL)   //找到了！
				{
#ifdef _WIN64
					pRealIAT->u1.Function = (ULONGLONG)lpFunction;
#else
					pRealIAT->u1.Function = (DWORD)lpFunction;
#endif
				}
				else
				{
					return NULL;
				}
				INTable++;
				pRealIAT++;
			}
			pID++;
		}
	}
	//重建IAT结束

	//修正基地址
#ifdef WIN32
	m_ntHead->OptionalHeader.ImageBase = (ULONGLONG)(PBYTE)m_hBaseAddress;
#else
	m_ntHead->OptionalHeader.ImageBase = (ULONGULONG)m_hBaseAddress;
#endif

	//接下来要调用一下dll的入口函数，做初始化工作。
	//调用dll的入口函数
	if (bIsCALL)
	{
		m_dllMain = (myDllMain)(m_ntHead->OptionalHeader.AddressOfEntryPoint + (PBYTE)m_hBaseAddress);
		m_dllMain(m_hInstance, DLL_PROCESS_ATTACH, NULL);
	}

	//PatchData();//给dll打补丁，如果不需要打补丁，这行可以注释掉;
	return (HANDLE)m_hBaseAddress;
}
FARPROC CDllFromMem::GetProcAddressFromRs(LPCSTR lpProcName)
{

	DWORD dwOffsetStart = m_ntHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD dwSize = m_ntHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	IMAGE_EXPORT_DIRECTORY* ExportTable = (IMAGE_EXPORT_DIRECTORY*)(m_ntHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (PBYTE)m_hBaseAddress);
	int iBase = ExportTable->Base;
	int iNumberOfFunctions = ExportTable->NumberOfFunctions;
	int iNumberOfNames = ExportTable->NumberOfNames; //<= iNumberOfFunctions
	LPDWORD pAddressOfNames = (LPDWORD)(ExportTable->AddressOfNames + (PBYTE)m_hBaseAddress);
	LPWORD pAddressOfOrdinals = (LPWORD)(ExportTable->AddressOfNameOrdinals + (PBYTE)m_hBaseAddress);
	LPDWORD pAddressOfFunctions = (LPDWORD)(ExportTable->AddressOfFunctions + (PBYTE)m_hBaseAddress);
	
	int iOrdinal = -1;
	
	if (((INT64)(PBYTE)lpProcName & 0xFFFF0000) == 0) //IT IS A ORDINAL!
	{
		iOrdinal = ((INT64)(PBYTE)lpProcName) & 0x0000FFFF - iBase;
	}
	else  //use name
	{
		int iFound = -1;
		for (int i = 0; i < iNumberOfNames; i++)
		{
			char* pName = (char*)(pAddressOfNames[i] + (PBYTE)m_hBaseAddress);
			if (strcmp(pName, lpProcName) == 0)
			{
				iFound = i;
				break;
			}
		}
		if (iFound >= 0)
		{
			iOrdinal = (int)(pAddressOfOrdinals[iFound]);
		}
	}

	if (iOrdinal < 0 || iOrdinal >= iNumberOfFunctions)
	{
		return NULL;
	}
	else
	{
		DWORD pFunctionOffset = pAddressOfFunctions[iOrdinal];

		if (pFunctionOffset > dwOffsetStart&& pFunctionOffset < (dwOffsetStart + dwSize))//maybe Export Forwarding
		{
			return NULL;
		}
		else
		{
			return (FARPROC)(pFunctionOffset + (PBYTE)m_hBaseAddress);
		}
	}


	return NULL;
}

void CDllFromMem::PatchData()
{
	DWORD PatchContent[][2] = { 0x0002CA94,0x0 };//rva,patchdata;
	int i = sizeof(PatchContent) / (sizeof(DWORD) * 2);
	for (int j = 0; j < i; j++)
	{
		*(char*)((char*)m_hBaseAddress + PatchContent[j][0]) = (char)PatchContent[j][1];
	}
}