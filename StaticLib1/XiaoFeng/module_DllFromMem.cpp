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
	// �õ�ָ������Դ�ļ����ڴ��е�λ�� 
	HRSRC hrec = FindResource(m_hInstance, MAKEINTRESOURCE(nRsId), L"RT_RCDATA");
	if (NULL != hrec)
	{
		// ����Դ�ļ������ڴ� 
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


	//���dosͷ�ı�� ��PEͷ
	if (m_pDosHeader->e_magic != IMAGE_DOS_SIGNATURE && m_ntHead->Signature != IMAGE_NT_SIGNATURE)
	{
		MessageBoxA(NULL, ("ָ������Դ������Ч��DLL�ļ�!"), ("װ�붯̬���ӿ����"),MB_OK|MB_ICONERROR);
		return NULL;
	}

	//��������ļ��ؿռ� ���������ڴ�
	int SizeOfImage = m_ntHead->OptionalHeader.SizeOfImage;

	m_hBaseAddress = VirtualAlloc((LPVOID)(m_ntHead->OptionalHeader.ImageBase), SizeOfImage,/*MEM_COMMIT*/MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!m_hBaseAddress)
	{
		m_hBaseAddress = VirtualAlloc(NULL, SizeOfImage, MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	}
	VirtualAlloc(m_hBaseAddress, SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	//����dll���ݣ�������ÿ����

	// ������Ҫ���Ƶ�PEͷ+�α��ֽ���
	int SizeOfHeaders = m_ntHead->OptionalHeader.SizeOfHeaders;
	int FileAlignment = m_ntHead->OptionalHeader.FileAlignment;
	//����ͷ�Ͷ���Ϣ
	memcpy(m_hBaseAddress, lpFileData,SizeOfHeaders);


	m_pSectionHeader = (PIMAGE_SECTION_HEADER)(sizeof(IMAGE_NT_HEADERS) + (PBYTE)m_ntHead);
	int NumberOfSections = m_ntHead->FileHeader.NumberOfSections;
	LPVOID desc,src;
	int iSize;
	//����ÿ����
	for (int i = 0; i < NumberOfSections; i++) //��������
	{
		src = (PBYTE)lpFileData + m_pSectionHeader[i].PointerToRawData;
		if (m_pSectionHeader[i].SizeOfRawData == 0 || m_pSectionHeader[i].VirtualAddress == 0)
		{
			continue;
		}
		// ��λ�ý����ڴ��е�λ��
		if (i < NumberOfSections - 1)
		{
			iSize = m_pSectionHeader[i + 1].PointerToRawData - m_pSectionHeader[i].PointerToRawData;
		}
		else
		{
			iSize = m_pSectionHeader[i].SizeOfRawData;
		}
		desc = (LPVOID)((PBYTE)m_hBaseAddress + m_pSectionHeader[i].VirtualAddress);
		// ���ƶ����ݵ������ڴ�	
		memcpy(desc, src, iSize);
	}
	m_pDosHeader = (PIMAGE_DOS_HEADER)m_hBaseAddress;
	m_ntHead = (PIMAGE_NT_HEADERS)((PBYTE)m_hBaseAddress + (m_pDosHeader->e_lfanew));
	m_pSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)m_ntHead + sizeof(IMAGE_NT_HEADERS));
	//�������ض�λ
	
	if (m_ntHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)  //���û���ض�λ���ʾ�����ض�λ�������ض�λ����
	{
		/* �ض�λ��Ľṹ��
	// DWORD sectionAddress, DWORD size (����������Ҫ�ض�λ������)
	// ���� 1000����Ҫ����5���ض�λ���ݵĻ����ض�λ���������
	// 00 10 00 00   14 00 00 00      xxxx xxxx xxxx xxxx xxxx 0000
	// -----------   -----------      ----
	// �����ڵ�ƫ��  �ܳߴ�=8+6*2     ��Ҫ�����ĵ�ַ           ���ڶ���4�ֽ�
	// �ض�λ�������ɸ����������address �� size����0 ��ʾ����
	// ��Ҫ�����ĵ�ַ��12λ�ģ���4λ����̬�֣�intel cpu����3
	*/
	//����NewBase��0x600000,���ļ������õ�ȱʡImageBase��0x400000,������ƫ��������0x200000

		//ע���ض�λ���λ�ÿ��ܺ�Ӳ���ļ��е�ƫ�Ƶ�ַ��ͬ��Ӧ��ʹ�ü��غ�ĵ�ַ
		PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)((PBYTE)m_hBaseAddress
			+ m_ntHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pLoc->VirtualAddress != 0) //��ʼɨ���ض�λ��
		{
			WORD* pLocData = (WORD*)((PBYTE)pLoc + sizeof(IMAGE_BASE_RELOCATION));

			//���㱾����Ҫ�������ض�λ���ַ������Ŀ
			DWORD nNumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			if (nNumberOfReloc ==0) break;
			//pLocData = Offset
			for (int i = 0; i < (int)nNumberOfReloc; i++)
			{
				// ÿ��WORD����������ɡ���4λָ�����ض�λ�����ͣ�WINNT.H�е�һϵ��IMAGE_REL_BASED_xxx�������ض�λ���͵�ȡֵ��
				// ��12λ�������VirtualAddress���ƫ�ƣ�ָ���˱�������ض�λ��λ�á�
				if ((DWORD)(pLocData[i] & 0x0000F000) != 0x0000A000)
				{
					// 64λdll�ض�λ��IMAGE_REL_BASED_DIR64
					// ����IA-64�Ŀ�ִ���ļ����ض�λ�ƺ�����IMAGE_REL_BASED_DIR64���͵ġ�
#ifdef _WIN64
					//m_hBaseAddress = pNewBase
					ULONGLONG* pAddress = (ULONGLONG*)((PBYTE)m_hBaseAddress + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
					ULONGLONG ullDelta = (ULONGLONG)m_hBaseAddress - m_ntHead->OptionalHeader.ImageBase;
					*pAddress += ullDelta;
#endif
				}
				else if ((DWORD)(pLocData[i] & 0x0000F000) == 0x00003000) //����һ����Ҫ�����ĵ�ַ
				{
					// 32λdll�ض�λ��IMAGE_REL_BASED_HIGHLOW
					// ����x86�Ŀ�ִ���ļ������еĻ�ַ�ض�λ����IMAGE_REL_BASED_HIGHLOW���͵ġ�
#ifndef _WIN64
					DWORD* pAddress = (DWORD*)((PBYTE)m_hBaseAddress + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
					DWORD dwDelta = (DWORD)m_hBaseAddress - m_ntHead->OptionalHeader.ImageBase;
					*pAddress += dwDelta;
#endif
				}
			}
			//ת�Ƶ���һ���ڽ��д���
			pLoc = (IMAGE_BASE_RELOCATION*)((PBYTE)pLoc + pLoc->SizeOfBlock);
		}
		
	}
	//�ض�λ����
	
	//�������ؽ�IAT
	// �����ʵ������һ�� IMAGE_IMPORT_DESCRIPTOR �ṹ���飬ȫ����0��ʾ����
	// ���鶨�����£�
	// 
	// DWORD   OriginalFirstThunk;         // 0��ʾ����������ָ��δ�󶨵�IAT�ṹ����
	// DWORD   TimeDateStamp; 
	// DWORD   ForwarderChain;             // -1 if no forwarders
	// DWORD   Name;                       // ����dll������
	// DWORD   FirstThunk;                 // ָ��IAT�ṹ����ĵ�ַ(�󶨺���ЩIAT�������ʵ�ʵĺ�����ַ)
	char MsgError[256] = { 0 };
	unsigned long nOffset = m_ntHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (nOffset) //���û�õ����������
	{
		HMODULE lib;
		IMAGE_THUNK_DATA * pRealIAT,*INTable;
		IMAGE_IMPORT_DESCRIPTOR* pID = (IMAGE_IMPORT_DESCRIPTOR*)((PBYTE)m_hBaseAddress + nOffset);
		
		while(pID->Name)//(pID->FirstThunk)
		{
			//��ȡdll������
			lib = LoadLibraryA((char*)(pID->Name + (PBYTE)m_hBaseAddress));
			if (lib == NULL) //װ�ؿ����
			{
				wsprintfA(MsgError, ("װ�붯̬���ӿ�%s����!"),(char *)(pID->Name+(PBYTE)m_hBaseAddress));
				MessageBoxA(NULL,MsgError, ("����"),MB_OK|MB_ICONERROR);
				return NULL;
			}
			pRealIAT = (IMAGE_THUNK_DATA*)(pID->FirstThunk + (PBYTE)m_hBaseAddress);
			INTable = (IMAGE_THUNK_DATA*)((pID->OriginalFirstThunk ? pID->OriginalFirstThunk : pID->FirstThunk) + (PBYTE)m_hBaseAddress);

			//��ȡDLL��ÿ�����������ĵ�ַ������IAT
			//ÿ��IAT�ṹ�� ��
			// union { PBYTE  ForwarderString;
			//   PDWORD Function;
			//   DWORD Ordinal;
			//   PIMAGE_IMPORT_BY_NAME  AddressOfData;
			// } u1;
			// ������һ��DWORD ����������һ����ַ��
			while (INTable->u1.AddressOfData)
			{
				if ((DWORD)INTable->u1.Function == 0)
				{
					break;
				}
				FARPROC lpFunction = NULL;

				if (INTable->u1.Ordinal & IMAGE_ORDINAL_FLAG) //�����ֵ�������ǵ������
				{
					lpFunction = GetProcAddress(lib, (LPCSTR)(INTable->u1.Ordinal & 0x0000FFFF));
				}
				else//�������ֵ���
				{
					//��ȡ��IAT���������ĺ�������
					PIMAGE_IMPORT_BY_NAME pByName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)m_hBaseAddress + (INTable->u1.AddressOfData));

					lpFunction = GetProcAddress(lib, (char*)pByName->Name);
				}
				if (lpFunction != NULL)   //�ҵ��ˣ�
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
	//�ؽ�IAT����

	//��������ַ
#ifdef WIN32
	m_ntHead->OptionalHeader.ImageBase = (ULONGLONG)(PBYTE)m_hBaseAddress;
#else
	m_ntHead->OptionalHeader.ImageBase = (ULONGULONG)m_hBaseAddress;
#endif

	//������Ҫ����һ��dll����ں���������ʼ��������
	//����dll����ں���
	if (bIsCALL)
	{
		m_dllMain = (myDllMain)(m_ntHead->OptionalHeader.AddressOfEntryPoint + (PBYTE)m_hBaseAddress);
		m_dllMain(m_hInstance, DLL_PROCESS_ATTACH, NULL);
	}

	//PatchData();//��dll�򲹶����������Ҫ�򲹶������п���ע�͵�;
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