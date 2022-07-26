//@隐藏{
#if !defined(AFX_DLLFROMMEM_H__233D9B97_BA88_48C7_AC00_03525B40C7F1__INCLUDED_)
#define AFX_DLLFROMMEM_H__233D9B97_BA88_48C7_AC00_03525B40C7F1__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
#include "windows.h"
//@隐藏}

//@模块名称  内存加载DLL  
//@版本  1.0  
//@日期  2022-07-26
//@作者  XiaoFeng  
//@模块备注 内存加载DLL模块

//@src "module_DllFromMem.cpp"

//@别名 DLL入口函数类型
typedef BOOL(WINAPI* myDllMain)(
	HINSTANCE hinstDLL,  // handle to the DLL module
	DWORD fdwReason,     // reason for calling function
	LPVOID lpvReserved   // reserved
	);

//@别名 内存加载DLL类
class CDllFromMem
{
public:
	//@隐藏{
	CDllFromMem();
	virtual ~CDllFromMem();
	//@隐藏}

	//@备注 加载内存动态库
	//@参数 实例句柄,可使用,GetModuleHandle(NULL);
	//@参数 资源ID
	//@参数 是否调用DLLMain
	//@返回 模块句柄
	//@别名 加载动态库(实例句柄,资源ID,是否调用DLLMain)
	HANDLE LoadLibraryFromRs(HINSTANCE hInstance, DWORD nRsId,BOOL bIsCALL);

	//@备注 获取函数地址
	//@参数 函数名称
	//@返回 函数地址
	//@别名 取函数地址(函数名称)
	FARPROC GetProcAddressFromRs(LPCSTR lpProcName);
	//@隐藏{
	void PatchData();
	//@隐藏}
private:
	void* m_hBaseAddress;
	HINSTANCE m_hInstance;
	PIMAGE_NT_HEADERS m_ntHead;
	PIMAGE_DOS_HEADER m_pDosHeader;
	PIMAGE_SECTION_HEADER m_pSectionHeader;
	myDllMain m_dllMain;
};

#endif // !defined(AFX_DLLFROMMEM_H__233D9B97_BA88_48C7_AC00_03525B40C7F1__INCLUDED_)
