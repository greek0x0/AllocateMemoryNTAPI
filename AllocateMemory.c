#include <Windows.h>
#include <stdio.h>
/*
int main() {
	// Using Kernelbase.dll/Kernel32.dll VirtualAlloc. Nah....
	LPVOID lpAddress = VirtualAlloc(NULL, 100, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	printf("Allocated Memory Using VirtualAlloc with memory address 0x%p\n", lpAddress);
	//will be stored within .rdata (read only due to const value)
	const char* String = "Hello this is allocated memory!!";
	memcpy(lpAddress, String, strlen(String));
	VirtualFree(lpAddress, 0, MEM_RELEASE);
	return 0;
	// Now lets do it with NtAllocateMemory and NtFreeVirtualMemory.
*/

// Struct for the NTAllocateVirtualMemory (used by VirtualAlloc)
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_wrapper)(
	HANDLE    ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T   RegionSize,
	ULONG     AllocationType,
	ULONG     Protect
	);
//Struct to free virtual memory (Used by VirtualFree)
typedef NTSTATUS(NTAPI* NtFreeVirtualMemory_wrapper)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PSIZE_T RegionSize,
	ULONG FreeType
);

// Get a HANDLE on the Native API
HMODULE getMod(LPCWSTR modName) {
	HMODULE hModule = NULL;
	printf("trying to get a handle to %S", modName);
	hModule = GetModuleHandleW(modName);
	if (hModule == NULL) {
		printf("failed to get a handle to the module. error: 0x%lx\n", GetLastError());
		return NULL;
	}
	else {
		printf("got a handle to the module!");
		printf("\\___[ %S\n\t\\_0x%p]\n", modName, hModule);
		return hModule;
	}
}

// Function to print memory content in hexadecimal format
void printMemoryContentHex(PVOID address, SIZE_T size) {
	unsigned char* ptr = (unsigned char*)address;
	for (SIZE_T i = 0; i < size; ++i) {
		printf("%02X ", ptr[i]);
	}
	printf("\n");
}


// Function to print memory content as ASCII characters
void printMemoryContentASCII(PVOID address, SIZE_T size) {
	unsigned char* ptr = (unsigned char*)address;
	for (SIZE_T i = 0; i < size; ++i) {
		char c = isprint(ptr[i]) ? ptr[i] : '.';
		printf("%c ", c);
	}
	printf("\n");
}

int main() {

	// Getting a handle on NTDLL
	HMODULE NTDLL_HANDLE = NULL;
	NTDLL_HANDLE = getMod(L"NTDLL");


	// Defining Custom NT API functions....
	// Get the address of the NTAllocateVirtualMemory Function..
	// Dont want to be using GetProcAddress in the future..
	NtAllocateVirtualMemory_wrapper rockyAllocateVirtualMemory = (NtAllocateVirtualMemory_wrapper)GetProcAddress(NTDLL_HANDLE, "NtAllocateVirtualMemory");
	

	// Using the Custom NT API functions...
	// They all return the type NTstatus , so we have to define the following:
	NTSTATUS STATUS = NULL;

	// parameters required for the use of rockyAllocateVirtualMemory
	HANDLE ProcessHandle = GetCurrentProcess();
	PVOID baseAddress = NULL;
	SIZE_T regionSize = 1024;

	// Using the rockyAllocateVirtualMemory NT API. 
	STATUS = rockyAllocateVirtualMemory(ProcessHandle, &baseAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	printf("Memory allocated successfully at 0x%p\n", &baseAddress);

	// Defining my string 
	const char* mystring = "Using the NTAPI to allocate this string to memory";

	// Copying my string to the baseaddress within memory
	memcpy(baseAddress, mystring, strlen(mystring));


	// Lets print the allocated memory:

	// Print memory content before deallocation
	printf("Memory content before deallocation:\n");
	printMemoryContentASCII(baseAddress, regionSize);


	// this would be VirtualFree if it was kernelbase.dll 
	NtFreeVirtualMemory_wrapper rockyDeallocateVirtualMemory = (NtFreeVirtualMemory_wrapper)GetProcAddress(NTDLL_HANDLE, "NtFreeVirtualMemory");

	// Dellocating the memory using custom native API
	STATUS = rockyDeallocateVirtualMemory(ProcessHandle, &baseAddress, &regionSize, MEM_RELEASE);


}


