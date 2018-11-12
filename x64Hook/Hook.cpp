#include "Hook.h"


// API name you want to hook
const char* apiName = "ExitProcess";


// function pointer 
void (WINAPI *procPtr)();

// Modifed API
void WINAPI Modified() {

	MessageBox(0, "HOOK", 0, 0);
}




void analyzeImportDescriptor
(
	IMAGE_IMPORT_DESCRIPTOR importDescriptor,
	PIMAGE_NT_HEADERS64 peHeader,
	DWORD64 baseAddress
)
{
	PIMAGE_THUNK_DATA64 thunkILT;
	PIMAGE_THUNK_DATA64 thunkIAT;
	PIMAGE_IMPORT_BY_NAME nameData;
	

	thunkILT = (PIMAGE_THUNK_DATA64)(importDescriptor.OriginalFirstThunk + baseAddress);
	thunkIAT = (PIMAGE_THUNK_DATA64)(importDescriptor.FirstThunk + baseAddress);

	while (thunkILT->u1.AddressOfData != 0) {
		// has been the routine imported as ordinal number
		if (!(thunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
			nameData = (PIMAGE_IMPORT_BY_NAME)(thunkILT->u1.AddressOfData + baseAddress);

			if (!strcmp(apiName, nameData->Name)) {
				DWORD  oldProtectionFlags;
				procPtr = Modified;
				VirtualProtect(&thunkIAT->u1.Function, sizeof(DWORD64), PAGE_EXECUTE_READWRITE, &oldProtectionFlags);
				thunkIAT->u1.Function = (DWORD64)procPtr;
				VirtualProtect(&thunkIAT->u1.Function, sizeof(DWORD64), oldProtectionFlags, NULL);
			}
			//printf("Funtion: %s address: %llx\n", nameData->Name, thunkIAT->u1.Function);
		}

		thunkILT++;
		thunkIAT++;
	}

	return;
}


BOOL parse() {
	DWORD64 baseAddress;

	// passing NULL to GetModuleHandle() gives us base address
	baseAddress = (DWORD64)GetModuleHandle(NULL);
	//printf("\nBase Address: %llx\n", baseAddress);


	PIMAGE_DOS_HEADER dosHeader;
	dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}
	else {
		//printf("IMAGE_DOS_SIGNATURE: %x\n", dosHeader->e_magic);
		//printf("RVA of PE's file header: %x\n", dosHeader->e_lfanew);
	}


	PIMAGE_NT_HEADERS64 peHeader;
	peHeader = (PIMAGE_NT_HEADERS64)(
		baseAddress + dosHeader->e_lfanew);
	if (peHeader->Signature != IMAGE_NT_SIGNATURE) {
		return(FALSE);
	}
	else {
		//printf("NT_HEADERS Address: %llx\n", peHeader);
		//printf("PE image: %x\n", peHeader->Signature);
	}

	IMAGE_OPTIONAL_HEADER64 optionalHeader;
	optionalHeader = peHeader->OptionalHeader;
	if (optionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		return FALSE;
	}
	else {
		//printf("x64 executable image: %x\n", optionalHeader.Magic);
	}


	IMAGE_DATA_DIRECTORY importDirectory;
	importDirectory = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	DWORD64 descriptorStartRVA;
	// get the RVA of the import descriptor
	descriptorStartRVA = importDirectory.VirtualAddress;
	//printf("RVA of IMPORT_DESCRIPTOR array: %llx\n", descriptorStartRVA);
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor;
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(descriptorStartRVA + baseAddress);
	//printf("Address of IMPORT_DESCRIPTOR array: %llx\n", importDescriptor);

	int index = 0;
	while (importDescriptor[index].Characteristics != 0) {
		DWORD64 dllname = importDescriptor[index].Name + baseAddress;
		//printf("DLL name: %s\n", dllname);
		analyzeImportDescriptor(
			importDescriptor[index],
			peHeader,
			baseAddress
		);

		index++;
	}
}
