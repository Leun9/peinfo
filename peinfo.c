#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

/*** API ***/

// pFile参数为PE文件映射对象在内存中映像的指针
int PrintPE(char* szPEPath);                // 打印PE文件的信息，参数为PE文件路径
VOID PrintDosHeader(PVOID pFile);           // 打印Dos头（Dos Header）的信息
int Is32BitPE(PVOID pFile);                 // 判断文件是否为32位PE文件
VOID PrintNTHeaders(PVOID pFile);           // 打印NT头（NT Headers）的信息
VOID PrintSectionTable(PVOID pFile);        // 打印块表（Section Table）信息
DWORD RVA2FOA(PVOID pFile, DWORD dwRVA);    // 将相对虚拟地址（RVA）转换为文件偏移地址（FOA）
VOID PrintExportTable(PVOID pFile);         // 打印导出表（Export Table）
VOID PrintImportTable(PVOID pFile);         // 打印导入表（Import Table）

/*** inter func ***/

VOID PrintOptionalHeader32(PVOID pFile);
VOID PrintOptionalHeader64(PVOID pFile);
VOID PrintImportTable32(PVOID pFile);
VOID PrintImportTable64(PVOID pFile);

int PrintPE(char *szPEPath) {
    // 获得PE文件句柄
    HANDLE hFile = CreateFile(szPEPath, GENERIC_ALL, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return -1;

    // 创建一个新的文件映射内核对象
    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (hMapping == NULL) return -1;

    // 将一个文件映射对象映射到内存,得到指向映射到内存的第一个字节的指针pFile
    PVOID pFile = MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (pFile == NULL) return -1;

    // 打印信息
    PrintDosHeader(pFile);
    PrintNTHeaders(pFile);
    PrintSectionTable(pFile);
    PrintImportTable(pFile);
    PrintExportTable(pFile);
}

VOID PrintDosHeader(PVOID pFile) {
    // DOS头
    PIMAGE_DOS_HEADER pDosHeader = pFile;
    printf("\nDOS Header:\n");
    printf("\te_lfanew: 0x%08X\n", pDosHeader->e_lfanew);
}

int Is32BitPE(PVOID pFile) {
    PIMAGE_DOS_HEADER pDosHeader = pFile;
    WORD machine = *(PWORD)(pFile + pDosHeader->e_lfanew + sizeof(DWORD));
    if (machine == IMAGE_FILE_MACHINE_I386) return 1;
    return 0;
}

VOID PrintOptionalHeader32(PVOID pFile) {
    // NT头: 可选头
    PIMAGE_DOS_HEADER pDosHeader = pFile;
    PIMAGE_NT_HEADERS32 pNTHeaders = pFile + pDosHeader->e_lfanew;
    printf("\nPE Optional Header:\n");
    PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = &pNTHeaders->OptionalHeader;
    printf("\tSizeOfCode: 0x%08X\n", pOptionalHeader->SizeOfCode);
    DWORD dwAddressOfEntryPoint = pOptionalHeader->AddressOfEntryPoint;
    printf("\tAddressOfEntryPoint: 0x%08X\n", dwAddressOfEntryPoint);
    DWORD dwImageBase = pOptionalHeader->ImageBase;
    printf("\tImageBase: 0x%08X\n", dwImageBase);
    DWORD dwSectionAlignment = pOptionalHeader->SectionAlignment;
    printf("\tSectionAlignment: 0x%08X\n", dwSectionAlignment);
    DWORD dwFileAlignment = pOptionalHeader->FileAlignment;
    printf("\tFileAlignment: 0x%08X\n", dwFileAlignment);
    DWORD dwSizeOfImage = pOptionalHeader->SizeOfImage;
    printf("\tSizeOfImage: 0x%08X\n", dwSizeOfImage);
    DWORD dwNumberOfRvaAndSize = pOptionalHeader->NumberOfRvaAndSizes;
    printf("\tNumberOfRvaAndSizes: 0x%08X\n", dwNumberOfRvaAndSize);

    // NT头: 可选头: 数据目录
    printf("\nData Directories:\n");
    PIMAGE_DATA_DIRECTORY pDataDir = pOptionalHeader->DataDirectory;
    for (int i = 0; i < dwNumberOfRvaAndSize; i++) {
        printf("\t[%d]\t", i);
        printf("VirtualAddress: 0x%08X\n", pDataDir[i].VirtualAddress);
        printf("\t\tSize: 0x%08X\n", pDataDir[i].Size);
    }
}

VOID PrintOptionalHeader64(PVOID pFile) {
    // NT头: 可选头
    PIMAGE_DOS_HEADER pDosHeader = pFile;
    PIMAGE_NT_HEADERS64 pNTHeaders = pFile + pDosHeader->e_lfanew;
    printf("\nPE Optional Header:\n");
    PIMAGE_OPTIONAL_HEADER64 pOptionalHeader = &pNTHeaders->OptionalHeader;
    printf("\tSizeOfCode: 0x%08X\n", pOptionalHeader->SizeOfCode);
    DWORD dwAddressOfEntryPoint = pOptionalHeader->AddressOfEntryPoint;
    printf("\tAddressOfEntryPoint: 0x%08X\n", dwAddressOfEntryPoint);
    DWORD dwImageBase = pOptionalHeader->ImageBase;
    printf("\tImageBase: 0x%08X\n", dwImageBase);
    DWORD dwSectionAlignment = pOptionalHeader->SectionAlignment;
    printf("\tSectionAlignment: 0x%08X\n", dwSectionAlignment);
    DWORD dwFileAlignment = pOptionalHeader->FileAlignment;
    printf("\tFileAlignment: 0x%08X\n", dwFileAlignment);
    DWORD dwSizeOfImage = pOptionalHeader->SizeOfImage;
    printf("\tSizeOfImage: 0x%08X\n", dwSizeOfImage);
    DWORD dwNumberOfRvaAndSize = pOptionalHeader->NumberOfRvaAndSizes;
    printf("\tNumberOfRvaAndSizes: 0x%08X\n", dwNumberOfRvaAndSize);

    // NT头: 可选头: 数据目录
    printf("\nData Directories:\n");
    PIMAGE_DATA_DIRECTORY pDataDir = pOptionalHeader->DataDirectory;
    for (int i = 0; i < dwNumberOfRvaAndSize; i++) {
        printf("\t[%d]\t", i);
        printf("VirtualAddress: 0x%08X\n", pDataDir[i].VirtualAddress);
        printf("\t\tSize: 0x%08X\n", pDataDir[i].Size);
    }
}

VOID PrintNTHeaders(PVOID pFile) { // TODO From here
    // NT头
    PIMAGE_DOS_HEADER pDosHeader = pFile;
    PIMAGE_NT_HEADERS32 pNTHeaders = pFile + pDosHeader->e_lfanew;

    // NT头: 签名
    printf("\nPE Signature: 0x%08X\n", pNTHeaders->Signature);

    // NT头: 文件头
    printf("\nPE File Header:\n");
    WORD wNumberOfSections = pNTHeaders->FileHeader.NumberOfSections; //找到存放节数的项，并打印
    printf("\tNumberOfSections: %u\n", wNumberOfSections);
    WORD wSizeOfOptionalHeader = pNTHeaders->FileHeader.SizeOfOptionalHeader; //找到可选头长度，并打印
    printf("\tSizeOfOptionalHeader: %u\n", wSizeOfOptionalHeader);

    // NT头: 可选头
    if (Is32BitPE(pFile))
        PrintOptionalHeader32(pFile);
    else 
        PrintOptionalHeader64(pFile);
}

VOID PrintSectionTable(PVOID pFile) {
    // 节表
    PIMAGE_DOS_HEADER pDosHeader = pFile;
    PIMAGE_NT_HEADERS32 pNTHeaders = pFile + pDosHeader->e_lfanew;
    WORD wSizeOfOptionalHeader = pNTHeaders->FileHeader.SizeOfOptionalHeader;
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((PVOID)pNTHeaders + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + wSizeOfOptionalHeader); //计算节表的位置
    printf("\nSection Table:\n");
    for (int i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++) {
        printf("\t[%d]\tName: %-8.8s\n", i + 1, pSectionHeader[i].Name);
        DWORD dwVirtualAddress = pSectionHeader[i].VirtualAddress;
        printf("\t\tVirtualAddress: 0x%08X\n", dwVirtualAddress);
        DWORD dwSizeOfRawData = pSectionHeader[i].SizeOfRawData;
        printf("\t\tSizeOfRawData: 0x%08X\n", dwSizeOfRawData);
        DWORD dwPointerToRawData = pSectionHeader[i].PointerToRawData;
        printf("\t\tPointerToRawData: 0x%08X\n", dwPointerToRawData);
    }
}

DWORD RVA2FOA(PVOID pFile, DWORD dwRVA) {
    PIMAGE_DOS_HEADER pDosHeader = pFile;
    PIMAGE_NT_HEADERS32 pNTHeaders = pFile + pDosHeader->e_lfanew;
    WORD wSizeOfOptionalHeader = pNTHeaders->FileHeader.SizeOfOptionalHeader;
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((PVOID)pNTHeaders + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + wSizeOfOptionalHeader); //计算节表的位置
    for (int i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++) {
        if (dwRVA >= pSectionHeader[i].VirtualAddress && dwRVA < (pSectionHeader[i].VirtualAddress + pSectionHeader[i].SizeOfRawData))
            return pSectionHeader[i].PointerToRawData + (dwRVA - pSectionHeader[i].VirtualAddress);
    }
    return 0;
}

VOID PrintExportTable(PVOID pFile) {
    // 导出表
    BOOL bIs32Bit = Is32BitPE(pFile);
    PIMAGE_DATA_DIRECTORY pImgDataDir;
    if (bIs32Bit) {
        PIMAGE_DOS_HEADER pDosHeader = pFile;
        PIMAGE_NT_HEADERS32 pNTHeaders = pFile + pDosHeader->e_lfanew;
        WORD wSizeOfOptionalHeader = pNTHeaders->FileHeader.SizeOfOptionalHeader;
        pImgDataDir = pNTHeaders->OptionalHeader.DataDirectory;
    } else {
        PIMAGE_DOS_HEADER pDosHeader = pFile;
        PIMAGE_NT_HEADERS64 pNTHeaders = pFile + pDosHeader->e_lfanew;
        WORD wSizeOfOptionalHeader = pNTHeaders->FileHeader.SizeOfOptionalHeader;
        pImgDataDir = pNTHeaders->OptionalHeader.DataDirectory;
    }
    if (pImgDataDir->Size) {
        printf("\nExport Table:\n");
        PIMAGE_EXPORT_DIRECTORY pExportDesc = (PIMAGE_EXPORT_DIRECTORY)(pFile + RVA2FOA(pFile, pImgDataDir->VirtualAddress));
        printf("\tName: %s\n", pFile + RVA2FOA(pFile, pExportDesc->Name));
        printf("\tNumberOfFunctions: %d\n", pExportDesc->NumberOfFunctions);
        printf("\tNumberOfNames: %d\n", pExportDesc->NumberOfNames);
        printf("\tAddressOfNameOrdinals: 0x%08X\n", pExportDesc->AddressOfNameOrdinals);
        PVOID pFunctionAddress = pFile + RVA2FOA(pFile, pExportDesc->AddressOfFunctions);
        printf("\tAddressOfFunctions: 0x%08X\n", pExportDesc->AddressOfFunctions);
        PDWORD adwNamesAddress = pFile + RVA2FOA(pFile, pExportDesc->AddressOfNames);
        printf("\tAddressOfNames: 0x%08X\n", pExportDesc->AddressOfNames);
        PWORD pwOrdinals = pFile + RVA2FOA(pFile, pExportDesc->AddressOfNameOrdinals);
        // 导出表: 函数
        if (pExportDesc->NumberOfFunctions) {
            printf("\tFunctions:\n");
            // 遍历所有导出函数
            for (int i = 0; i < pExportDesc->NumberOfFunctions; i++) {
                if (bIs32Bit) {
                    DWORD dwFunctionAddress = ((PDWORD)pFunctionAddress)[i];
                    printf("\t\tOrdinal: %d, Address: 0x%08X", i);
                } else {
                    ULONGLONG dwFunctionAddress = ((PULONGLONG)pFunctionAddress)[i];
                    printf("\t\tOrdinal: %d, Address: 0x%016llX", i);
                }
                // 遍历导出序数表，若存在该序号，则输出函数对应名称
                for (int j = 0; j < pExportDesc->NumberOfNames; j++) {
                    if (i == pwOrdinals[j]) {
                        DWORD pstrFuncName = (DWORD)(ULONGLONG)(pFile + RVA2FOA(pFile, adwNamesAddress[i]));
                        printf(", Name: %-30s", pstrFuncName);
                        break;
                    }
                }
                putchar('\n');
            }
        }
    }
}

VOID PrintImportTable32(PVOID pFile) {
    // 导入表
    PIMAGE_DOS_HEADER pDosHeader = pFile;
    PIMAGE_NT_HEADERS32 pNTHeaders = pFile + pDosHeader->e_lfanew;
    WORD wSizeOfOptionalHeader = pNTHeaders->FileHeader.SizeOfOptionalHeader;
    PIMAGE_DATA_DIRECTORY pDataDir = pNTHeaders->OptionalHeader.DataDirectory;
    DWORD dwImportTableSize = pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    if (dwImportTableSize) {
        printf("\nImport Table:\n");
        PIMAGE_IMPORT_DESCRIPTOR pImportTable = pFile + RVA2FOA(pFile, pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        // 遍历所有导入模块
        for (int i = 0; ; i++) {
            PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(&pImportTable[i]);
            if (pImportDesc->Name == 0) break;
            DWORD dwOriginalFirstThunk = (ULONGLONG)pFile + RVA2FOA(pFile, pImportDesc->OriginalFirstThunk);
            DWORD dwFirstThunk = (ULONGLONG)pFile + RVA2FOA(pFile, pImportDesc->FirstThunk);
            DWORD dwName = (ULONGLONG)pFile + RVA2FOA(pFile, pImportDesc->Name);
            printf("\tImport File Name: %s\n", dwName);
            if (dwOriginalFirstThunk == 0x00000000)
                dwOriginalFirstThunk = dwFirstThunk;
            PDWORD adwTrunkData = (PDWORD)(ULONGLONG)dwOriginalFirstThunk;
            // 遍历导入名称表的函数
            for (int i = 0; adwTrunkData[i] != 0; i++) {
                if (~(adwTrunkData[i] & IMAGE_ORDINAL_FLAG32)) {   // 名字导入
                    PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((PVOID)pFile + RVA2FOA(pFile, adwTrunkData[i]));
                    printf("\t\tHint: %d, Name: %s\n", pImportByName->Hint, pImportByName->Name);
                } else {                                        // 序号导入
                    DWORD FunNumber = (adwTrunkData[i] ^ IMAGE_ORDINAL_FLAG32);
                    printf("\t\tNumber: %-4d\n", FunNumber);
                }
            }
        };
    }
}

VOID PrintImportTable64(PVOID pFile) {
    // 导入表
    PIMAGE_DOS_HEADER pDosHeader = pFile;
    PIMAGE_NT_HEADERS64 pNTHeaders = pFile + pDosHeader->e_lfanew;
    WORD wSizeOfOptionalHeader = pNTHeaders->FileHeader.SizeOfOptionalHeader;
    PIMAGE_DATA_DIRECTORY pDataDir = pNTHeaders->OptionalHeader.DataDirectory;
    DWORD dwImportTableSize = pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    if (dwImportTableSize) {
        printf("\nImport Table:\n");
        PIMAGE_IMPORT_DESCRIPTOR pImportTable = pFile + RVA2FOA(pFile, pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        // 遍历所有导入模块
        for (int i = 0; ; i++) {
            PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(&pImportTable[i]);
            if (pImportDesc->Name == 0) break;
            DWORD dwOriginalFirstThunk = (ULONGLONG)pFile + RVA2FOA(pFile, pImportDesc->OriginalFirstThunk);
            DWORD dwFirstThunk = (ULONGLONG)pFile + RVA2FOA(pFile, pImportDesc->FirstThunk);
            DWORD dwName = (ULONGLONG)pFile + RVA2FOA(pFile, pImportDesc->Name);
            printf("\tImport File Name: %s\n", dwName);
            if (dwOriginalFirstThunk == 0x00000000)
                dwOriginalFirstThunk = dwFirstThunk;
            PULONGLONG aullTrunkData = (PULONGLONG)(ULONGLONG)dwOriginalFirstThunk;
            // 遍历导入名称表的函数
            for (int i = 0; aullTrunkData[i] != 0; i++) {
                if (~(aullTrunkData[i] & IMAGE_ORDINAL_FLAG64)) {   // 名字导入
                    PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((PVOID)pFile + RVA2FOA(pFile, (DWORD)aullTrunkData[i]));
                    printf("\t\tHint: %d, Name: %s\n", pImportByName->Hint, pImportByName->Name);
                } else {                                        // 序号导入
                    DWORD FunNumber = (DWORD)(aullTrunkData[i] ^ IMAGE_ORDINAL_FLAG64);
                    printf("\t\tNumber: %-4d\n", FunNumber);
                }
            }
        };
    }
}

VOID PrintImportTable(PVOID pFile){
    if (Is32BitPE(pFile)) 
        PrintImportTable32(pFile);
    else
        PrintImportTable64(pFile);
}

int main(int argc, char *argv[])
{
    char *szPEPath = argv[1];
    PrintPE(szPEPath);
    return 0;
}
