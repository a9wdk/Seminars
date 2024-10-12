//*****************************************************************************
// ��������������� �������, ������������ �� Post-build step'� ������
// ������� ����������� ����������.
// ����������: ���������� ���-�������� ��� ���������� ���������������� 
// ��������� �������� ������/���� (� �������������� ��������� CRC32), 
// ���������� ����������� ���-�������� � ��������� ����� ����������� ����������. 
//
// ����� - ������ ����� (Sergey.Uskov@safenet-inc.com, uskov@smtp.ru)
//*****************************************************************************

#include <windows.h>
#include <stdio.h>

#include "macros.h"

#define UtilityName		"Post-Build CRC Calculation Tools"
#define UtilityVersion	"2.0"
#define UtilityDate	    "2013"

#define SignatureLength	  7
#define FirstChar		 '-'

//////////////////////////////////////////////////////////////////////////////////////////////
// ���������� ����������.

CHAR	SrcFile[255], Str[255];
DWORD	dwFileSize, Done, MarkersDone = 0;
HANDLE	hSrcFile, hFileMapping;
LPVOID	lpFileMap;
PBYTE	Buffer, LastDsc = NULL;

//////////////////////////////////////////////////////////////////////////////////////////////

void	PrintDump(PBYTE buffer, DWORD offset);
DWORD   VAtoRAW(PBYTE Base, PBYTE VA);
BOOL	SavingImageBaseValue(PBYTE buffer, DWORD length);
DWORD	SearchCrcDataMarker(PBYTE buffer, DWORD length);
DWORD	SearchCrcCodeMarker(PBYTE buffer, DWORD length);
DWORD	SearchCrcLibsMarker(PBYTE buffer, DWORD length);
DWORD	SearchDscListEntryPoint(PBYTE buffer, DWORD length);
void	ReplaceData(PBYTE buffer, DWORD length);
void	ReplaceCode(PBYTE buffer, DWORD length);
DWORD	CalcCRC32(PBYTE buffer, DWORD length);

//////////////////////////////////////////////////////////////////////////////////////////////

int main(int argc, char* argv[]) {
	printf("\n \n############################################################################################\n");
	printf("#                 %s, version %s, SU(C) %s                #\n", UtilityName, UtilityVersion, UtilityDate);
	printf("############################################################################################\n \n");

	// ��������� ��������� ������
	if(argc != 2) {
		printf("Usage:   CRC32Protect <target file>\nExample: CRC32Protect Sample.exe\n\n");
		return -1;
	}
	sprintf_s(SrcFile, sizeof(SrcFile), "%s", argv[1]); 

	// ��������� ������� ����
	printf("Open the target file ........................... %s -> ", SrcFile);
	hSrcFile = CreateFile(SrcFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if(hSrcFile == INVALID_HANDLE_VALUE) {
		printf("Error\n");
		return -2;
	}
	printf("Ok\n");

	// ������� ������-����������� ��� ��������� �����
	printf("Create the FileMapping object .................. ");
	dwFileSize = GetFileSize(hSrcFile, NULL);
	hFileMapping = CreateFileMapping(hSrcFile, NULL, PAGE_READWRITE, 0, dwFileSize, NULL);
	if(hFileMapping == NULL) {
		printf("Error\n");
		return -3;
	}	
	printf("Ok\n");
	
	// ��������� ����������� ����� �� ������. � ���������� lpFileMap ����� ������� ��������� �� ������������ ������� ������
	printf("Maps a view of a file into the address space ... ");
	lpFileMap = MapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if(lpFileMap == 0) {
		printf("Error\n");
		return -4;
	}	
	Buffer = (PBYTE)lpFileMap;
	printf("Ok\n \n");

	srand(GetTickCount());

	SavingImageBaseValue(Buffer, dwFileSize);

	printf("\n----------------------------- CRC32 Data Markers processing --------------------------------\n \n");

	Done = SearchCrcDataMarker(Buffer, dwFileSize);
	if(!Done) printf("Markers not found.\n \n");
	MarkersDone += Done;

	printf("\n---------------------------- CRC32 Code Markers processing ---------------------------------\n \n");
	
	Done = SearchCrcCodeMarker(Buffer, dwFileSize);
	if(!Done) printf("Markers not found.\n \n");
	MarkersDone += Done;
	
	printf("\n------------------------- CRC32 Library Code Markers processing ----------------------------\n \n");
	
	Done = SearchCrcLibsMarker(Buffer, dwFileSize);
	if(!Done) printf("Markers not found.\n \n");
	MarkersDone += Done;
	
	printf("\n---------------------- CRC-Descriptor's list Entry Point searching -------------------------\n \n");

	Done = SearchDscListEntryPoint(Buffer, dwFileSize);

	printf("\n--------------------- Processing is completed. %.2d marker(s) are found ----------------------\n \n", MarkersDone);

	// �������� ����������� ����� � ����������� ������������� ���������� �������-�����������
	printf("\nClose the target file .......................... ");
	UnmapViewOfFile(lpFileMap);
	CloseHandle(hFileMapping);	
	printf("Ok\n \n");

	return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  ��������� �������� HEX/ASCII-���� ��������� ������ (16 ����) � ���������� ��������.
void PrintDump(PBYTE buffer, const DWORD offset) {
	DWORD i;

	printf("%08X ", offset);
	for(i = 0; i < 16; i++) printf(" %02X", buffer[offset+i]);
	printf("  ");
	for(i = 0; i < 16; i++) printf("%c", buffer[offset+i] > 0x1F && buffer[offset+i] < 0xFF ? buffer[offset+i] : '.');
	printf("\n");
}

//////////////////////////////////////////////////////////////////////////////////////////////
// ��������� ��������� VA-����� ������� � ������� ����� � �������� ������������ ������ ����� 
// �����, ������������ � ����� �� ������ Base.

#define ALIGN_DOWN(x, align)  (x & ~(align - 1))										//������������ ����
#define ALIGN_UP(x, align)    ((x & (align - 1)) ? ALIGN_DOWN(x, align) + align : x)	//������������ �����

DWORD VAtoRAW(PBYTE Base, PBYTE VA) {
	DWORD VirtualAddress, PointerToRawData, i;
	BOOL flag = FALSE;

	PIMAGE_NT_HEADERS32 PEHeader  = (PIMAGE_NT_HEADERS32)(Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew);
	DWORD RVA                     = (DWORD)(VA - PEHeader->OptionalHeader.ImageBase);
	DWORD SectionAlign            = PEHeader->OptionalHeader.SectionAlignment;
	WORD NumberOfSection          = PEHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER Section = (PIMAGE_SECTION_HEADER)(PEHeader->FileHeader.SizeOfOptionalHeader + 
		(DWORD)&(PEHeader->FileHeader) + sizeof(IMAGE_FILE_HEADER));

	for(i = 0; i < NumberOfSection; i++) {
		if((RVA >= Section->VirtualAddress) && 
			(RVA <  Section->VirtualAddress + ALIGN_UP(Section->Misc.VirtualSize, SectionAlign))) {

				VirtualAddress   = Section->VirtualAddress;
				PointerToRawData = Section->PointerToRawData;
				flag = TRUE;
				break;
		}
		Section++;
	}
	if(flag) return(RVA - VirtualAddress + PointerToRawData); else return(RVA);
}

//////////////////////////////////////////////////////////////////////////////////////////////
// ��������� ���� � ������� ����� ����������-��������� ��� ���������� ������������� ��������
// ImageBase, �.�. � ������ ������������� ���������� ASLR, ������������ �������� ImageBase
// ����������� ���������������� ��������� �����������. 

BOOL SavingImageBaseValue(PBYTE buffer, DWORD length) {
	DWORD i;
	PBYTE startPtr;
	POrgPE descriptor;
	PIMAGE_NT_HEADERS32 PEHeader  = (PIMAGE_NT_HEADERS32)(buffer + ((PIMAGE_DOS_HEADER)buffer)->e_lfanew);

	for(i = 0; i < length; i++) {
		startPtr = (PBYTE)memchr(buffer+i, FirstChar, length-i);
		if(startPtr == NULL) continue;
		i = startPtr - buffer;
		if(!memcmp(startPtr, OrgPESig, SignatureLength)) {

			// ������ ����������-��������� ��� �������� ImageBase.
			printf("\n-------------------------- Saving the ImageBase original value -----------------------------\n \n");

			descriptor = (POrgPE)(buffer + i);
			printf("Descriptor_RAW . "); PrintDump(buffer, i);			// ������

			// ��������� ������������ �������� ImageBase.
			printf("> Saving ImageBase original value ................ ");
			descriptor->ImageBase = PEHeader->OptionalHeader.ImageBase;
			printf("Ok\n");

			// ��������� ������� ��������� �����������.
			printf("> Descriptor's signature replacement ............. ");
			ReplaceData(startPtr, SignatureLength);
			printf("Ok\n");

			// ������� ���� ����������� ����� ���������.
			printf("Descriptor_RAW . "); PrintDump(buffer, i);			// ������
			printf("\n \n");
			return TRUE;
		}	
	}	
	return FALSE;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  ��������� ���� � ������� ����� ���������, ����������� ������, ������� ���������� �����������.
DWORD SearchCrcDataMarker(PBYTE buffer, DWORD length) {
	DWORD i, descriptor_raw, data_raw, done = 0;
	PBYTE startPtr;
	PCrcDataMrk marker;
	PCrcDsc descriptor;

	for(i = 0; i < length; i++) {
		startPtr = (PBYTE)memchr(buffer+i, FirstChar, length-i);
		if(startPtr == NULL) continue;
		i = startPtr - buffer;
		if(!memcmp(startPtr, CrcDataSig, SignatureLength)) {
			
			// ������ ������, ����������� ������, ������� ����� ������� � ������.
			done++;
			marker = (PCrcDataMrk)startPtr;
			descriptor_raw = VAtoRAW(buffer, (PBYTE)marker->CrcDscAddr);
			descriptor = (PCrcDsc)(buffer + descriptor_raw);
			data_raw = VAtoRAW(buffer, (PBYTE)marker->Addr);
			printf("Marker found --> Region ID = %04d, Region length = %d(%Xh) byte(s)\n", marker->Id, marker->Length, marker->Length);
			printf("Marker_RAW ..... "); PrintDump(buffer, i);					// ������
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);		// ����������
			printf("DATA_RAW ....... "); PrintDump(buffer, data_raw);			// ������
			
			// ��������� ������� ���������-���������, ������� ����������� �������� ����������� �����.
			printf("> Calculation CRC ................................ ");
			descriptor->NextDsc = LastDsc;					// ����� ���������� ���������� �����������
			LastDsc = (PBYTE)marker->CrcDscAddr;			// ������ ��������� - ������� ����������
			descriptor->Addr = (PBYTE)marker->Addr;
			descriptor->Length = marker->Length;
			descriptor->OrgCrc = CalcCRC32(buffer + data_raw, descriptor->Length);
			descriptor->CurrCrc = 0;
			descriptor->Id = marker->Id;
			descriptor->ValidateFlag = FALSE;
			printf("%08Xh\n", descriptor->OrgCrc);
			
			// ��������� ������� ������.
			printf("> Marker's content replacement ................... ");
			ReplaceData(startPtr, sizeof(CrcDataMrk)); 
			printf("Ok\n");

			// ������� ����� ������� � ���������.
			printf("Marker_RAW ..... "); PrintDump(buffer, i);					// ������
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);		// ����������
			printf("\n \n");
		}
	}	
	return done;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  ��������� ���� � ������� ����� ���������, ����������� ������, ������� ���������� �����������.
DWORD SearchCrcCodeMarker(PBYTE buffer, DWORD length) {
	DWORD i, descriptor_raw, code_raw, code_len, done = 0;
	PBYTE startPtr;
	PCrcCodeMrk marker;
	PCrcDsc descriptor;
	
	for(i = 0; i < length; i++) {
		startPtr = (PBYTE)memchr(buffer+i, FirstChar, length-i);
		if(startPtr == NULL) continue;
		i = startPtr - buffer;
		if(!memcmp(startPtr, CrcCodeSig, SignatureLength)){
			
			// ������ ������, ����������� ���, ������� ����� ������� � ����.
			done++;
			marker = (PCrcCodeMrk)startPtr;
			descriptor_raw = VAtoRAW(buffer, (PBYTE)marker->DescriptorAddr);
			descriptor = (PCrcDsc)(buffer + descriptor_raw);
			code_raw = VAtoRAW(buffer, (PBYTE)marker->StartAddr);
			code_len = marker->EndAddr - marker->StartAddr;
			printf("Marker found --> Region ID = %04d, Region length = %d(%Xh) byte(s)\n", marker->Id, code_len, code_len);
			printf("Marker_RAW ..... "); PrintDump(buffer, i);					// ������
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);		// ����������
			printf("CODE_RAW ....... "); PrintDump(buffer, code_raw);			// ���
			
			// ��������� ������� ���������-���������, ������� ����������� �������� ����������� �����.
			printf("> Calculation CRC ................................ ");
			descriptor->NextDsc = LastDsc;					// ����� ���������� ���������� �����������
			LastDsc = (PBYTE)marker->DescriptorAddr ;		// ������ ��������� - ������� ����������
			descriptor->Addr = (PBYTE)marker->StartAddr;
			descriptor->Length = code_len;
			descriptor->OrgCrc = CalcCRC32(buffer + code_raw, descriptor->Length);
			descriptor->CurrCrc = 0;
			descriptor->Id = marker->Id;
			descriptor->ValidateFlag = FALSE;
			printf("%08Xh\n", descriptor->OrgCrc);
	
			// ��������� ������� ������.
			printf("> Marker's content replacement ................... ");
			ReplaceCode(startPtr, sizeof(CrcCodeMrk)); 	
			printf("Ok\n");
			
			// ������� ����� ������� � ���������.
			printf("Marker_RAW ..... "); PrintDump(buffer, i);					// ������
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);		// ����������
			printf("\n \n");
		}
	}	
	return done;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  ��������� ���� � ������� ����� ���������, ����������� ������, ������� ���������� �����������.
DWORD SearchCrcLibsMarker(PBYTE buffer, DWORD length) {
	DWORD i, descriptor_raw, code_raw, code_len, done = 0;
	PBYTE startPtr;
	PCrcLibsMrk marker;
	PCrcDsc descriptor;
	
	for(i = 0; i < length; i++) {
		startPtr = (PBYTE)memchr(buffer+i, FirstChar, length-i);
		if(startPtr == NULL) continue;
		i = startPtr - buffer;
		if(!memcmp(startPtr, CrcLibsSig, SignatureLength)){
			
			// ������ ������, ����������� ���, ������� ����� ������� � ����.
			done++;
			marker = (PCrcLibsMrk)startPtr;
			descriptor_raw = VAtoRAW(buffer, (PBYTE)marker->DescriptorAddr);
			descriptor = (PCrcDsc)(buffer + descriptor_raw);
			code_raw = VAtoRAW(buffer, (PBYTE)marker->EntryPointAddr);
			code_len = marker->CodeLength ;
			printf("Marker found --> Region ID = %04d, Region length = %d(%Xh) byte(s)\n", marker->Id, code_len, code_len);
			printf("Marker_RAW ..... "); PrintDump(buffer, i);					// ������
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);		// ����������
			printf("LIB_CODE_RAW ... "); PrintDump(buffer, code_raw);			// ���
			
			// ��������� ������� ���������-���������, ������� ����������� �������� ����������� �����.
			printf("> Calculation CRC ................................ ");
			descriptor->NextDsc = LastDsc;						// ����� ���������� ���������� �����������
			LastDsc = (PBYTE)marker->DescriptorAddr;			// ������ ��������� - ������� ����������
			descriptor->Addr = (PBYTE)marker->EntryPointAddr;
			descriptor->Length = code_len;
			descriptor->OrgCrc = CalcCRC32(buffer + code_raw, descriptor->Length);
			descriptor->CurrCrc = 0;
			descriptor->Id = marker->Id;
			descriptor->ValidateFlag = FALSE;
			printf("%08Xh\n", descriptor->OrgCrc);
			
			// ��������� ������� ������.
			printf("> Marker's content replacement ................... ");
			ReplaceCode(startPtr, sizeof(CrcLibsMrk)); 	
			printf("Ok\n");
			
			// ������� ����� ������� � ���������.
			printf("Marker_RAW ..... "); PrintDump(buffer, i);					// ������
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);		// ����������
			printf("\n \n");
		}
	}	
	return done;
}

//////////////////////////////////////////////////////////////////////////////////////////////
// ��������� ���� � ������� ����� ���������� ����� ����� � ����������� ������ ������������
// _CrcDsc � �������������� � ������� ���������� ���������� �����������.
DWORD SearchDscListEntryPoint(PBYTE buffer, DWORD length) {
	DWORD i;
	PBYTE startPtr;
	PCrcDscList marker;

	for(i = 0; i < length; i++) {
		startPtr = (PBYTE)memchr(buffer+i, FirstChar, length-i);
		if(startPtr == NULL) continue;
		i = startPtr - buffer;
		if(!memcmp(startPtr, CrcDscListSig, SignatureLength)) {

			// ������ ���������� ����� �����, ������� ���� �����������.
			marker = (PCrcDscList)(buffer + i);
			printf("Descriptor_RAW . "); PrintDump(buffer, i);			// ������

			// �������������� ��������� ����� ����� ������� ���������� ���������� �����������.
			printf("> Entry Point initialization ..................... ");
			marker->EntryPoint = (PCrcDsc)LastDsc;
			printf("Ok\n");

			// ��������� ������� ��������� �����������.
			printf("> Descriptor's signature replacement ............. ");
			ReplaceData(startPtr, SignatureLength);
			printf("Ok\n");

			// ������� ���� ����������� ����� ���������.
			printf("Descriptor_RAW . "); PrintDump(buffer, i);			// ������
			printf("\n \n");
			return 0;
		}	
	}	

	if(MarkersDone) printf("\nDescriptor not found. List entry point is not created.\n \n");
		else printf("\nList is empty.\n \n");

	return 1;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  ��������� �������� ���������� ���������� ������ � ������� �� "�����". 
void ReplaceData(PBYTE buffer, DWORD length) {
	for(DWORD i = 0; i < length; i++) buffer[i] = rand() % 0xFF;	// ���������� �����
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  ��������� �������� ���������� ���������� ������ � ����� �� "�����". 
void ReplaceCode(PBYTE buffer, DWORD length) {
	DWORD i;
		
	if(length > 2 && length < 128) {
		// ���� ����� ������� ��������� ������������� ���������� ��������� ��������, �� ��������� 
		// jmp short ������ ����� �������, � ������������ ������� �������� �������.
		buffer[0] = 0xEB;										// ����� jmp short ���
		buffer[1] = (BYTE)(length - 2);							// ��������� ������� ����������
		for(i = 2; i < length; i++) buffer[i] = rand() % 0xFF;	// ���������� �����
	} else {
		// ���� ������ ����� �������� ��� ������� ������� ��� ������������� ��������� ��������, �������� ��� NOP'���, 
		for(i = 0; i < length; i++) buffer[i] = 0x90;	
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ����������� �����, ��������� ���� �� ���������� ��������� CRC32.
DWORD CalcCRC32(PBYTE buffer, DWORD length) {
    DWORD i, j, crc, crc_table[256]; 
	
    for (i = 0; i < 256; i++) {
        crc = i;
        for (j = 0; j < 8; j++) crc = crc & 1 ? (crc >> 1) ^ 0xEDB88320UL : crc >> 1;
        crc_table[i] = crc;
    }
	
    crc = 0xFFFFFFFFUL;
    while(length--) crc = crc_table[(crc ^ *buffer++) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFUL;
}