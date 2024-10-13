//*****************************************************************************
// ��������������� �������, ������������ �� Post-build step'� ������
// ������� ����������� ����������.
// ����������: ���������� ����� ��������� ������ (ECC) ��� ���������� 
// ���������������� ��������� �������� ������/����, ���������� �����������
// ����� ��������� ������ � ��������� ����� ����������� ����������. 
// ��������� TLS_Callback'�� ��� ������� ���������� TLS_Directory.
//
// ����� - ������ ����� (Sergey.Uskov@safenet-inc.com, uskov@smtp.ru)
//*****************************************************************************

#include <windows.h>
#include <stdio.h>

#include "RSLib.h"
#include "macros.h"

#define UtilityName		"Post-Build ECC Calculation Tools"
#define UtilityVersion	"2.0"
#define UtilityDate	    "2013"

#define SignatureLength	  7
#define FirstChar		 '-'

//////////////////////////////////////////////////////////////////////////////////////////////
// ���������� ����������.

CHAR	SrcFile[255];
DWORD	dwFileSize, Done, MarkersDone = 0, Tls_Flag = FALSE;
HANDLE	hSrcFile, hFileMapping;
LPVOID	lpFileMap;
PBYTE	Buffer, LastDsc = NULL;

//////////////////////////////////////////////////////////////////////////////////////////////

void	PrintDump(PBYTE buffer, DWORD offset);
DWORD   VAtoRAW(PBYTE Base, PBYTE VA);
BOOL	SavingImageBaseValue(PBYTE buffer, DWORD length);
DWORD	SearchEccDataMarker(PBYTE buffer, DWORD length);
DWORD	SearchEccCodeMarker(PBYTE buffer, DWORD length);
DWORD	SearchEccLibsMarker(PBYTE buffer, DWORD length);
DWORD	SearchDscListEntryPoint(PBYTE buffer, DWORD length);
DWORD	TLSCallbackActivation(PBYTE buffer, DWORD length);
void	ReplaceData(PBYTE buffer, DWORD length);
void	ReplaceCode(PBYTE buffer, DWORD length);
void	ConsolErrMsg(PCHAR format, ...);
DWORD	MsgBox(PCHAR title, UINT style, PCHAR format, ...);

//////////////////////////////////////////////////////////////////////////////////////////////

void Help(void) {
	printf("Usage:   ECCProtect <target file> [options]\n");
	printf("Options: /tls -> TLS_Callback entry point initialization.\n\n");
	printf("Example: ECCProtect Sample.exe\n");
	printf("         ECCProtect Sample.exe /tls\n\n");
	exit(-1);
}

//////////////////////////////////////////////////////////////////////////////////////////////

int main(int argc, char* argv[]) {
	printf("\n \n############################################################################################\n");
	printf("#                 %s, version %s, SU(C) %s                #\n", UtilityName, UtilityVersion, UtilityDate);
	printf("############################################################################################\n \n");

	// ��������� ��������� ������
	if(argc < 2 || argc > 3) Help();
	if(argc == 3) {
		if(strcmp(argv[2], "/tls")) Help();
		Tls_Flag = TRUE;
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

	printf("\n----------------------------- ECC Data Markers processing ----------------------------------\n \n");

	Done = SearchEccDataMarker(Buffer, dwFileSize);
	if(!Done) printf("Markers not found.\n \n");
	MarkersDone += Done;

	printf("\n-------------------------------- ECC Code Markers processing -------------------------------\n \n");
	
	Done = SearchEccCodeMarker(Buffer, dwFileSize);
	if(!Done) printf("Markers not found.\n \n");
	MarkersDone += Done;
	
	printf("\n-------------------------- ECC Library Code Markers processing -----------------------------\n \n");

	Done = SearchEccLibsMarker(Buffer, dwFileSize);
	if(!Done) printf("Markers not found.\n \n");
	MarkersDone += Done;
	
	printf("\n---------------------- ECC-Descriptor's list Entry Point searching -------------------------\n \n");
	
	Done = SearchDscListEntryPoint(Buffer, dwFileSize);
	
	if(Tls_Flag) {
		
		printf("\n-------------------------------- TLS_Callback activation -----------------------------------\n \n");
		
		Done = TLSCallbackActivation(Buffer, dwFileSize);
	}
	
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
//  ��������� ���� � ������� ����� �������, ����������� ������, ��� ������� ���������� ��������� ECC.
DWORD SearchEccDataMarker(PBYTE buffer, DWORD length) {
	DWORD i, descriptor_raw, ecc_raw, data_raw, done = 0;
	PBYTE startPtr;
	PEccDataMrk marker;
	PEccDsc descriptor;

	for(i = 0; i < length; i++) {
		startPtr = (PBYTE)memchr(buffer+i, FirstChar, length-i);
		if(startPtr == NULL) continue;
		i = startPtr - buffer;
		if(!memcmp(startPtr, EccDataSig, SignatureLength)) {
			
			// ������ ������, ����������� ������, ������� ����� �������, �����������, ������� ECC � ������.
			done++;
			marker = (PEccDataMrk)(buffer + i);
			descriptor_raw = VAtoRAW(buffer, (PBYTE)marker->EccDscAddr);
			descriptor = (PEccDsc)(buffer + descriptor_raw);
			ecc_raw = (DWORD)(descriptor->Ecc - buffer);
			data_raw = VAtoRAW(buffer, (PBYTE)marker->Addr);
			printf("Marker found --> Region ID = %04d, Region length = %d(%Xh) byte(s)\n", marker->Id, marker->Length, marker->Length);
			printf("Marker_RAW ..... "); PrintDump(buffer, i);							// ������
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);				// ����������
			printf("ECC_RAW ........ "); PrintDump(buffer, ecc_raw);					// ECC
			printf("DATA_RAW ....... "); PrintDump(buffer, data_raw);					// ������
			
			// �������� �� ���������� ����������� ����������� ������� �����.
			if(marker->Length + marker->EccLength > GF_SIZE) {
				ConsolErrMsg("Error in marker #%04d! Frame size exceed %d bytes! Data + ECC = %d bytes.", 
					marker->Id, GF_SIZE * sizeof(GF_TYPE), marker->Length + marker->EccLength);
				MsgBox(UtilityName, MB_ICONERROR, "Error in marker #%04d!\nFrame size exceed %d bytes!\nData + ECC = %d bytes.", 
					marker->Id, GF_SIZE * sizeof(GF_TYPE), marker->Length + marker->EccLength);
				continue;
			}

			// �������� �� ���������� ����������� ���������� ����� ���� ��������� ������.
			if(marker->EccLength > sizeof(descriptor->Ecc)) {
				ConsolErrMsg("Error in marker #%04d! ECC length exceed %d bytes!", marker->Id, MaxEccLength);
				MsgBox(UtilityName, MB_ICONERROR, "Error in marker #%04d!\nECC length exceed %d bytes!", 
					marker->Id, MaxEccLength);
				continue;
			}

			// ��������� ������� ����������.
			printf("> Descriptor filling ............................. ");
			descriptor->NextDsc = LastDsc;			// ����� ���������� ���������� �����������
			LastDsc = (PBYTE)marker->EccDscAddr;	// ������ ��������� - ������� ����������
			descriptor->Addr = (PBYTE)marker->Addr;
			descriptor->Length = marker->Length;
			descriptor->EccLength = marker->EccLength;
			descriptor->Id = marker->Id;
			descriptor->ValidateFlag = FALSE;
			printf("Ok\n");

			// ����������� ECC			
			printf("> Calculation ECC ................................ ");
			RSLibInit(descriptor->Length, descriptor->EccLength, NULL);
			RSCalcECC(data_raw + buffer, ecc_raw + buffer);
			RSLibClose();
			printf("Ok\n");
			
			// ��������� ������� ������.
			printf("> Marker's content replacement ................... ");
			ReplaceData(startPtr, sizeof(EccDataMrk)); 
			printf("Ok\n");

			// ������� ����� �������, ����������� � ������� ECC.
			printf("Marker_RAW ..... "); PrintDump(buffer, i);							// ������
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);				// ����������
			printf("ECC_RAW ........ "); PrintDump(buffer, ecc_raw);					// ECC
			printf("\n \n");
		}
	}
	return done;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  ��������� ���� � ������� ����� �������, ����������� ���, ��� �������� ���������� ��������� ECC.
DWORD SearchEccCodeMarker(PBYTE buffer, DWORD length) {
	DWORD i, descriptor_raw, ecc_raw, code_raw, code_len, done = 0;
	PBYTE startPtr;
	PEccCodeMrk marker;
	PEccDsc descriptor;
	
	for(i = 0; i < length; i++) {
		startPtr = (PBYTE)memchr(buffer+i, FirstChar, length-i);
		if(startPtr == NULL) continue;
		i = startPtr - buffer;
		if(!memcmp(startPtr, EccCodeSig, SignatureLength)) {
			
			// ������ ������, ����������� ���, ������� ����� �������, �����������, ������� ECC � ����.
			done++;
			marker = (PEccCodeMrk)(buffer + i);
			descriptor_raw = VAtoRAW(buffer, (PBYTE)marker->DescriptorAddr);
			descriptor = (PEccDsc)(buffer + descriptor_raw);
			ecc_raw = (DWORD)(descriptor->Ecc - buffer);
			code_raw = VAtoRAW(buffer, (PBYTE)marker->StartAddr);
			code_len = marker->EndAddr - marker->StartAddr;
			printf("Marker found --> Region ID = %04d, Region length = %d(%Xh) byte(s)\n", marker->Id, code_len, code_len);
			printf("Marker_RAW ..... "); PrintDump(buffer, i);							// ������
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);				// ����������
			printf("ECC_RAW ........ "); PrintDump(buffer, ecc_raw);					// ECC
			printf("CODE_RAW ....... "); PrintDump(buffer, code_raw);					// ���

			// �������� �� ���������� ����������� ����������� ������� �����.
			if(code_len + marker->EccLength > GF_SIZE) {
				ConsolErrMsg("Error in marker #%04d! Frame size exceed %d bytes! Data + ECC = %d bytes.", 
					marker->Id, GF_SIZE * sizeof(GF_TYPE), code_len + marker->EccLength);
				MsgBox(UtilityName, MB_ICONERROR, "Error in marker #%04d!\nFrame size exceed %d bytes!\nData + ECC = %d bytes.", 
					marker->Id, GF_SIZE * sizeof(GF_TYPE), code_len + marker->EccLength);
				continue;
			}
			
			// �������� �� ���������� ����������� ���������� ����� ���� ��������� ������.
			if(marker->EccLength > sizeof(descriptor->Ecc)) {
				ConsolErrMsg("Error in marker #%04d! ECC length exceed %d bytes!", marker->Id, MaxEccLength);
				MsgBox(UtilityName, MB_ICONERROR, "Error in marker #%04d!\nECC length exceed %d bytes!", 
					marker->Id, MaxEccLength);
				continue;
			}

			// ��������� ������� ����������.
			printf("> Descriptor filling ............................. ");
			descriptor->NextDsc = LastDsc;				// ����� ���������� ���������� �����������
			LastDsc = (PBYTE)marker->DescriptorAddr ;	// ������ ��������� - ������� ����������
			descriptor->Addr = (PBYTE)marker->StartAddr;
			descriptor->Length = code_len;
			descriptor->EccLength = marker->EccLength;
			descriptor->Id = marker->Id;
			descriptor->ValidateFlag = FALSE;
			printf("Ok\n");
			
			// ����������� ECC			
			printf("> Calculation ECC ................................ ");
			RSLibInit(descriptor->Length, descriptor->EccLength, NULL);
			RSCalcECC(code_raw + buffer, ecc_raw + buffer);
			RSLibClose();
			printf("Ok\n");
			
			// ��������� ������� ������.
			printf("> Marker's content replacement ................... ");
			ReplaceCode(startPtr, sizeof(EccCodeMrk)); 
			printf("Ok\n");
			
			// ������� ����� �������, ����������� � ������� ECC.
			printf("Marker_RAW ..... "); PrintDump(buffer, i);							// ������
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);				// ����������
			printf("ECC_RAW ........ "); PrintDump(buffer, ecc_raw);					// ������ ECC
			printf("\n \n");
		}
	}
	return done;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  ��������� ���� � ������� ����� �������, ����������� ���, ��� �������� ���������� ��������� ECC.
DWORD SearchEccLibsMarker(PBYTE buffer, DWORD length) {
	DWORD i, descriptor_raw, ecc_raw, code_raw, code_len, done = 0;
	PBYTE startPtr;
	PEccLibsMrk marker;
	PEccDsc descriptor;
	
	for(i = 0; i < length; i++) {
		startPtr = (PBYTE)memchr(buffer+i, FirstChar, length-i);
		if(startPtr == NULL) continue;
		i = startPtr - buffer;
		if(!memcmp(startPtr, EccLibsSig, SignatureLength)) {
			
			// ������ ������, ����������� ���, ������� ����� �������, �����������, ������� ECC � ����.
			done++;
			marker = (PEccLibsMrk)(buffer + i);
			descriptor_raw = VAtoRAW(buffer, (PBYTE)marker->DescriptorAddr);
			descriptor = (PEccDsc)(buffer + descriptor_raw);
			ecc_raw = (DWORD)(descriptor->Ecc - buffer);
			code_raw = VAtoRAW(buffer, (PBYTE)marker->EntryPointAddr);
			code_len = marker->CodeLength;
			printf("Marker found --> Region ID = %04d, Region length = %d(%Xh) byte(s)\n", marker->Id, code_len, code_len);
			printf("Marker_RAW ..... "); PrintDump(buffer, i);							// ������
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);				// ����������
			printf("ECC_RAW ........ "); PrintDump(buffer, ecc_raw);					// ECC
			printf("LIB_CODE_RAW ... "); PrintDump(buffer, code_raw);					// ���

			// �������� �� ���������� ����������� ����������� ������� �����.
			if(code_len + marker->EccLength > GF_SIZE) {
				ConsolErrMsg("Error in marker #%04d! Frame size exceed %d bytes! Data + ECC = %d bytes.", 
					marker->Id, GF_SIZE * sizeof(GF_TYPE), code_len + marker->EccLength);
				MsgBox(UtilityName, MB_ICONERROR, "Error in marker #%04d!\nFrame size exceed %d bytes!\nData + ECC = %d bytes.", 
					marker->Id, GF_SIZE * sizeof(GF_TYPE), code_len + marker->EccLength);
				continue;
			}

			// �������� �� ���������� ����������� ���������� ����� ���� ��������� ������.
			if(marker->EccLength > sizeof(descriptor->Ecc)) {
				ConsolErrMsg("Error in marker #%04d! ECC length exceed %d bytes!", marker->Id, MaxEccLength);
				MsgBox(UtilityName, MB_ICONERROR, "Error in marker #%04d!\nECC length exceed %d bytes!", 
					marker->Id, MaxEccLength);
				continue;
			}
				
			// ��������� ������� ����������.
			printf("> Descriptor filling ............................. ");
			descriptor->NextDsc = LastDsc;				// ����� ���������� ���������� �����������
			LastDsc = (PBYTE)marker->DescriptorAddr ;	// ������ ��������� - ������� ����������
			descriptor->Addr = (PBYTE)marker->EntryPointAddr;
			descriptor->Length = code_len;
			descriptor->EccLength = marker->EccLength;
			descriptor->Id = marker->Id;
			descriptor->ValidateFlag = FALSE;
			printf("Ok\n");
			
			// ����������� ECC			
			printf("> Calculation ECC ................................ ");
			RSLibInit(descriptor->Length, descriptor->EccLength, NULL);
			RSCalcECC(code_raw + buffer, ecc_raw + buffer);
			RSLibClose();
			printf("Ok\n");
			
			// ��������� ������� ������.
			printf("> Marker's content replacement ................... ");
			ReplaceCode(startPtr, sizeof(EccLibsMrk)); 
			printf("Ok\n");
			
			// ������� ����� �������, ����������� � ������� ECC.
			printf("Marker_RAW ..... "); PrintDump(buffer, i);							// ������
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);				// ����������
			printf("ECC_RAW ........ "); PrintDump(buffer, ecc_raw);					// ������ ECC
			printf("\n \n");
		}
	}	
	return done;
}

//////////////////////////////////////////////////////////////////////////////////////////////
// ��������� ���� � ������� ����� ���������� ����� ����� � ����������� ������ ������������ 
// _EccDsc � �������������� � ������� ���������� ���������� �����������.
DWORD SearchDscListEntryPoint(PBYTE buffer, DWORD length) {
	DWORD i;
	PBYTE startPtr;
	PEccDscList marker;
	
	for(i = 0; i < length; i++) {
		startPtr = (PBYTE)memchr(buffer+i, FirstChar, length-i);
		if(startPtr == NULL) continue;
		i = startPtr - buffer;
		if(!memcmp(startPtr, EccDscListSig, SignatureLength)) {
			
			// ������ ���������� ����� �����, ������� ���� �����������.
			marker = (PEccDscList)(buffer + i);
			printf("Descriptor_RAW . "); PrintDump(buffer, i);			// ������
			
			// �������������� ��������� ����� ����� ������� ���������� ���������� �����������.
			printf("> Entry Point initialization ..................... ");
			marker->EntryPoint = (PEccDsc)LastDsc;
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
//  ��������� ���������� TLS_Callback ����� ������������ � PE-��������� ������ � �������
//  TLS_Directory, ���������� ������� � �������� ���� �������.
DWORD TLSCallbackActivation(PBYTE buffer, DWORD length) {
	PIMAGE_NT_HEADERS32 PEHeader  = (PIMAGE_NT_HEADERS32)(buffer + ((PIMAGE_DOS_HEADER)buffer)->e_lfanew);
	DWORD i, tlsdir_rva;
	PBYTE startPtr;
	PTLS marker;

	for(i = 0; i < length; i++) {
		startPtr = (PBYTE)memchr(buffer+i, FirstChar, length-i);
		if(startPtr == NULL) continue;
		i = startPtr - buffer;
		if(!memcmp(startPtr, TLSDirSign, SignatureLength)) {
			
			// ������ ������ TLS_Directory, ������� ���� �������.
			marker = (PTLS)(buffer + i);
			tlsdir_rva = (DWORD)marker->TlsDirAddr - PEHeader->OptionalHeader.ImageBase;
			printf("\nMarker_RAW ..... "); PrintDump(buffer, i);			// ������
			
			// ������������� TLS_Directory. ��������� ���� PE-��������� �������� �����, ���������� TLS.
			printf("> TLS_Directory initialization ................... ");
			PEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = tlsdir_rva;
			PEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = sizeof(IMAGE_TLS_DIRECTORY32);
			printf("Ok\n");
			
			// ��������� ������� ������.
			printf("> Marker's content replacement ................... ");
			ReplaceData(startPtr, sizeof(TLS));
			printf("Ok\n");
			
			// ������� ���� ������� ����� ���������.
			printf("Marker_RAW ..... "); PrintDump(buffer, i);			// ������
			printf("\n \n");
			return 0;
		}	
	}	

	ConsolErrMsg("TLS_Directory address not found!");
	MsgBox(UtilityName, MB_ICONEXCLAMATION, "TLS_Directory address not found!");
	return 1;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  ��������� �������� ���������� ���������� ������ �� "�����". 
void ReplaceData(PBYTE buffer, DWORD length) {
	for(DWORD i = 0; i < length; i++) buffer[i] = rand() % 0xFF;	// ���������� �����
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  ��������� �������� ���������� ���������� ������ �� "�����". 
void ReplaceCode(PBYTE buffer, DWORD length) {
	DWORD i;
		
	if(length > 2 && length < 128) {
		// ���� ����� ������� ��������� ������������� ���������� ��������� ��������, �� ��������� 
		// jmp short ������ ����� �������, � ������������ ������� �������� �������.
		buffer[0] = 0xEB;										// ����� jmp short ���
		buffer[1] = (BYTE)length - 2;							// ��������� ������� ����������
		for(i = 2; i < length; i++) buffer[i] = rand() % 0xFF;	// ���������� �����
	} else {
		// ���� ������ ����� �������� ��� ������� ������� ��� ������������� ��������� ��������, �������� ��� NOP'���, 
		for(i = 0; i < length; i++) buffer[i] = 0x90;	
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  ����� ��������� � ������ ����� (��� ����������) � ���� ������.
void ConsolErrMsg(PCHAR format, ...) {
	char buffer[128];
	va_list arg_ptr;
	DWORD i, gap, len = 92;

	va_start(arg_ptr, format);
	vsprintf_s(buffer, sizeof(buffer), format, arg_ptr);
	va_end(arg_ptr);

	gap = (len - 2 - strlen(buffer)) / 2;

	printf("\n \n");
	for(i = 0; i < len; i++) printf("\xdb");
	printf("\n");
	for(i = 0; i < gap; i++) printf("\xdb");
	printf(" %s ", buffer);
	if((len - strlen(buffer)) % 2) printf(" ");
	for(i = 0; i < gap; i++) printf("\xdb");
	printf("\n");
	for(i = 0; i < len; i++) printf("\xdb");
	printf("\n \n");
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  ����� MessageBox � ��������� ������� ������.
DWORD MsgBox(PCHAR title, UINT style, PCHAR format, ...) {
	char buffer[1024];
	va_list arg_ptr;

	va_start(arg_ptr, format);
	vsprintf_s(buffer, sizeof(buffer), format, arg_ptr);
	va_end(arg_ptr);
	return MessageBox(NULL, buffer, title, style);
}