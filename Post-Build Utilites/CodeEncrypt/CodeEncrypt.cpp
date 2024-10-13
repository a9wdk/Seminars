//*****************************************************************************
// (v11) ��������������� �������, ������������ �� Post-build step'� ������
// ������� ����������� ����������.
// ����������: ������������ ���������� ���������������� ��������� ������� ����. 
//
// ����� - ������ ����� (Sergey.Uskov@safenet-inc.com, uskov@smtp.ru)
//*****************************************************************************

#include <windows.h>
#include <stdio.h>

#include "hasp_api.h"
#include "hasp_vcode.h"
#include "macros.h"

#define UtilityName		"Post-Build Code Encryption Tools"
#define UtilityVersion	"2.0"
#define UtilityDate	    "2013"

#define SignatureLength	  7
#define FirstChar		 '-'

//////////////////////////////////////////////////////////////////////////////////////////////
// ���������� ����������.

CHAR	SrcFile[255];
DWORD	dwFileSize, Done, MarkersDone = 0;
HANDLE	hSrcFile, hFileMapping;
LPVOID	lpFileMap;
PBYTE	Buffer;

//////////////////////////////////////////////////////////////////////////////////////////////

void	PrintDump(PBYTE buffer, DWORD offset);
DWORD   VAtoRAW(PBYTE Base, PBYTE VA);
BOOL	SavingImageBaseValue(PBYTE buffer, DWORD length);
DWORD	SearchExceptionData(PBYTE buffer, DWORD length);	
DWORD	SearchCustomEncryptCodeMarker(PBYTE buffer, DWORD length);		
DWORD	SearchKeyEncryptCodeMarker(PBYTE buffer, DWORD length);		
void	CustomEncryptCode(PBYTE buffer, DWORD length);
DWORD	KeyEncryptCode(PBYTE buffer, DWORD length, DWORD feature);
void	ReplaceData(PBYTE buffer, DWORD length);
void	ReplaceCode(PBYTE buffer, DWORD length);
void	ConsolErrMsg(PCHAR format, ...);
DWORD	MsgBox(PCHAR title, UINT style, PCHAR format, ...);

//////////////////////////////////////////////////////////////////////////////////////////////

int main(int argc, char* argv[]) {
	UINT major_ver, minor_ver, build_srv, build_num;
	hasp_get_version(&major_ver, &minor_ver, &build_srv, &build_num, NULL);

	printf("\n \n############################################################################################\n");
	printf("#                 %s, version %s, SU(C) %s                #\n", UtilityName, UtilityVersion, UtilityDate);
	printf("#                                  LDK API v%u.%u.%u.%u                                    #\n", major_ver, minor_ver, build_srv, build_num);
	printf("############################################################################################\n \n");

	// ��������� ��������� ������
	if(argc != 2) {
		printf("Usage:   CodeEncrypt <target file>\nExample: CodeEncrypt Sample.exe\n\n");
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

	printf("\n-------------------- Processing the Data site for Exception Handler ------------------------\n \n");

	Done = SearchExceptionData(Buffer, dwFileSize);
	if(!Done) printf("Data site for Exception Handler not found.\n \n");
		else  printf("Data site for Exception Handler processed: %d\n \n", Done);

	printf("\n------------------------ Custom Encrypt Code Markers processing ----------------------------\n \n");

	Done = SearchCustomEncryptCodeMarker(Buffer, dwFileSize);
	if(!Done) printf("Markers not found.\n \n");
	MarkersDone += Done;

	printf("\n-------------------------- Key Encrypt Code Markers processing -----------------------------\n \n");

	Done = SearchKeyEncryptCodeMarker(Buffer, dwFileSize);
	if(!Done) printf("Markers not found.\n \n");
	MarkersDone += Done;

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
// ��������� ���� � ������� ����� ����������, ��������������� ��� �������� ������ � ����������
// �������������� �������� (������ ��� ������ - 0F xx BC xx xx xx xx BC xx xx xx xx). � ������
// ����������� ����� ���������� ����� ���������� ����������� ������ �� ������� (0xBC - mov ESP, ...)
// �� ��������� ����� � ����� �������������� ������������� ����������� �������� � ������ �����������
// �������������� ��������  

DWORD SearchExceptionData(PBYTE buffer, DWORD length) {
	DWORD i, done = 0;
	PRaiseExcept DataSite;
	PBYTE startPtr;
	
	for(i = 0; i < length; i++) {
		startPtr = (PBYTE)memchr(buffer+i, FirstByteBadOpCode, length-i);
		if(startPtr == NULL) continue;
		i = startPtr - buffer;
		DataSite = (PRaiseExcept)startPtr ;
		if(DataSite->OpCode0 == ExceptionDataOpCode && DataSite->OpCode1 == ExceptionDataOpCode) {
			
			// ���������� ����������, ��������������� ��� �������� ������ � ���������� ��������������
			// �������� � ��������������� ������� ������ 0F xx BC xx xx xx xx BC xx xx xx xx
			done++;
			PrintDump(buffer, i);				// ���� �� ���������

			// �������� ������ ���������� �� ��������� �����.
			printf("OpCode replacement ............................. ");
			ReplaceData(&DataSite->OpCode0, 1); 	
			ReplaceData(&DataSite->OpCode1, 1); 	
			printf("Ok\n");

			PrintDump(buffer, i);				// ���� ����� ���������
			printf("\n \n");
		}
	}	
	return done;
}

//////////////////////////////////////////////////////////////////////////////////////////////
// ��������� ���� � ������� ����� ���������-�������, ����������� ������, ������� ���������� 
// ����������� ����������, ����� �������������� ��� ���������� ����������� ��������.

DWORD SearchCustomEncryptCodeMarker(PBYTE buffer, DWORD length) {
	DWORD i, descriptor_raw, code_raw, code_len, done = 0;
	PCstEncCodeMrk marker;		// ������
	PCstEncCodeDsc descriptor;	// ����������
	PBYTE startPtr;

	for(i = 0; i < length; i++) {
		startPtr = (PBYTE)memchr(buffer+i, FirstChar, length-i);
		if(startPtr == NULL) continue;
		i = startPtr - buffer;
		if(!memcmp(startPtr, CstEncCodeSig, SignatureLength)) {
			
			// ������� ���������-������, ����������� ���, ���������� ������������. ���������� � ������� 
			// �������� ���������, ���������� ����� ������.
			done++;
			marker = (PCstEncCodeMrk)(buffer + i);
			descriptor_raw = VAtoRAW(buffer, (PBYTE)marker->DescriptorAddr);
			descriptor = (PCstEncCodeDsc)(buffer + descriptor_raw);
			code_raw = VAtoRAW(buffer, (PBYTE)marker->StartAddr);
			code_len = marker->EndAddr - marker->StartAddr;

			// ������� ����� �������, ����������� � �������� ���� (��� �� ���������).
			printf("Marker_RAW ..... "); PrintDump(buffer, i);				// ������
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);	// ����������
			printf("CODE_RAW ....... "); PrintDump(buffer, code_raw);		// ���

			// ������������� ������� ���
			printf("> Encrypt the target CODE ........................ ");
			CustomEncryptCode(buffer + code_raw, code_len);
			printf("Ok, CODE length %d(%Xh) byte(s)\n", code_len, code_len);

			// ��������� ���������� �� ������ ������ �� �������.
			printf("> Descriptor filling ............................. ");
			descriptor->Addr = (PBYTE)marker->StartAddr;
			descriptor->Length = code_len;
			descriptor->ValidateFlag = FALSE;
			printf("Ok\n");
	
			// ��������� ������ ���������� �������� �����.
			printf("> Marker's content replacement ................... ");
			ReplaceCode(startPtr, sizeof(CstEncCodeMrk)); 	
			printf("Ok\n");

			// ������� ����� �������, ����������� � �������� ���� (��� ����� ���������).
			printf("Marker_RAW ..... "); PrintDump(buffer, i);				// ������
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);	// ����������
			printf("CODE_RAW ....... "); PrintDump(buffer, code_raw);		// ���
			printf("\n \n");
		}
	}	
	return done;
}

//////////////////////////////////////////////////////////////////////////////////////////////
// ��������� ���� � ������� ����� ���������-�������, ����������� ������, ������� ���������� 
// ����������� ����������, ����� �������������� ��� ���������� ����������� ��������.

DWORD SearchKeyEncryptCodeMarker(PBYTE buffer, DWORD length) {
	DWORD i, code_raw, code_len, descriptor_raw, session_raw, feature, status, done = 0;
	PKeyEncCodeMrk marker;		// ������
	PKeyEncCodeDsc descriptor;	// ����������
	PHaspSession session;
	PBYTE startPtr;
	
	for(i = 0; i < length; i++) {
		startPtr = (PBYTE)memchr(buffer+i, FirstChar, length-i);
		if(startPtr == NULL) continue;
		i = startPtr - buffer;
		if(!memcmp(startPtr, KeyEncCodeSig, SignatureLength)) {
			
			// ������� ���������-������, ����������� ���, ���������� ������������. ���������� � ������� 
			// �������� ���������, ���������� ����� ������.
			done++;
			marker = (PKeyEncCodeMrk)(buffer + i);
			descriptor_raw = VAtoRAW(buffer, (PBYTE)marker->DescriptorAddr);
			descriptor = (PKeyEncCodeDsc)(buffer + descriptor_raw);
			session_raw = VAtoRAW(buffer, (PBYTE)marker->KeySessionAddr);
			session = (PHaspSession)(buffer + session_raw);
			feature = session->feature;
			code_raw = VAtoRAW(buffer, (PBYTE)marker->StartAddr);
			code_len = marker->EndAddr - marker->StartAddr;
			
			// ������� ����� �������, ������������ � �������� ���� (��� �� ���������).
			printf("Marker_RAW ..... "); PrintDump(buffer, i);				// ������
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);	// ����������
			printf("KeySession_RAW . "); PrintDump(buffer, session_raw);	// ���������� ������ � ������
			printf("CODE_RAW ....... "); PrintDump(buffer, code_raw);		// ���
			
			// ������������� ������� ���
			printf("> Encrypt the target CODE ........................ ");
			status = KeyEncryptCode((PBYTE)(buffer + code_raw), code_len, feature);
			if(status == HASP_STATUS_OK) {
				printf("Ok, CODE length %d(%Xh) byte(s)\n", code_len, code_len);
				
				// ��������� ���������� �� ������ ������ �� �������.
				printf("> Descriptor filling ............................. ");
				descriptor->KeySessionAddr = (PHaspSession)marker->KeySessionAddr;
				descriptor->Addr = (PBYTE)marker->StartAddr;
				descriptor->Length = code_len;
				descriptor->ValidateFlag = FALSE;
				printf("Ok\n");

				// ��������� ������ ���������� �������� �����.
				printf("> Marker's content replacement ................... ");
				ReplaceCode(startPtr, sizeof(KeyEncCodeMrk)); 	
				printf("Ok\n");

				// ������� ����� �������, ����������� � �������� ���� (��� ����� ���������).
				printf("Marker_RAW ..... "); PrintDump(buffer, i);				// ������
				printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);	// ����������
				printf("CODE_RAW ....... "); PrintDump(buffer, code_raw);		// ���
				printf("\n \n");

			} else {

				printf("LDK API Error #%d\n", status);
				ConsolErrMsg("Code key-encryption error #%d", status);
				MsgBox(UtilityName, MB_ICONERROR, "Code key-encryption error #%d", status);
			}
		}
	}	
	return done;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  ��������� ������������� ��������� ������ � ������� �����. �������� � ��� ��������� 
//  (��������� �������� - XOR) ������ ��������������� ������������ � ������� �����.

#define XOR 0x53

void CustomEncryptCode(PBYTE buffer, DWORD length) {

	buffer[0] ^= XOR;
	for(DWORD i = 1; i < length; i++) buffer[i] ^= buffer[i-1];
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  ��������� ������������� ��������� ������ � �������������� ��������� ���� �����.

DWORD KeyEncryptCode(PBYTE buffer, DWORD length, DWORD feature) {
	DWORD status;
	hasp_handle_t handle = HASP_INVALID_HANDLE_VALUE;
	
	// ��������� Login �� Feature ID ��������� � ������� �������.
	status = hasp_login((hasp_feature_t)feature, vendor_code, &handle);
	if(status != HASP_STATUS_OK) return status; 
	
	// ������������� ������
	status = hasp_encrypt(handle, buffer, length);
	if(status != HASP_STATUS_OK) {
		hasp_logout(handle);
		return status; 
	}
	
	// ��������� ������ � ������
	status = hasp_logout(handle);
	return status;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  ��������� �������� ���������� ���������� ������ �� "�����". 

void ReplaceData(PBYTE buffer, DWORD length) {
	for(DWORD i = 0; i < length; i++) buffer[i] = rand() % 0xFF;	// ���������� �����
}

//////////////////////////////////////////////////////////////////////////////////////////////
// ��������� �������� ���������� ���������� ������ �� "�����". 
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