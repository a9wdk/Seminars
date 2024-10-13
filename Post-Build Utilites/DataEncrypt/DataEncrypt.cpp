//***************************************************************************** 
// Вспомогательная утилита, используемая на Post-build step'е сборки
// проекта защищенного приложения.
// Назначение: зашифрование помеченных соответствующими маркерами данных. 
//
// Автор - Сергей Усков (a9wdk@yandex.ru, Telegram: @a9wdk)
//*****************************************************************************

#include <windows.h>
#include <stdio.h>

#include "hasp_api.h"
#include "hasp_vcode.h"
#include "macros.h"

#define UtilityName		"Post-Build Data Encryption Tools"
#define UtilityVersion	"2.0"
#define UtilityDate	    "2013"

#define SignatureLength	  7
#define FirstChar		 '-'

//////////////////////////////////////////////////////////////////////////////////////////////
// Глобальные переменные.

CHAR	SrcFile[255];
DWORD	dwFileSize, Done, MarkersDone = 0;
HANDLE	hSrcFile, hFileMapping;
LPVOID	lpFileMap;
PBYTE	Buffer;

//////////////////////////////////////////////////////////////////////////////////////////////

void			PrintDump(PBYTE buffer, DWORD offset);
DWORD			VAtoRAW(PBYTE Base, PBYTE VA);
DWORD			SearchCustomEncDataMarker(PBYTE buffer, DWORD length);	
DWORD			SearchKeyEncDataMarker(PBYTE buffer, DWORD length);			
void			CustomEncryptData(PBYTE buffer, DWORD length);
hasp_status_t	KeyEncryptData(PBYTE buffer, DWORD length, DWORD feature);
void			ReplaceData(PBYTE buffer, DWORD length);
void			ConsolErrMsg(PCHAR format, ...);
DWORD			MsgBox(PCHAR title, UINT style, PCHAR format, ...);

//////////////////////////////////////////////////////////////////////////////////////////////

int main(int argc, char* argv[]) {
	UINT major_ver, minor_ver, build_srv, build_num;
	hasp_get_version(&major_ver, &minor_ver, &build_srv, &build_num, NULL);

	printf("\n \n############################################################################################\n");
	printf("#                 %s, version %s, SU(C) %s                #\n", UtilityName, UtilityVersion, UtilityDate);
	printf("#                                  LDK API v%u.%u.%u.%u                                    #\n", major_ver, minor_ver, build_srv, build_num);
	printf("############################################################################################\n \n");

	// Разбираем командную строку
	if(argc != 2) {
		printf("Usage:   DataEncrypt <target file>\nExample: DataEncrypt Sample.exe\n\n");
		return -1;
	}
	sprintf_s(SrcFile, sizeof(SrcFile), "%s", argv[1]); 

	// Открываем целевой файл
	printf("Open the target file ........................... %s -> ", SrcFile);
	hSrcFile = CreateFile(SrcFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if(hSrcFile == INVALID_HANDLE_VALUE) {
		printf("Error\n");
		return -2;
	}
	printf("Ok\n");

	// Создаем объект-отображение для исходного файла
	printf("Create the FileMapping object .................. ");
	dwFileSize = GetFileSize(hSrcFile, NULL);
	hFileMapping = CreateFileMapping(hSrcFile, NULL, PAGE_READWRITE, 0, dwFileSize, NULL);
	if(hFileMapping == NULL) {
		printf("Error\n");
		return -3;
	}	
	printf("Ok\n");
	
	// Выполняем отображение файла на память. В переменную lpFileMap будет записан указатель на отображаемую область памяти
	printf("Maps a view of a file into the address space ... ");
	lpFileMap = MapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if(lpFileMap == 0) {
		printf("Error\n");
		return -4;
	}	
	Buffer = (PBYTE)lpFileMap;
	printf("Ok\n");

	srand(GetTickCount());

	printf("\n \n------------------------ Custom Encrypt Data Markers processing ----------------------------\n \n");

	Done = SearchCustomEncDataMarker(Buffer, dwFileSize);
	if(!Done) printf("Markers not found.\n \n");
	MarkersDone += Done;
	
	printf("\n--------------------------- Key Encrypt Data Markers processing ----------------------------\n \n");
	
	Done = SearchKeyEncDataMarker(Buffer, dwFileSize);
	if(!Done) printf("Markers not found.\n \n");
	MarkersDone += Done;
	
	printf("\n--------------------- Processing is completed. %.2d marker(s) are found ----------------------\n \n", MarkersDone);

	// Отменяем отображение файла и освобождаем идентификатор созданного объекта-отображения
	printf("\nClose the target file .......................... ");
	UnmapViewOfFile(lpFileMap);
	CloseHandle(hFileMapping);	
	printf("Ok\n \n");

	return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура печатает HEX/ASCII-дамп параграфа памяти (16 байт) с указанного смещения.
void PrintDump(PBYTE buffer, const DWORD offset) {
	DWORD i;

	printf("%08X ", offset);
	for(i = 0; i < 16; i++) printf(" %02X", buffer[offset+i]);
	printf("  ");
	for(i = 0; i < 16; i++) printf("%c", buffer[offset+i] > 0x1F && buffer[offset+i] < 0xFF ? buffer[offset+i] : '.');
	printf("\n");
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Процедура переводит VA-адрес объекта в целевом файле в смещение относительно начала этого 
// файла, загруженного в буфер по адресу Base.

#define ALIGN_DOWN(x, align)  (x & ~(align - 1))										//выравнивание вниз
#define ALIGN_UP(x, align)    ((x & (align - 1)) ? ALIGN_DOWN(x, align) + align : x)	//выравнивание вверх

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
// Процедура ищет в целевом файле маркеры, описывающие данные, которые необходимо зашифровать
// custom-алгоритмом.

DWORD SearchCustomEncDataMarker(PBYTE buffer, DWORD length) {
	DWORD i, data_raw, done = 0;
	PCstEncDataMrk marker;
	PBYTE startPtr;
	
	for(i = 0; i < length; i++) {
		startPtr = (PBYTE)memchr(buffer+i, FirstChar, length-i);
		if(startPtr == NULL) continue;
		i = startPtr - buffer;
		if(!memcmp(startPtr, CstEncDataSig, SignatureLength)) {
			
			// Найден маркер, описывающий данные, выводим дампы маркера и данных.
			done++;
			marker = (PCstEncDataMrk)startPtr;
			data_raw = VAtoRAW(buffer, (PBYTE)marker->Addr);
			printf("Marker_RAW ..... "); PrintDump(buffer, i);			// Маркер
			printf("DATA_RAW ....... "); PrintDump(buffer, data_raw);	// Данные

			// Зашифровываем данные. 
			printf("> Encrypt the target DATA ........................ ");
			CustomEncryptData(buffer + data_raw, marker->Length);
			printf("Ok, DATA length %d(%Xh) byte(s)\n", marker->Length, marker->Length);

			// Заполняем мусором маркер.
			printf("> Marker's content replacement ................... ");
			ReplaceData(startPtr, sizeof(CstEncDataMrk));
			printf("Ok\n");

			// Выводим дампы маркера и данных.
			printf("Marker_RAW ..... "); PrintDump(buffer, i);			// Маркер
			printf("DATA_RAW ....... "); PrintDump(buffer, data_raw);	// Данные
			printf("\n \n");
		}
	}	
	return done;
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Процедура ищет в целевом файле маркеры, описывающие данные, которые необходимо зашифровать
// через ключ.

DWORD SearchKeyEncDataMarker(PBYTE buffer, DWORD length) {
	DWORD i, data_raw, done = 0;
	PKeyEncDataMrk marker;
	hasp_status_t status;
	PBYTE startPtr;
	
	for(i = 0; i < length; i++) {
		startPtr = (PBYTE)memchr(buffer+i, FirstChar, length-i);
		if(startPtr == NULL) continue;
		i = startPtr - buffer;
		if(!memcmp(startPtr, KeyEncDataSig, SignatureLength)) {
			
			// Найден маркер, описывающий данные, выводим дампы маркера и данных.
			done++;
			marker = (PKeyEncDataMrk)startPtr;
			data_raw = VAtoRAW(buffer, (PBYTE)marker->Addr);
			printf("Marker_RAW ..... "); PrintDump(buffer, i);			// Маркер
			printf("DATA_RAW ....... "); PrintDump(buffer, data_raw);	// Данные
			
			// Зашифровываем данные. 
			printf("> Encrypt the target DATA ........................ ");
			status = KeyEncryptData(buffer + data_raw, marker->Length, marker->Feature);
			if(status == HASP_STATUS_OK) {
				printf("Ok, DATA length %d(%Xh) byte(s)\n", marker->Length, marker->Length);

				// Заполняем мусором маркер.
				printf("> Marker's content replacement ................... ");
				ReplaceData(startPtr, sizeof(KeyEncDataMrk));
				printf("Ok\n");

				// Выводим дампы маркера и данных.
				printf("Marker_RAW ..... "); PrintDump(buffer, i);			// Маркер
				printf("DATA_RAW ....... "); PrintDump(buffer, data_raw);	// Данные
				printf("\n \n");

			} else {

				printf("LDK API Error #%d\n", status);
				ConsolErrMsg("Data key-encryption error #%d", status);
				MsgBox(UtilityName, MB_OK | MB_ICONERROR, "Data key-encryption error #%d", status);
			}
		}
	}	
	return done;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура зашифровывает указанные данные в целевом файле. Алгоритм и его параметры 
//  (начальное значение - XOR) должны соответствовать используемым в целевом файле.

#define XOR 0x53

void CustomEncryptData(PBYTE buffer, DWORD length) {
	
	buffer[0] ^= XOR;
	for(DWORD i = 1; i < length; i++) buffer[i] ^= buffer[i-1];
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура зашифровывает указанные данные с использованием указанного Feature ID

hasp_status_t KeyEncryptData(PBYTE buffer, DWORD length, DWORD feature) {
	hasp_status_t status;
	hasp_handle_t handle = HASP_INVALID_HANDLE_VALUE;
	
	// Выполняем Login на Feature ID указанный в маркере региона.
	status = hasp_login((hasp_feature_t)feature, vendor_code, &handle);
	if(status != HASP_STATUS_OK) return status; 
	
	// Зашифровываем регион
	status = hasp_encrypt(handle, buffer, length);
	if(status != HASP_STATUS_OK) {
		hasp_logout(handle);
		return status; 
	}
	
	// Закрываем сессию с ключом
	status = hasp_logout(handle);
	return status;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура замещает содержимое указанного буфера с данными на "мусор". 
void ReplaceData(PBYTE buffer, DWORD length) {
	for(DWORD i = 0; i < length; i++) buffer[i] = rand() % 0xFF;	// Генерируем мусор
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Вывод сообщения в черной рамке (для заметности) в окно вывода.
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
//  Вызов MessageBox с форматным выводом строки.
DWORD MsgBox(PCHAR title, UINT style, PCHAR format, ...) {
	char buffer[1024];
	va_list arg_ptr;

	va_start(arg_ptr, format);
	vsprintf_s(buffer, sizeof(buffer), format, arg_ptr);
	va_end(arg_ptr);
	return MessageBox(NULL, buffer, title, style);
}