//*****************************************************************************
// Вспомогательная утилита, используемая на Post-build step'е сборки
// проекта защищенного приложения.
// Назначение: вычисление кодов коррекции ошибок (ECC) для помеченных 
// соответствующими маркерами участков данных/кода, размещение вычисленных
// кодов коррекции ошибок в указанном месте защищенного приложения. 
// Активация TLS_Callback'ов при наличии корректной TLS_Directory.
//
// Автор - Сергей Усков (a9wdk@yandex.ru, Telegram: @a9wdk)
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
// Глобальные переменные.

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

	// Разбираем командную строку
	if(argc < 2 || argc > 3) Help();
	if(argc == 3) {
		if(strcmp(argv[2], "/tls")) Help();
		Tls_Flag = TRUE;
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
// Процедура ищет в целевом файле дескриптор-контейнер для сохранения оригинального значения
// ImageBase, т.к. в случае использования технологии ASLR, оригинальное значение ImageBase
// произвольно перезаписывается системным загрузчиком. 

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

			// Найден дескриптор-контейнер для хранения ImageBase.
			printf("\n-------------------------- Saving the ImageBase original value -----------------------------\n \n");

			descriptor = (POrgPE)(buffer + i);
			printf("Descriptor_RAW . "); PrintDump(buffer, i);			// Маркер

			// Сохраняем оригинальное значение ImageBase.
			printf("> Saving ImageBase original value ................ ");
			descriptor->ImageBase = PEHeader->OptionalHeader.ImageBase;
			printf("Ok\n");

			// Заполняем мусором сигнатуру дескриптора.
			printf("> Descriptor's signature replacement ............. ");
			ReplaceData(startPtr, SignatureLength);
			printf("Ok\n");

			// Выводим дамп дескриптора после обработки.
			printf("Descriptor_RAW . "); PrintDump(buffer, i);			// Маркер
			printf("\n \n");
			return TRUE;
		}	
	}	
	return FALSE;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура ищет в целевом файле маркеры, описывающие данные, для которых необходимо расчитать ECC.
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
			
			// Найден маркер, описывающий данные, выводим дампы маркера, дескриптора, массива ECC и данных.
			done++;
			marker = (PEccDataMrk)(buffer + i);
			descriptor_raw = VAtoRAW(buffer, (PBYTE)marker->EccDscAddr);
			descriptor = (PEccDsc)(buffer + descriptor_raw);
			ecc_raw = (DWORD)(descriptor->Ecc - buffer);
			data_raw = VAtoRAW(buffer, (PBYTE)marker->Addr);
			printf("Marker found --> Region ID = %04d, Region length = %d(%Xh) byte(s)\n", marker->Id, marker->Length, marker->Length);
			printf("Marker_RAW ..... "); PrintDump(buffer, i);							// Маркер
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);				// Дескриптор
			printf("ECC_RAW ........ "); PrintDump(buffer, ecc_raw);					// ECC
			printf("DATA_RAW ....... "); PrintDump(buffer, data_raw);					// Данные
			
			// Проверка на превышение максимально допустимого размера кадра.
			if(marker->Length + marker->EccLength > GF_SIZE) {
				ConsolErrMsg("Error in marker #%04d! Frame size exceed %d bytes! Data + ECC = %d bytes.", 
					marker->Id, GF_SIZE * sizeof(GF_TYPE), marker->Length + marker->EccLength);
				MsgBox(UtilityName, MB_ICONERROR, "Error in marker #%04d!\nFrame size exceed %d bytes!\nData + ECC = %d bytes.", 
					marker->Id, GF_SIZE * sizeof(GF_TYPE), marker->Length + marker->EccLength);
				continue;
			}

			// Проверка на превышение максимально допустимой длины кода коррекции ошибок.
			if(marker->EccLength > sizeof(descriptor->Ecc)) {
				ConsolErrMsg("Error in marker #%04d! ECC length exceed %d bytes!", marker->Id, MaxEccLength);
				MsgBox(UtilityName, MB_ICONERROR, "Error in marker #%04d!\nECC length exceed %d bytes!", 
					marker->Id, MaxEccLength);
				continue;
			}

			// Заполняем данными дескриптор.
			printf("> Descriptor filling ............................. ");
			descriptor->NextDsc = LastDsc;			// Адрес последнего найденного дескриптора
			LastDsc = (PBYTE)marker->EccDscAddr;	// Теперь последний - текущий дескриптор
			descriptor->Addr = (PBYTE)marker->Addr;
			descriptor->Length = marker->Length;
			descriptor->EccLength = marker->EccLength;
			descriptor->Id = marker->Id;
			descriptor->ValidateFlag = FALSE;
			printf("Ok\n");

			// Расчитываем ECC			
			printf("> Calculation ECC ................................ ");
			RSLibInit(descriptor->Length, descriptor->EccLength, NULL);
			RSCalcECC(data_raw + buffer, ecc_raw + buffer);
			RSLibClose();
			printf("Ok\n");
			
			// Заполняем мусором маркер.
			printf("> Marker's content replacement ................... ");
			ReplaceData(startPtr, sizeof(EccDataMrk)); 
			printf("Ok\n");

			// Выводим дампы маркера, дескриптора и массива ECC.
			printf("Marker_RAW ..... "); PrintDump(buffer, i);							// Маркер
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);				// Дескриптор
			printf("ECC_RAW ........ "); PrintDump(buffer, ecc_raw);					// ECC
			printf("\n \n");
		}
	}
	return done;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура ищет в целевом файле маркеры, описывающие код, для которого необходимо расчитать ECC.
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
			
			// Найден маркер, описывающий код, выводим дампы маркера, дескриптора, массива ECC и кода.
			done++;
			marker = (PEccCodeMrk)(buffer + i);
			descriptor_raw = VAtoRAW(buffer, (PBYTE)marker->DescriptorAddr);
			descriptor = (PEccDsc)(buffer + descriptor_raw);
			ecc_raw = (DWORD)(descriptor->Ecc - buffer);
			code_raw = VAtoRAW(buffer, (PBYTE)marker->StartAddr);
			code_len = marker->EndAddr - marker->StartAddr;
			printf("Marker found --> Region ID = %04d, Region length = %d(%Xh) byte(s)\n", marker->Id, code_len, code_len);
			printf("Marker_RAW ..... "); PrintDump(buffer, i);							// Маркер
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);				// Дескриптор
			printf("ECC_RAW ........ "); PrintDump(buffer, ecc_raw);					// ECC
			printf("CODE_RAW ....... "); PrintDump(buffer, code_raw);					// Код

			// Проверка на превышение максимально допустимого размера кадра.
			if(code_len + marker->EccLength > GF_SIZE) {
				ConsolErrMsg("Error in marker #%04d! Frame size exceed %d bytes! Data + ECC = %d bytes.", 
					marker->Id, GF_SIZE * sizeof(GF_TYPE), code_len + marker->EccLength);
				MsgBox(UtilityName, MB_ICONERROR, "Error in marker #%04d!\nFrame size exceed %d bytes!\nData + ECC = %d bytes.", 
					marker->Id, GF_SIZE * sizeof(GF_TYPE), code_len + marker->EccLength);
				continue;
			}
			
			// Проверка на превышение максимально допустимой длины кода коррекции ошибок.
			if(marker->EccLength > sizeof(descriptor->Ecc)) {
				ConsolErrMsg("Error in marker #%04d! ECC length exceed %d bytes!", marker->Id, MaxEccLength);
				MsgBox(UtilityName, MB_ICONERROR, "Error in marker #%04d!\nECC length exceed %d bytes!", 
					marker->Id, MaxEccLength);
				continue;
			}

			// Заполняем данными дескриптор.
			printf("> Descriptor filling ............................. ");
			descriptor->NextDsc = LastDsc;				// Адрес последнего найденного дескриптора
			LastDsc = (PBYTE)marker->DescriptorAddr ;	// Теперь последний - текущий дескриптор
			descriptor->Addr = (PBYTE)marker->StartAddr;
			descriptor->Length = code_len;
			descriptor->EccLength = marker->EccLength;
			descriptor->Id = marker->Id;
			descriptor->ValidateFlag = FALSE;
			printf("Ok\n");
			
			// Расчитываем ECC			
			printf("> Calculation ECC ................................ ");
			RSLibInit(descriptor->Length, descriptor->EccLength, NULL);
			RSCalcECC(code_raw + buffer, ecc_raw + buffer);
			RSLibClose();
			printf("Ok\n");
			
			// Заполняем мусором маркер.
			printf("> Marker's content replacement ................... ");
			ReplaceCode(startPtr, sizeof(EccCodeMrk)); 
			printf("Ok\n");
			
			// Выводим дампы маркера, дескриптора и массива ECC.
			printf("Marker_RAW ..... "); PrintDump(buffer, i);							// Маркер
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);				// Дескриптор
			printf("ECC_RAW ........ "); PrintDump(buffer, ecc_raw);					// Массив ECC
			printf("\n \n");
		}
	}
	return done;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура ищет в целевом файле маркеры, описывающие код, для которого необходимо расчитать ECC.
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
			
			// Найден маркер, описывающий код, выводим дампы маркера, дескриптора, массива ECC и кода.
			done++;
			marker = (PEccLibsMrk)(buffer + i);
			descriptor_raw = VAtoRAW(buffer, (PBYTE)marker->DescriptorAddr);
			descriptor = (PEccDsc)(buffer + descriptor_raw);
			ecc_raw = (DWORD)(descriptor->Ecc - buffer);
			code_raw = VAtoRAW(buffer, (PBYTE)marker->EntryPointAddr);
			code_len = marker->CodeLength;
			printf("Marker found --> Region ID = %04d, Region length = %d(%Xh) byte(s)\n", marker->Id, code_len, code_len);
			printf("Marker_RAW ..... "); PrintDump(buffer, i);							// Маркер
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);				// Дескриптор
			printf("ECC_RAW ........ "); PrintDump(buffer, ecc_raw);					// ECC
			printf("LIB_CODE_RAW ... "); PrintDump(buffer, code_raw);					// Код

			// Проверка на превышение максимально допустимого размера кадра.
			if(code_len + marker->EccLength > GF_SIZE) {
				ConsolErrMsg("Error in marker #%04d! Frame size exceed %d bytes! Data + ECC = %d bytes.", 
					marker->Id, GF_SIZE * sizeof(GF_TYPE), code_len + marker->EccLength);
				MsgBox(UtilityName, MB_ICONERROR, "Error in marker #%04d!\nFrame size exceed %d bytes!\nData + ECC = %d bytes.", 
					marker->Id, GF_SIZE * sizeof(GF_TYPE), code_len + marker->EccLength);
				continue;
			}

			// Проверка на превышение максимально допустимой длины кода коррекции ошибок.
			if(marker->EccLength > sizeof(descriptor->Ecc)) {
				ConsolErrMsg("Error in marker #%04d! ECC length exceed %d bytes!", marker->Id, MaxEccLength);
				MsgBox(UtilityName, MB_ICONERROR, "Error in marker #%04d!\nECC length exceed %d bytes!", 
					marker->Id, MaxEccLength);
				continue;
			}
				
			// Заполняем данными дескриптор.
			printf("> Descriptor filling ............................. ");
			descriptor->NextDsc = LastDsc;				// Адрес последнего найденного дескриптора
			LastDsc = (PBYTE)marker->DescriptorAddr ;	// Теперь последний - текущий дескриптор
			descriptor->Addr = (PBYTE)marker->EntryPointAddr;
			descriptor->Length = code_len;
			descriptor->EccLength = marker->EccLength;
			descriptor->Id = marker->Id;
			descriptor->ValidateFlag = FALSE;
			printf("Ok\n");
			
			// Расчитываем ECC			
			printf("> Calculation ECC ................................ ");
			RSLibInit(descriptor->Length, descriptor->EccLength, NULL);
			RSCalcECC(code_raw + buffer, ecc_raw + buffer);
			RSLibClose();
			printf("Ok\n");
			
			// Заполняем мусором маркер.
			printf("> Marker's content replacement ................... ");
			ReplaceCode(startPtr, sizeof(EccLibsMrk)); 
			printf("Ok\n");
			
			// Выводим дампы маркера, дескриптора и массива ECC.
			printf("Marker_RAW ..... "); PrintDump(buffer, i);							// Маркер
			printf("Descriptor_RAW . "); PrintDump(buffer, descriptor_raw);				// Дескриптор
			printf("ECC_RAW ........ "); PrintDump(buffer, ecc_raw);					// Массив ECC
			printf("\n \n");
		}
	}	
	return done;
}

//////////////////////////////////////////////////////////////////////////////////////////////
// Процедура ищет в целевом файле дескриптор точки входа в односвязный список дескрипторов 
// _EccDsc и инициализирует её адресом последнего найденного дескриптора.
DWORD SearchDscListEntryPoint(PBYTE buffer, DWORD length) {
	DWORD i;
	PBYTE startPtr;
	PEccDscList marker;
	
	for(i = 0; i < length; i++) {
		startPtr = (PBYTE)memchr(buffer+i, FirstChar, length-i);
		if(startPtr == NULL) continue;
		i = startPtr - buffer;
		if(!memcmp(startPtr, EccDscListSig, SignatureLength)) {
			
			// Найден дескриптор точки входа, выводим дамп дескриптора.
			marker = (PEccDscList)(buffer + i);
			printf("Descriptor_RAW . "); PrintDump(buffer, i);			// Маркер
			
			// Инициализируем указатель точки входа адресом последнего найденного дескриптора.
			printf("> Entry Point initialization ..................... ");
			marker->EntryPoint = (PEccDsc)LastDsc;
			printf("Ok\n");
			
			// Заполняем мусором сигнатуру дескриптора.
			printf("> Descriptor's signature replacement ............. ");
			ReplaceData(startPtr, SignatureLength);
			printf("Ok\n");
			
			// Выводим дамп дескриптора после обработки.
			printf("Descriptor_RAW . "); PrintDump(buffer, i);			// Маркер
			printf("\n \n");
			return 0;
		}	
	}	

	if(MarkersDone) printf("\nDescriptor not found. List entry point is not created.\n \n");
		else printf("\nList is empty.\n \n");
	
	return 1;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура активирует TLS_Callback путем прописывания в PE-заголовок адреса и размера
//  TLS_Directory, созданного вручную в исходном коде примера.
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
			
			// Найден маркер TLS_Directory, выводим дамп маркера.
			marker = (PTLS)(buffer + i);
			tlsdir_rva = (DWORD)marker->TlsDirAddr - PEHeader->OptionalHeader.ImageBase;
			printf("\nMarker_RAW ..... "); PrintDump(buffer, i);			// Маркер
			
			// Инициализация TLS_Directory. Заполняем поля PE-заголовка целевого файла, касающиеся TLS.
			printf("> TLS_Directory initialization ................... ");
			PEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = tlsdir_rva;
			PEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = sizeof(IMAGE_TLS_DIRECTORY32);
			printf("Ok\n");
			
			// Заполняем мусором маркер.
			printf("> Marker's content replacement ................... ");
			ReplaceData(startPtr, sizeof(TLS));
			printf("Ok\n");
			
			// Выводим дамп маркера после обработки.
			printf("Marker_RAW ..... "); PrintDump(buffer, i);			// Маркер
			printf("\n \n");
			return 0;
		}	
	}	

	ConsolErrMsg("TLS_Directory address not found!");
	MsgBox(UtilityName, MB_ICONEXCLAMATION, "TLS_Directory address not found!");
	return 1;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура замещает содержимое указанного буфера на "мусор". 
void ReplaceData(PBYTE buffer, DWORD length) {
	for(DWORD i = 0; i < length; i++) buffer[i] = rand() % 0xFF;	// Генерируем мусор
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  Процедура замещает содержимое указанного буфера на "мусор". 
void ReplaceCode(PBYTE buffer, DWORD length) {
	DWORD i;
		
	if(length > 2 && length < 128) {
		// Если длина маркера допускает использование инструкции короткого перехода, то формируем 
		// jmp short вокруг всего маркера, а внутренности маркера забиваем мусором.
		buffer[0] = 0xEB;										// Опкод jmp short ххх
		buffer[1] = (BYTE)length - 2;							// Вычисляем операнд инструкции
		for(i = 2; i < length; i++) buffer[i] = rand() % 0xFF;	// Генерируем мусор
	} else {
		// Если маркер очень короткий или слишком длинный для использования короткого перехода, забиваем его NOP'ами, 
		for(i = 0; i < length; i++) buffer[i] = 0x90;	
	}
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