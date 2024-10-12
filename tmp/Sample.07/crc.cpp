#include "crc.h"

//////////////////////////////////////////////////////////////////////////////////////////////
// Процедура проверяет совпадение текущей и эталонной контрольных сумм для массива, адресуемого
// через дескриптор. Для расчета контрольных сумм используется одна из реализаций алгоритма CRC32.
BOOL CheckCRC32(PCrcDsc descriptor) {
	DWORD i, j, crc, crc_table[256], length = descriptor->Length; 
	PBYTE buffer = (PBYTE)descriptor->Addr;

	for (i = 0; i < 256; i++) {
		crc = i;
		for (j = 0; j < 8; j++) crc = crc & 1 ? (crc >> 1) ^ 0xEDB88320UL : crc >> 1;
		crc_table[i] = crc;
	}

	crc = 0xFFFFFFFFUL;
	while(length--) crc = crc_table[(crc ^ *buffer++) & 0xFF] ^ (crc >> 8);
	descriptor->CurrCrc = crc ^ 0xFFFFFFFFUL;
	if(descriptor->CurrCrc == descriptor->OrgCrc) return TRUE; 
	return FALSE;
}
