//************************************************************[0x083F3C2E24]***
// ������������ ����� ����-��������, �������������� ��� ����� ������ ��. 
// �������������� ������ RS8 � RS16, ����������� �������� � ������� ������
// �������� �� 256 ���� (������) � �� 128 ����� (���������) ��������������.
// 
// RSLib.cpp - ���������� ������� ���������� RSLib, ������ M.03.17
//
// ����� - ������ ����� (Sergey.Uskov@safenet-inc.com, uskov@smtp.ru)
// ��������� ����� � 2010, ������ ����� (SU)
//*****************************************************************************

#include <windows.h>
#include <stdio.h>

#include "RSLib.h"

#define int3 _asm int 3;

static DWORD	DataLen        = 0;		// ����� ������ (�� � ������, � � ��������� �������!)
static DWORD	ECCLen         = 0;		// ����� ECC (�� � ������, � � ��������� �������!)
static DWORD	WorkPolyLen    = 0;		// ������� �������� ECCLen/2 + 1 
static DWORD	CurGPolyDegree = 0;		// ������� ������� ������������ �������� 
static DWORD	Errors         = 0;		// ���������� ��������� ������ �������� ��������� ������ 
										// (���������� - ���������� ��������� ������ � ����� ������)

static HANDLE	RSHeap      = NULL;		// ����, ������ ����� �������������� ������ ��� ��������
static GF_TYPE *nGF         = NULL;		// ���������� ���� �����,	 ����� GF_SIZE * 3
static GF_TYPE *rGF         = NULL;		// �������� ���� �����,		 ����� GF_SIZE
static GF_TYPE *GenPoly     = NULL;		// ����������� �������,      ����� ECCLen + 1
static GF_TYPE *Syndrome    = NULL;		// ������� �������� ������,  ����� ECCLen
static GF_TYPE *Lambda      = NULL;		// ������� ��������� ������, ����� ECCLen/2 + 1 
static GF_TYPE *ErrorLocs   = NULL;		// �������� ������,          ����� ECCLen/2 + 1
static GF_TYPE *Omega       = NULL;		// ������� ������� ������,   ����� ECCLen/2 + 1

static GF_TYPE *TmpLambda   = NULL;		// ��������������� ������� ��������� ������, ����� ECCLen/2 + 1
static GF_TYPE *TmpPoly     = NULL;		// ��������������� ������� ������ ����������, ����� ECCLen + ECCLen/2 + 1
static GF_TYPE *TmpPolyMul  = NULL;		// ��������������� ������� ��� ��������� polyMul, ����� ECCLen + ECCLen/2 + 1

//================================================================================================================

// ������ ������������ �������� ��� �������� ����� ���� ECC. ����� ����������� ������� �� ���� ����������.
// � ������ RS16, ��� ������ ECC, ����������� 3-4 ������, ��� � ������������� ����� ��������� ������������
// ��������. ������ ������������� ���������� �� �������� � ����������� Intel Pentium M 2.0 GHz (����� RS16):
// 
// ����� ECC														1 �����		2 ������	4 ������
// ������ ������������ ��������										0.17 ���.	1.15 ���.	8.36 ���.
// ��������� ������������� ���������� ������ (data =  16 �����) 	0.35 ���.	0.7  ���.	1.4  ���.
// ��������� ������������� ���������� ������ (data = 124 ������)	0.65 ���.	1.3  ���.	2.65 ���.
//
// �������, ��� ������ ECC, ����������� 3-4 ������ ����� �������������� ����� �� ����������� �����������
// ������� �� ����� ������ ����������, � ������� ��� � ������� ���� � �������� ��� ������ ����������. 
// ��� ��������� ������������ �������� � ������� ���� ������������� ������� RSGetGenPoly(), ������� �����
// ������� ����� ����� RSLibInit().
static void  CalcGenPoly(DWORD ecclen);

// ������ ��������� ������ � ������� ������.
static DWORD CalcErrors(void);

// ����� ��������� �� ������ �� ���� MessageBox � ���������� �������������� ������� � ���������� ������ ����������.
static void ErrMsgBox(char *title, char *format, ...);

//================================== �������� ��� ���������� � ����� ����� =======================================

// �������� ���������
static void	polyAdd(GF_TYPE *res, GF_TYPE *poly1, GF_TYPE *poly2, DWORD len);
// ��������� ���������
static void	polySub(GF_TYPE *res, GF_TYPE *poly1, GF_TYPE *poly2, DWORD len);
// ��������������� �������� 
static void	polyScaling(GF_TYPE *poly, GF_TYPE factor, DWORD len);
// ����� �������� �� shift ������� "�����"
static void	polyLShift(GF_TYPE *poly, GF_TYPE shift, DWORD len);					
// ��������� ���������
static void	polyMul(GF_TYPE *res, GF_TYPE *poly1, DWORD p1len, GF_TYPE *poly2, DWORD p2len);	
// ���������� ������� �� ������� ������ �������� �� ������
#ifdef FULL 
static void	polyRest(GF_TYPE *rest, GF_TYPE *poly1, DWORD p1len, GF_TYPE *poly2, DWORD p2len);	
#endif // FULL

//=================================== �������� ��� ������� � ����� ����� ========================================= 

#define gAdd(a, b)	(a ^ b)													// �������� 
#define gSub(a, b)	(a ^ b)													// ��������� 
#define gMul(a, b)	((a == 0 || b == 0) ? 0 : nGF[rGF[a] + rGF[b]])			// ��������� 
#define gDiv(a, b)	((b == 0) ? -1 : (a == 0) ? 0 : nGF[rGF[a] - rGF[b]])	// ������� 

//================================================================================================================

//////////////////////////////////////////////////////////////////////////
// ������������� ����������. �������� ������������ ������� ���������� � ���������� �� � 
// ����������� ������������ ���������. ��������� ��� ����������������� ������������ ������
// ��� ����� ����� � ���� ������������ ���������. ������������� ����� ����� �, ���
// �������������, ������ ������������ �������� ��� �������� ����� ECC.  
void RSLibInit(DWORD datalen, DWORD ecclen, BYTE *genpoly) {
	DWORD i, n, new_ecclen;

	// ����������� ����� ������ � ECC (�� � ������, � � ��������� �������!)
	DataLen = datalen / sizeof(GF_TYPE);
	new_ecclen = ecclen / sizeof(GF_TYPE);

	// �������� ������������ ������� ECC. ��� ������ RS8 ����������� ������ ���������� 2 ����� (��� 
	// �������������� ������ �����), ��� RS16 - 2 ����� (4 �����) ��� �������������� ������ �����. 
	// ������ ����������� ������������� ����������� ������� polyRest().
	if(new_ecclen < 2) 
		ErrMsgBox("RSLibInit Error", "ECC size less then %d bytes!", sizeof(GF_TYPE) * 2);

	// �������� ������������ ������� ECC. ��� ������ RS8 ������������ ������ ���������� 170 ���� (��� 
	// ������� �������������� ���� ���������� 85 ���� �����), ��� RS16 - 43690 ���� (~85 �����) ��� 
	// ������� �������������� ���� ���������� 21845 ���� (~42 K�����) �����. 
	if(new_ecclen > ECC_MAX) 
		ErrMsgBox("RSLibInit Error", "ECC size exceed %d bytes!", sizeof(GF_TYPE) * ECC_MAX);

	// �������� ������������ ������� �����. ������ ����� (datalen + ecclen) �� ������ ���������
	// ������ ���� ����� (256 ���� ��� ������ RS8, 65535 ���� (128 �����) ��� RS16).
	if(DataLen + new_ecclen > GF_MAX_INDEX) 
		ErrMsgBox("RSLibInit Error", "Frame size exceed %d bytes!", SizeInBytes(GF_MAX_INDEX));

	// ���������, ��������� �� ������������� ��� ����� �����, ���� ECCLen == 0, �� ��� - ������ �����
	if(ECCLen == 0) {

		// ������ �������������� ����, �� ������� � ���������� ����� ������������ ������.
		RSHeap = HeapCreate(0, (4 * GF_SIZE + 8 * ECC_MAX) * sizeof(GF_TYPE), 0);
		if(RSHeap == NULL) ErrMsgBox("RSLibInit Error", "Memory allocation error for RSHeap!");

		// �������� ������ ��� ��� ����� ����������� ���� �����. ��� ���������� ��� ����, �����
		// �������� �������������� �������� �������� � ��������� � ���������� ���������/�������
		nGF = (GF_TYPE *)HeapAlloc(RSHeap, 0, SizeInBytes(GF_SIZE) * 3);
		if(nGF == NULL) ErrMsgBox("RSLibInit Error", "Memory allocation error for nGF!");

		// �������� ������ ��� �������� ���� �����
		rGF = (GF_TYPE *)HeapAlloc(RSHeap, 0, SizeInBytes(GF_SIZE));
		if(rGF == NULL) ErrMsgBox("RSLibInit Error", "Memory allocation error for rGF!");

		// ������� ����� - �������
		nGF += GF_MAX_INDEX;

		// ��������� ����������� ���� ����� ��� ������� �����
		for(i = nGF[0] = 1, nGF[GF_MAX_INDEX] = 0; i < GF_MAX_INDEX; i++) {
			n = nGF[i-1] << 1;
			if(n < GF_MAX_INDEX) nGF[i] = (GF_TYPE)n; 
				else nGF[i] = (GF_TYPE)(n ^ INIT_POLY);
		}
	
		// ��������� ��������� ���� �����
		for(i = 0; i < GF_SIZE; i++) rGF[nGF[i]] = (GF_TYPE)i; 

		// ���������� ��������� ���� ����� ����������� ���� ����� ���������� �� ������� �����. 
		for(i = 0; i < GF_MAX_INDEX; i++) nGF[i - GF_MAX_INDEX] = nGF[i + GF_MAX_INDEX] = nGF[i];

	} else {

		// ��� ��� �� ������ �����, ������������� ����� ����� �� ���������. ���� ����� �� ����� ECC ���� 
		// � ������� ������, �� �� ���������, �����, ���������� ������������ �������� � ����������������� 
		// ������������ ������ ��� ������ ��������. 
		
		if(ECCLen == new_ecclen) return;

		HeapFree(RSHeap, 0, TmpPolyMul);  TmpPolyMul = NULL;
		HeapFree(RSHeap, 0, TmpPoly);	  TmpPoly    = NULL;
		HeapFree(RSHeap, 0, Omega);       Omega      = NULL;
		HeapFree(RSHeap, 0, ErrorLocs);   ErrorLocs  = NULL;
		HeapFree(RSHeap, 0, TmpLambda);   TmpLambda  = NULL;
		HeapFree(RSHeap, 0, Lambda);      Lambda     = NULL;
		HeapFree(RSHeap, 0, Syndrome);    Syndrome   = NULL;
		HeapFree(RSHeap, 0, GenPoly);	  GenPoly    = NULL;
	}
	
	ECCLen = new_ecclen;
	WorkPolyLen = ECCLen/2 + 1;

	// �������� ������ ��� ����������� �������
	GenPoly = (GF_TYPE *)HeapAlloc(RSHeap, 0, SizeInBytes(ECCLen + 1));
	if(GenPoly == NULL) ErrMsgBox("RSLibInit Error", "Memory allocation error for GenPoly!");

	// �������� ������ ��� ������� �������� ������
	Syndrome = (GF_TYPE *)HeapAlloc(RSHeap, 0, SizeInBytes(ECCLen));
	if(Syndrome == NULL) ErrMsgBox("RSLibInit Error", "Memory allocation error for Syndrome!");
	
	// �������� ������ ��� ������� ��������� ������
	Lambda = (GF_TYPE *)HeapAlloc(RSHeap, 0, SizeInBytes(WorkPolyLen));
	if(Lambda == NULL) ErrMsgBox("RSLibInit Error", "Memory allocation error for Lambda!");
	
	// �������� ������ ��� ��������������� ������� ��������� ������
	TmpLambda = (GF_TYPE *)HeapAlloc(RSHeap, 0, SizeInBytes(WorkPolyLen));
	if(TmpLambda == NULL) ErrMsgBox("RSLibInit Error", "Memory allocation error for TmpLambda!");

	// �������� ������ ��� �������� ������
	ErrorLocs = (GF_TYPE *)HeapAlloc(RSHeap, 0, SizeInBytes(WorkPolyLen));
	if(ErrorLocs == NULL) ErrMsgBox("RSLibInit Error", "Memory allocation error for ErrorLocs!");
	
	// �������� ������ ��� ������� ������� ������ 
	Omega = (GF_TYPE *)HeapAlloc(RSHeap, 0, SizeInBytes(WorkPolyLen));
	if(Omega == NULL) ErrMsgBox("RSLibInit Error", "Memory allocation error for Omega!");
	
	// �������� ������ ��� ��������������� ������� ������ ����������
	TmpPoly = (GF_TYPE *)HeapAlloc(RSHeap, 0, SizeInBytes(WorkPolyLen + ECCLen));
	if(TmpPoly == NULL) ErrMsgBox("RSLibInit Error", "Memory allocation error for TmpPoly!");
	
	// �������� ������ ��� ��������������� ������� ��� ��������� polyMul
	TmpPolyMul = (GF_TYPE *)HeapAlloc(RSHeap, 0, SizeInBytes(WorkPolyLen + ECCLen));
	if(TmpPolyMul == NULL) ErrMsgBox("RSLibInit Error", "Memory allocation error for TmpPolyMul!");

	// ������ ������������ �������� ��� �������� ����� ECC ��� ������������� ����� ������������.
	if(genpoly == NULL)	CalcGenPoly(ECCLen); 
		else CopyMemory(GenPoly, genpoly, ecclen + 1);
}

#ifdef FULL 

//////////////////////////////////////////////////////////////////////////
// ������ ���� ��������� ������ ��� �������� ����� ECC.
void RSCalcECC(BYTE *data, BYTE *ecc) {
	polyRest((GF_TYPE *)ecc, (GF_TYPE *)data, DataLen, GenPoly, ECCLen+1);
}

#endif // FULL

//////////////////////////////////////////////////////////////////////////
// ���������� �������, �������������� �������� ����������� ����� ������ (data + ecc). 
// ������ �������� �������� ������ ����������� ����� ����������� � ����������� ������� 
// ����� ������, ������ ������������ ��������. ���� ���� ������ �� ���������, �� ����� 
// ������������ �������� ����� ��� �� � ��� �������, ��� ����������� ������� �� ���������� � ����.
DWORD RSCheckData(BYTE *data, BYTE *ecc) {
	DWORD i, j, sum;

	// ������ �������� �������� ������ ��� ����� ������ (data+ecc)
	for(i = 0; i < ECCLen; i++) {
		sum = 0;
		for(j = 0; j < DataLen; j++) sum = gAdd(((GF_TYPE *)data)[j], gMul(nGF[i+1], sum));
		for(j = 0; j < ECCLen;  j++) sum = gAdd(((GF_TYPE *)ecc)[j],  gMul(nGF[i+1], sum));
		Syndrome[i] = (GF_TYPE)sum;
	}

	// �������� ������������� �������� �������� ������ �� ��������� ����. 
	// ���� ���� �� ���� �� ��� �� ����� ���� - ����������� ����� ��������.
	for(i = 0; i < ECCLen; i++) if(Syndrome[i] != 0) return(1);		// ���� ������.
	return(0);														// ��� ������.
}

//////////////////////////////////////////////////////////////////////////
// �������������� ���������� ��������� ����� ������
DWORD RSRepairData(BYTE *data, BYTE *ecc) { 
	DWORD i, j, k, r, err, num, denom;

	if(!CalcErrors()) return(0);		// �� ������� ��������� ������� ���������, ������� ����� ������
 
	for(r = 0; r < Errors; r++) {
		i = ErrorLocs[r];
		for(k = ECCLen/2, num = j = 0; j < k; j++) 
			num = gAdd(num, gMul(Omega[j], nGF[((GF_MAX_INDEX - i) * j) % GF_MAX_INDEX]));
		for(j = 1, denom = 0; j < WorkPolyLen; j += 2) 
			denom = gAdd(denom, gMul(Lambda[j], nGF[((GF_MAX_INDEX - i) * (j - 1)) % GF_MAX_INDEX]));
		err = gMul(num, nGF[GF_MAX_INDEX - rGF[denom]]);
		k = DataLen + ECCLen - i - 1;
		if(k < DataLen) ((GF_TYPE *)data)[k] ^= err;	// ��������� ������ � ������� ������
			else ((GF_TYPE *)ecc)[k - DataLen] ^= err;	// ��������� ������ � ������� ECC
	}
	return(1);		// ��� ������ ����������
}

//////////////////////////////////////////////////////////////////////////
// ������������ ������������ ������ � ������ ��������
void RSLibClose(void) {
	DataLen = ECCLen = WorkPolyLen = CurGPolyDegree = Errors = 0;
	if(RSHeap != NULL) {
		if(HeapDestroy(RSHeap)) RSHeap = NULL;
			else ErrMsgBox("RSLibClose Error", "Can't destroy RSHeap!");
	}	
}

///////////////////////////////////////////////////////////////////////////////
// ������ ������������ �������� ��� �������� ����� ECC. ������������ �������
// �������� r = ECCLen, ��������������, ����� �������� ����� ECCLen + 1 (� 
// ��������� � �� � ������!!!). ������� �������� �������� �������� ���� �����,
// ��������������� ����������� ���������� ����� 2 � ������� 1, 2, ..., r (�.�. 
// 2^1, 2^2, ..., 2^r). ��� ����������� ���� ������ ������� ���������� � ����.
static void CalcGenPoly(DWORD ecclen) {
	DWORD gpolylen = ecclen + 1, gpolyleninbytes = SizeInBytes(gpolylen);
	GF_TYPE	tmp[2] = { 0, 1 };
	
	ZeroMemory(GenPoly, gpolyleninbytes);
	for(CurGPolyDegree = GenPoly[0] = 1; CurGPolyDegree < gpolylen; CurGPolyDegree++) {
		tmp[0] = nGF[CurGPolyDegree];
		polyMul(TmpPoly, GenPoly, gpolylen, tmp, 2);
		CopyMemory(GenPoly, TmpPoly, gpolyleninbytes);
	}
}

//////////////////////////////////////////////////////////////////////////
// ������ �������� ��������� ������ � ���������� ����� ��������� ������. ��������
// ������������ ��������� ��������� ������. ������ �������� ������� ������.
static DWORD CalcErrors(void) {	
	DWORD i, q, m, L1, L2, dscr, zero; 
	
	// ������ �������� ��������� ������ �� ��������� ����������-����� (Berlekamp-Massey). 
	// ���������� ���������:
	// q    - ����� ���� ���������.
	// m    - ����� ����, �� ������� ������� ��������� ��������� ��� ���������������.
	// Lx   - ���������� ������ � ����� ����� ��������� (���������� - ���������� ����������.
	//        ��������� ����� ������, �������������� �� ����� �������� ���������).
	// dscr - �������� ������� (����� ����� � ������ ����� q-�� ���������, ���� �������
	//        ��������� ������������� ���������).
	// �������� ���������:
	// Lambda    - �������������� ������� ��������� ������.
	// TmpLambda - ��������������� ������� ��������� ������.
	// TmpPoly   - ��������������� �������, ������������ ��� ����������� �������� ���������
	//             ������ ��� "����������" ��� ��� ��������� �������.

	ZeroMemory(Lambda, SizeInBytes(WorkPolyLen)); 			
	Lambda[0] = 1;
	CopyMemory(TmpPoly, Lambda, SizeInBytes(WorkPolyLen));	
	
	for(m = -1, q = L1 = 0; q < ECCLen; q++) {
		polyLShift(TmpPoly, 1, q);
		for(dscr = i = 0; i <= L1; i++) dscr = gAdd(dscr, gMul(Lambda[i], Syndrome[q-i]));
		if(dscr) {
			for(i = 0; i < WorkPolyLen; i++) TmpLambda[i] = gAdd(Lambda[i], gMul(dscr, TmpPoly[i]));
			if(L1 < (q - m)) {
				L2 = q - m;
				m  = q - L1;
				L1 = L2;
				for(i = 0; i < WorkPolyLen - 1; i++) TmpPoly[i] = gMul(Lambda[i], nGF[GF_MAX_INDEX - rGF[dscr]]);
			}	
			CopyMemory(Lambda, TmpLambda, SizeInBytes(WorkPolyLen)); 
		}
	}

	// ��������� ���� (Chien search). ���������� ������ �������� ��������� ������ � ���������� ��������� ������.  
	
	for(q = 1, Errors = 0; q < GF_SIZE; q++) {
		for(zero = i = 0; i < WorkPolyLen; i++) zero = gAdd(zero, gMul(nGF[(i * q) % GF_MAX_INDEX], Lambda[i]));
		if(zero == 0) ErrorLocs[Errors++] = (GF_TYPE)(GF_MAX_INDEX - q); 
	}
	
	// �������� ������������ �������� ��������� ������. ���� ������� ��������� ��� ��������� 
	// �����, �� ���������� ��������� ������ (Errors) ������ ���� ����� ������� �������� 
	// ��������� ������ (L1), � ���� �������� �� ������ �������� �� ������� ����� ������.
	
	if(L1 != Errors) return(0); 
	m = DataLen + ECCLen;
	for(i = 0; i < Errors; i++) if(ErrorLocs[i] >= m) return(0); 
		
	// ������ �������� ������� ������

	polyMul(TmpPoly, Lambda, WorkPolyLen - 1, Syndrome, ECCLen);
	ZeroMemory(Omega, SizeInBytes(WorkPolyLen));
	CopyMemory(Omega, TmpPoly, SizeInBytes(WorkPolyLen));

	return(1);
}

//////////////////////////////////////////////////////////////////////////
// �������� ��������� poly1 � poly2 � ���� �����, ��������� ���������� � ������ res. ���� �������� ������ 
// �����, �� � ��������� len ����������� ������ ������ �������� �� ��� (� ���������, � �� � ������!!!).
static void polyAdd(GF_TYPE *res, GF_TYPE *poly1, GF_TYPE *poly2, DWORD len) { 
	for(DWORD i = 0; i < len; i++) res[i] = gAdd(poly1[i], poly2[i]); 
}

//////////////////////////////////////////////////////////////////////////
// ��������� ��������� poly1 � poly2 � ���� �����, ��������� ���������� � ������ res. ���� �������� ������ 
// �����, �� � ��������� len ����������� ������ ������ �������� �� ��� (� ���������, � �� � ������!!!).
static void polySub(GF_TYPE *res, GF_TYPE *poly1, GF_TYPE *poly2, DWORD len) { 
	for(DWORD i = 0; i < len; i++) res[i] = gSub(poly1[i], poly2[i]); 
}

//////////////////////////////////////////////////////////////////////////
// ��������������� �������� � ���� ����� �� factor, ����� ��������� �������� - len ��������� 
static void polyScaling(GF_TYPE *poly, GF_TYPE factor, DWORD len) { 
	for(DWORD i = 0; i < len; i++) poly[i] = gMul(poly[i], factor); 
}

//////////////////////////////////////////////////////////////////////////
// ����� �������� �� shift ������� "�����", ����� ��������� �������� - len, ���������� - (len + shift) ���������
// ������ ������ �� shift = 2 �������: 3x^2+2x^1+1x^0 -> 3x^4+2x^3+1x^2+0x^1+0x^0 -> 3x^4+2x^3+1x^2
static void polyLShift(GF_TYPE *poly, GF_TYPE shift, DWORD len) { 
	for(DWORD i = len - 1; i < len; i--) poly[i + shift] = poly[i]; 
	ZeroMemory(poly, SizeInBytes(shift));
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� poly1 � poly2 � ���� �����, ����� ���������� ����� ����� ���� ���������-���������� 
// ����� ��������� �������� � ���������� ��������� �������, � �� � ������!!!
static void polyMul(GF_TYPE *res, GF_TYPE *poly1, DWORD p1len, GF_TYPE *poly2, DWORD p2len) {
	ZeroMemory(res, SizeInBytes(p1len + p2len));
	for(DWORD i = 0; i < p1len; i++) {
		CopyMemory(TmpPolyMul, poly2, SizeInBytes(p2len));
		polyScaling(TmpPolyMul, poly1[i], p2len);
		polyLShift(TmpPolyMul, (GF_TYPE)i, p2len);
		polyAdd(res, res, TmpPolyMul, p2len + i);
	}
}

#ifdef FULL 

//////////////////////////////////////////////////////////////////////////
// ���������� ������� �� ������� poly1 �� poly2, ����� ���������� ����� p2len-1.
// ����� ��������� �������� � ���������� ��������� �������, � �� � ������!!!
// ����� poly2 �� ������ ���� ����� 2-� ��������� (�.�. ECCLen >= 2). 
static void polyRest(GF_TYPE *rest, GF_TYPE *poly1, DWORD p1len, GF_TYPE *poly2, DWORD p2len) {
	DWORD i, j, tmp;

	ZeroMemory(TmpPoly, SizeInBytes(p2len));
	p2len -= 2;
	for(i = 0; i < p1len; i++) {
		tmp = gSub(poly1[i], TmpPoly[p2len]);
		for(j = p2len; j > 0; j--) TmpPoly[j] = gSub(TmpPoly[j - 1], gMul(poly2[j], tmp));
		TmpPoly[0] = gMul(poly2[0], tmp);
	}
	for(tmp = p2len + 1, i = 0; i < tmp; i++) rest[i] = TmpPoly[p2len - i];
}

#endif // FULL

//////////////////////////////////////////////////////////////////////////
// ��������� ���������� � ���������� ������������ ������. ���� ���������, ��
// �������� ����� ����� ������� RSRepairData() 
DWORD RSGetErrors() {
	return(Errors);
}

//////////////////////////////////////////////////////////////////////////
// ������� ���������� ������� ���������� ������� ������������ ��������. ��������� � 
// ������ RS16 ��� ����� ��� ����� 3-4 ����� ��� �������� ��������� ��������, �.�. ������
// � ���� ������ ����� ������ ������������ �����. �������� � ������� �� ������� ������, 
// � ������� �������� ���������� � ������� RSLibInit() � �� ������� �������� ����������
// �� ��. � ����� ������ ����� ������������� RSGenPolyPercentReady() ������ ������. 
DWORD RSGenPolyPercentReady(void) {
	DWORD res;
	
	if(ECCLen == 0) return(0);
	res = SizeInBytes(CurGPolyDegree) / (SizeInBytes(ECCLen + 1) / 100); 
	return( (res > 100) ? 100 : res );
}

//////////////////////////////////////////////////////////////////////////
// ������� ��������� ����������� ����������� ������� � ��������� ������, ����� � ������ �����
// SizeInBytes(ECCLen + 1). ����������� ������� � ���������� ����� �������������� �����, � �� 
// �������������� ��� ������������� ����������. �������� � ������� ����� ������� RSLibInit(),
// �� �� ������ ������� RSLibClose().
void RSGetGenPoly(BYTE *genpoly) {
	if(genpoly != NULL)	CopyMemory(genpoly, GenPoly, SizeInBytes(ECCLen + 1));
}

///////////////////////////////////////////////////////////////////////////
// ����� ��������� �� ������ �� ���� MessageBox � ���������� �������������� ������� � ���������� ������ ����������.
static void ErrMsgBox(char *title, char *format, ...) {
	char buffer[1024];
	va_list arg_ptr;
    
	va_start(arg_ptr, format);
	vsprintf_s(buffer, sizeof(buffer), format, arg_ptr);
    va_end(arg_ptr);
	MessageBox(NULL, buffer, title, MB_SYSTEMMODAL | MB_ICONERROR);
	exit(1);
}
