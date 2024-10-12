//*****************************************************************************
// ���������� ����������, ������������ ��������� ����������� ����, ����� 
// ����-�������� � ������������ ���������� ������������ ����, ���������������
// ��� ������������� � ����������� � �����������, ���������� ������������ ��������.
// 
// ������������ ������� � ������ ��������� ������ �������� ����� ����� LDK API,
// ������������� ������ � �������������� ��� ������� Function1 � ��� Function1.
// ��� ������� Function2 ����������.
//
// ����� - ������ ����� (Sergey.Uskov@safenet-inc.com, uskov@smtp.ru)
//*****************************************************************************

#include <windows.h>
#include <stdio.h>

#include "resource.h"
#include "hasp_api.h"
#include "RSLib.h"		// ����� ����-��������.
#include "macros.h"		// ��������� � ��������� ������, ������������ ��� �������� ���������� �� ������� �������.
#include "enc_str.h"	// ������, ���������� ������������ ��� ������ ������� �������.

#define MAX_LOADSTRING 100

#define xGap 50				// ���������� ����� ��������� ��������� ��� ������ ������.
#define yGap 20				// ���������� ����� ��������� �������� ��� ������ ������.

#define CheckKeyTimeout		500						// �������� �������� ������ ����� (� �������������).
#define CheckThreadTimeout	CheckKeyTimeout*2		// �������� �������� ��������� ������ �������� ������ �����
#define MinReactionTimeout	10						// ����������� �������� (� ���.) �� ������� �� ���������� ������.
#define MaxReactionTimeout	20						// ������������ �������� (� ���.) �� ������� �� ���������� ������.

#define F1Trigger			1						// ��������� �������� ��� Function1, ���������� ������ ������ ������.

//////////////////////////////////////////////////////////////////////////////////////////////
// ��������� �������� ������������, ����������� ��� ������ ������� F1 � F2 
//
struct Factors {		
	DWORD   Min;			// ����������� ��������
	DWORD   Max;			// ������������ ��������
	DWORD   Xor;			// ��������������� �����������
	DWORD   And;			// ��������������� �����������
};

//////////////////////////////////////////////////////////////////////////////////////////////
// ���������� �������������� ��������.

LONG WINAPI VEH_Handler(PEXCEPTION_POINTERS ExceptionInfo);

// ��������������� ������� � �������������� ���������� ����� �������� (HW BreakPoint)
DWORD HardwareBPFlag(struct _CONTEXT *ContextRecord);

//////////////////////////////////////////////////////////////////////////////////////////////
// ���������� ����������.
HINSTANCE hInst;							
HMENU hMainMenu;
TCHAR szTitle[MAX_LOADSTRING]; 
TCHAR szWindowClass[MAX_LOADSTRING];
TCHAR szText;

HANDLE hF1Thread, hF2Thread, hKeyBackgroundChk;		// �������������� ���������� �������
BOOL f1Terminate = TRUE, f2Terminate = TRUE;		// �������� ���������� �������
BOOL HaspKeyPresent = FALSE;						// ���� ��������������� �������, ����������� ������� ����� �����

DWORD	CurrentImageBase;
PIMAGE_NT_HEADERS32 PEHeader;

int	TimerID, ProtectTimeout = MaxReactionTimeout;

DWORD F1ErrCount = 0;

// ����� ������� ���������� ���� ������� "�������" ������������� ��������� ���������� �������������� ��������.
// ��� ����� ��������� ��� ������������� ���������� hVEH_Handler, �� ����� ���������� startup-���� �������.

PVOID  hVEH_Handler = AddVectoredExceptionHandler(0, VEH_Handler);	// ������������� VEH-�����������

// �������� ���� ������������ �������������� �� ������ �����-���� ������, � �������� �������, �����
// ����������� ����� ��� ���� � ������ ������������ ���������.
CrcDscList CrcListEntry = {CrcDscListSig, (PCrcDsc)&AddrStub};		// ����� ����� � ������ CRC-������������
EccDscList EccListEntry = {EccDscListSig, (PEccDsc)&AddrStub};		// ����� ����� � ������ ECC-������������

OrgPE OrgPEValue = {OrgPESig};						// ��������� ��� �������� ��������� �������� ImageBase

//////////////////////////////////////////////////////////////////////////////////////////////

ATOM				RegisterWindowClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	About(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
void				Function1(PVOID hwnd);
void				Function2(PVOID hwnd);
void				KeyBackgroundChk(PVOID hwnd);
void				KeyBackgroundChkMsg(PVOID err);
void	CALLBACK	KBChkProtect(HWND, UINT, UINT, DWORD);
PBYTE 				Enc(PBYTE buffer, DWORD length);
PBYTE				Dec(PBYTE buffer, DWORD length);

void __stdcall		KeyEncWithFixUp(PKeyEncCodeDsc data);						// Fixup-������� ��� KeyEnc 
void				KeyEnc(PKeyEncCodeDsc data);
void __stdcall		KeyDecWithFixUp(PKeyEncCodeDsc data);						// Fixup-������� ��� KeyDec
void				KeyDec(PKeyEncCodeDsc data);
void				HaspReLogin(PHaspSession session);

BOOL				CRCDataScan(PCrcDsc	EntryPoint);							// �������� ���� ������� CRC-������������
BOOL				CheckCRC32WithFixUp(PCrcDsc descriptor);					// Fixup-������� ��� CheckCRC32
BOOL				CheckCRC32(PCrcDsc descriptor);

void				RSCDataScan(PVOID EntryPoint);								// �������� ���� ������� ECC-������������
DWORD				RSCDataFixingWithFixUp(PEccDsc descriptor);					// Fixup-������� ��� RSCDataFixing
DWORD				RSCDataFixing(PEccDsc descriptor);

DWORD				SearchingRelocs(PDWORD Reloc, PBYTE Addr, DWORD Length);	// ����� ������������ ��������� � �������

DWORD				MsgBox(PCHAR title, UINT style, PCHAR format, ...);


//////////////////////////////////////////////////////////////////////////////////////////////

HaspSession Main = {HASP_INVALID_HANDLE_VALUE, HASP_HASP_NOT_FOUND, HASP_DEFAULT_FID};

#define API_DEPTH		128		// �� ����� ������� ����������� ��� HASP API �� ����� �����
#define API_ECC_LEN		256		// ����� ECC ��� �������������� ������������ ����

// ����������� ���������� �������� ����� ����� � LDK API. �������� ���� ������������ �������������� �� ������
// �����-���� ������, � �������� �������, ����� ����������� ����� ��� ���� � ������ ������������ ���������.
CrcDsc	login_CRC   = {&AddrStub, &AddrStub};		// CRC-���������� ������� hasp_login
EccDsc	login_ECC   = {&AddrStub, &AddrStub};		// ECC-���������� ������� hasp_login
CrcDsc	getinfo_CRC = {&AddrStub, &AddrStub};		// CRC-���������� ������� hasp_getinfo
EccDsc	getinfo_ECC = {&AddrStub, &AddrStub};		// ECC-���������� ������� hasp_getinfo

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	MSG msg;
	HWND hWnd;
	HACCEL hAccelTable;
	UCHAR vc[sizeof(vendor_code)];

	// ��������� ������������� ����������, ������� �������� ImageBase � ����� ��������� PE-�����.
	hInst = hInstance;
	CurrentImageBase = (DWORD)hInstance;
	PEHeader = (PIMAGE_NT_HEADERS32)(CurrentImageBase + ((PIMAGE_DOS_HEADER)CurrentImageBase)->e_lfanew);


	// �������� ������������� ������-��� ������ � ��������� ����������.
	CopyMemory(vc, vendor_code, sizeof(vc));

	// ��������� Login �� Feature ID 0, �������� ���������� ����� ��������� � InitInstance(). ����� ������� Login
	// ������������ ������������� Vendor-����, ����� ����� ������ - �������� ������������.
	Main.status = hasp_login(Main.feature, Dec(vc, sizeof(vc)), &Main.handle);
	Enc(vc, sizeof(vc));

	// �������� ����� � ������������� �� ��������
	LoadString(hInst, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
	LoadString(hInst, IDC_CppSample, szWindowClass, MAX_LOADSTRING);
	hAccelTable = LoadAccelerators(hInst, (LPCTSTR)IDC_CppSample);

	// ���������, �� ���� �� ��� ���������� �������� �����. 
	// ���� ����, ��������� ���� ���������� �� �������� ����.
	hWnd = FindWindow(szWindowClass, NULL);
	if(hWnd) {
		if(IsIconic(hWnd)) ShowWindow(hWnd, SW_RESTORE);
		SetForegroundWindow(hWnd);
		return -1;
	}
	
	// ������������ ����� ����, ������� ������� ���� ���������� � ���������� ���.
	RegisterWindowClass(hInst);
	if (!InitInstance (hInst, nCmdShow)) return -2;

	// ��������� �����, ����������� ������� ����� ����� � �������� ��� ���������.
	hKeyBackgroundChk = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)KeyBackgroundChk, 0, 0, NULL);
	SetThreadPriority(hKeyBackgroundChk, THREAD_PRIORITY_LOWEST);

	// ��������� ���� ��������� ���������.
	while (GetMessage(&msg, NULL, 0, 0)) {
		if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}
	Main.status = hasp_logout(Main.handle);
	return 0;

	// CRC/ECC-������� ��� ������� hasp_login � hasp_get_info
	AsmCrcLibsMrk(login_CRC, hasp_login, API_DEPTH, 0);
	AsmEccLibsMrk(login_ECC, hasp_login, API_DEPTH, API_ECC_LEN, 0);
	AsmCrcLibsMrk(getinfo_CRC, hasp_get_info, API_DEPTH, 1);
	AsmEccLibsMrk(getinfo_ECC, hasp_get_info, API_DEPTH, API_ECC_LEN, 1);
}


//////////////////////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ����������� ������ ����.
ATOM RegisterWindowClass(HINSTANCE hInstance) {
	WNDCLASSEX wcex;

	wcex.cbSize			= sizeof(WNDCLASSEX); 
	wcex.style			= CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc	= (WNDPROC)WndProc;
	wcex.cbClsExtra		= 0;
	wcex.cbWndExtra		= 0;
	wcex.hInstance		= hInstance;
	wcex.hIcon			= LoadIcon(hInstance, (LPCTSTR)IDI_CppSample);
	wcex.hCursor		= LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground	= (HBRUSH)(COLOR_WINDOW + 1);
	wcex.lpszMenuName	= (LPCSTR)IDC_CppSample;
	wcex.lpszClassName	= szWindowClass;
	wcex.hIconSm		= LoadIcon(wcex.hInstance, (LPCTSTR)IDI_CppSample);
	
	// ������ ��������� �� ���������� �����.
	if(Main.status != HASP_STATUS_OK) MsgBox("Feature ID = 0", MB_SYSTEMMODAL | MB_ICONERROR, "Login error #%d", Main.status);
	
	return RegisterClassEx(&wcex);
}

//////////////////////////////////////////////////////////////////////////////////////////////
// ��������� ��������� �������� � ����������� �������� ���� ����������.
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow) {
	HWND hWnd;
	CHAR new_header[356], header[256];
	
	hWnd = CreateWindow(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, 0, 930, 606, NULL, NULL, hInstance, NULL);

	// ���������� ����������, ���� ��� �����. ��, ���, ���� �����-���� �������� ��� ������ CreateWindow(...)
   if(!hWnd || Main.status) return FALSE;
	ShowWindow(hWnd, nCmdShow);

	// ����� � ��������� ���� �������� �������� ImageBase
	GetWindowText(hWnd, header, sizeof(header));
	sprintf_s(new_header, sizeof(new_header), "%s [ current ImageBase = %08Xh ]", header, CurrentImageBase);
	SetWindowText(hWnd, new_header);

	UpdateWindow(hWnd);
	return TRUE;
}

//////////////////////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ��������� ��������� ������� About
LRESULT CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
	UINT major_ver, minor_ver, build_srv, build_num;
	TCHAR api_ver[64];

	switch (message) {
	case WM_INITDIALOG:
		hasp_get_version(&major_ver, &minor_ver, &build_srv, &build_num, NULL);
		sprintf_s(api_ver, sizeof(api_ver), "LDK API v%u.%u.%u.%u", major_ver, minor_ver, build_srv, build_num);
		SetWindowText(GetDlgItem(hDlg, IDC_STATIC_API), api_ver);
		return TRUE;
		
	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) {
			EndDialog(hDlg, LOWORD(wParam));
			return TRUE;
		}
		break;
	}
    return FALSE;
}

//////////////////////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ��������� ��������� �������� ���� ����������
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
	int wmId, wmEvent;

	hMainMenu = GetMenu(hWnd);
	switch (message) {
		case WM_COMMAND:
			wmId    = LOWORD(wParam); 
			wmEvent = HIWORD(wParam); 
			
			// ������� �� ����� ������� ����. 
			switch (wmId) {
					
				case IDM_F1Start:
					// ��������� �����. ���� ��� ������, ������������ ����� ���� "Stop" � ����������� "Start".
					hF1Thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Function1, (LPVOID)hWnd, 0, NULL);
					if(hF1Thread != NULL) {
						f1Terminate = FALSE;
						EnableMenuItem(hMainMenu, IDM_F1Start, MF_GRAYED);
						EnableMenuItem(hMainMenu, IDM_F1Stop, MF_ENABLED);
					}
					break;
					
				case IDM_F1Stop:
					// ��������� �����. 
					f1Terminate = TRUE;
					break;
					
				case IDM_F2Start:
					// ��������� �����. ���� ��� ������, ������������ ����� ���� "Stop" � ����������� "Start".
					hF2Thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Function2, (LPVOID)hWnd, 0, NULL);
					if(hF2Thread != NULL) {
						f2Terminate = FALSE;
						EnableMenuItem(hMainMenu, IDM_F2Start, MF_GRAYED);
						EnableMenuItem(hMainMenu, IDM_F2Stop, MF_ENABLED);
					}
					break;
					
				case IDM_F2Stop:
					// ��������� �����.
					f2Terminate = TRUE;
					break;
				
				case IDM_ABOUT:
					DialogBox(hInst, (LPCTSTR)IDD_ABOUTBOX, hWnd, (DLGPROC)About);
					break;

				case IDM_EXIT:
					DestroyWindow(hWnd);
					break;

				default:
					return DefWindowProc(hWnd, message, wParam, lParam);
			}
			break;
			
		case WM_CREATE:
			srand(GetTickCount());
			// ������� ����������� ������, ������������ ���������� ���������� � ������� KBChkProtect
			TimerID = SetTimer(hWnd, 0,  CheckThreadTimeout, (TIMERPROC)KBChkProtect);
			break;

		case WM_DESTROY:
			KillTimer(hWnd, TimerID);
			PostQuitMessage(0);
			break;

		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  ��������� ���������� ������-��������� ����� � ��������� [0;128] � ��������� ������.
//  ��� �������� � �������� �������� ��������� ������� ������, ��� ������ - �������.
//  ��� ��, � ��������� ����������� ������� �� "������ �������" - ��� ���������� 
//  ����� ������, ��������� �� ��� ��������� ����� ������.

Factors F1 = {0x0000, 0x0080, 0xFF00, 0x00FF};	// ������ � ��������������, ������������ ��� ������ �������.

#define F1_Feature		1						// ����� ���� �����, ������� ����� ������������ �������.
#define F1_Ecc_Length	(sizeof(F1) * 2)		// ������ ECC ��� �������������� ������� � ��������������.
#define Fn1_Ecc_Length	256						// ������ ECC ��� ����������� ������� ����.

HaspSession Fn1  = {HASP_INVALID_HANDLE_VALUE, HASP_HASP_NOT_FOUND, F1_Feature};

// �������� ���� ������������ �������������� �� ������ �����-���� ������, � �������� �������, �����
// ����������� ����� ��� ���� � ������ ������������ ���������.
CrcDsc F1_Crc  = {&AddrStub, &AddrStub};		// CRC-���������� ������� F1.
CrcDsc Fn1_Crc = {&AddrStub, &AddrStub};		// CRC-���������� ������� ���� ����� ������� l1 � l2.
EccDsc F1_Ecc  = {&AddrStub, &AddrStub};		// ECC-���������� ������� F1.
EccDsc Fn1_Ecc = {&AddrStub, &AddrStub};		// ECC-���������� ������� ���� ����� ������� l1 � l2.

KeyEncDataMrk F1_Mrk1 = {KeyEncDataSig, &F1, sizeof(F1), F1_Feature};				// Encrypt-������ ������� F1
CrcDataMrk	  F1_Mrk2 = {CrcDataSig, &F1_Crc, &F1, sizeof(F1), 2};					// CRC-������ ������� F1
EccDataMrk    F1_Mrk3 = {EccDataSig, &F1_Ecc, &F1, sizeof(F1), F1_Ecc_Length, 2};	// ECC-������ ������� F1

void Function1(PVOID hwnd) {
	HDC		hDC;
	RECT	rect;
	INT		delay, x, y;
	UINT	z0 = 0, z1 = 0, z2 = 0;
	TCHAR	szTxt[8];
	Factors F;
	UCHAR vc[sizeof(vendor_code)];

	l1:	// ������ ����������� ������� ����.

	// �������� ������������� ������-��� � ����� � �������������� � ��������� ����������.
	CopyMemory(vc, vendor_code, sizeof(vc));
	CopyMemory(&F, &F1, sizeof(F));

	// ��������� Login �� Feature 1, ���� ������ - ������� ��������� � ��������� ������ �������. ����� 
	// ������� Login ������������ ������������� Vendor-����, ����� ����� ������ - �������� ������������.
	Fn1.status = hasp_login(Fn1.feature, Dec(vc, sizeof(vc)), &Fn1.handle);
	Enc(vc, sizeof(vc));
	if(Fn1.status != HASP_STATUS_OK) {
		MsgBox("Feature ID = 1", MB_SYSTEMMODAL | MB_ICONERROR, "Login error #%d", Fn1.status);
		EnableMenuItem(hMainMenu, IDM_F1Start, MF_ENABLED);
		EnableMenuItem(hMainMenu, IDM_F1Stop, MF_GRAYED);
		ExitThread(1);
	}

	// �������������� ��������� ����� ������ � ��������������
	hasp_decrypt(Fn1.handle, &F, sizeof(F));

	while(!f1Terminate) {
		hDC = GetDC((HWND)hwnd);
		GetWindowRect((HWND)hwnd, &rect);
		delay = 50;

		// ���� ��� ����� - ������� �������� ������ �� ������. HaspKeyPresent ���������������, �����
		// �� ��������� "���", �������� � ���������� ��� ������ ������ ������ ������� �������� �����.
		if(!(BYTE)HaspKeyPresent) { 
			Sleep(delay); 
			continue;
		}

		for (y = 5; y < (rect.bottom - rect.top - 4*yGap); y += yGap) {
			for (x = 5; x < ((rect.right - rect.left)/2 - xGap); x += xGap) {
				z0 = ((rand() % (F.Max - F.Min) + F.Min) ^ (F.Xor & F.And)) & 0x0000FFFF;

				// "������ �������".

				if(z1 == z0 && z2 == z0) {
					// �������� ����������� �������� �� ���� ������� ������������.
					if(!CRCDataScan(CrcListEntry.EntryPoint)) {
						if(F1ErrCount < F1Trigger) SetTextColor(hDC, RGB(192, 0, 192));
							else SetTextColor(hDC, RGB(192, 0, 0));
						F1ErrCount++;
					} else SetTextColor(hDC, RGB(0, 0, 192));
					delay = 1500;
				} else z0 < 128 ? SetTextColor(hDC, RGB(0, 192, 0)) : SetTextColor(hDC, RGB(192, 0, 0));
				sprintf_s(szTxt, sizeof(szTxt), "%.4Xh ", z0);
				TextOut(hDC, x, y, szTxt, strlen(szTxt));
				z2 = z1;
				z1 = z0;
			}
		}
		ReleaseDC((HWND)hwnd, hDC);
		Sleep(delay);
	}
	EnableMenuItem(hMainMenu, IDM_F1Start, MF_ENABLED);
	EnableMenuItem(hMainMenu, IDM_F1Stop, MF_GRAYED);
	Fn1.status = hasp_logout(Fn1.handle);
	ExitThread(0);

	l2:	// ����� ����������� ������� ����.

	AsmCrcCodeMrk(Fn1_Crc, l1, l2, 3);							// CRC-������ ������� ���� ����� ������� l1 � l2.
	AsmEccCodeMrk(Fn1_Ecc, l1, l2, Fn1_Ecc_Length, 3);			// ECC-������ ������� ���� ����� ������� l1 � l2.
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  ��������� ���������� ������-��������� ����� � ��������� [128; 255] � ��������� ������.
//  ��� �������� � �������� �������� ��������� ������� ������, ��� ������ - �������. ��� ��, 
//  � ��������� ����������� ������� �� "������ �������" - ��������� ������������ ������������������
//  �� ��� ����� ������, ������������ ���� �� ����� �� �������, ��������� �� ��� ��������� ����� ������.

#define F2_Feature 2									// ����� ���� �����, ������� ����� ������������ �������.

HaspSession Fn2 = {HASP_INVALID_HANDLE_VALUE, HASP_HASP_NOT_FOUND, F2_Feature};

// �������� ���� ������������ �������������� �� ������ �����-���� ������, � �������� �������, �����
// ����������� ����� ��� ���� � ������ ������������ ���������.
KeyEncCodeDsc  Fn2_KeyEnc1 = {(PHaspSession)&AddrStub, &AddrStub};		// Encrypt-���������� ������� ���� ����� ������� l1 � l2.
KeyEncCodeDsc  Fn2_KeyEnc2 = {(PHaspSession)&AddrStub, &AddrStub};		// Encrypt-���������� ������� ���� ����� ������� l2 � l3.

void Function2(PVOID hwnd) {
	HDC		hDC;
	RECT	rect;
	INT		delay, x, y;
	UINT	z_min = 0x0080, z_max = 0x00FF, z_xor = 0xFF00, z_and = 0x00FF;
	UINT	z0 = 0, z1 = 0, z2 = 0;
	TCHAR	szTxt[8];
	UCHAR vc[sizeof(vendor_code)];
	
	RaiseExceptionForKeyDecrypt(Fn2_KeyEnc1, NULL);	
	l1:		// ������ 1-�� �������.

	// �������� ������������� ������-��� � ��������� ����������.
	CopyMemory(vc, vendor_code, sizeof(vc));
	
	// ��������� Login �� Feature 2, ���� ������ - ������� ��������� � ��������� ������ �������. ����� 
	// ������� Login ������������ ������������� Vendor-����, ����� ����� ������ - �������� ������������.
	Fn2.status = hasp_login(Fn2.feature, Dec(vc, sizeof(vc)), &Fn2.handle);
	Enc(vc, sizeof(vc));
	if(Fn2.status != HASP_STATUS_OK) {
		MsgBox("Feature ID = 2", MB_SYSTEMMODAL | MB_ICONERROR, "Login error #%d", Fn2.status);
		EnableMenuItem(hMainMenu, IDM_F2Start, MF_ENABLED);
		EnableMenuItem(hMainMenu, IDM_F2Stop, MF_GRAYED);
		RaiseExceptionForKeyEncrypt(Fn2_KeyEnc1, offset l4);	// ����� ��������� ���������� �������� ���������� �� l4. 
	}
	
	RaiseExceptionForKeyDecrypt(Fn2_KeyEnc2, NULL);	
	l2:	// ����� 1-�� � ������ 2-�� ��������.
	RaiseExceptionForKeyEncrypt(Fn2_KeyEnc1, NULL);

	while(!f2Terminate) {
		hDC = GetDC((HWND)hwnd);
		GetWindowRect((HWND)hwnd, &rect);
		delay = 50;

		// ���� ��� ����� - ������� �������� ������ �� ������. HaspKeyPresent ���������������, �����
		// �� ��������� "���", �������� � ���������� ��� ������ ������ ������ ������� �������� �����.
		if(!(BYTE)HaspKeyPresent) { 
			Sleep(delay); 
			continue;
		}
		
		for (y = 5; y < (rect.bottom - rect.top - 4*yGap); y += yGap) {
			for (x = (rect.right - rect.left)/2; x < rect.right - rect.left - xGap; x += xGap) {
				z0 = ((rand() % (z_max - z_min) + z_min) ^ (z_xor & z_and)) & 0x0000FFFF;

				// ���� ��������� "������ �������" - ��������� ������������ ������������������ �� ��� ����� 
				// ������, ������������ ���� �� ����� �� ������� - ������� ��������� �� ��� ����� ������ � 
				// ������ ������� ��������. �������� �� ��������� [128; 255] ������� ������� ������, ��� 
				// ������ ����� ��������� ������� � ���������� ������� ������.
				
				if(z1 == z0-1 && z2 == z1-1) {
					SetTextColor(hDC, RGB(0, 0, 192));
					delay = 1500;
				} else (z0 > 127 && z0 < 256) ? SetTextColor(hDC, RGB(0, 192, 0)) : SetTextColor(hDC, RGB(192, 0, 0));
				sprintf_s(szTxt, sizeof(szTxt), "%.4Xh ", z0);
				TextOut(hDC, x, y, szTxt, strlen(szTxt));
				z2 = z1;
				z1 = z0;
			}
		}
		ReleaseDC((HWND)hwnd, hDC);
		Sleep(delay);
	}
	// ������������ ����� ���� "Start" � ����������� "Stop".
	EnableMenuItem(hMainMenu, IDM_F2Start, MF_ENABLED);
	EnableMenuItem(hMainMenu, IDM_F2Stop, MF_GRAYED);

	RaiseExceptionForKeyEncrypt(Fn2_KeyEnc2, NULL);
	l3:		// ����� 2-�� �������.

	Fn2.status = hasp_logout(Fn2.handle);
	ExitThread(0);

	l4:		// ����� ��� ���������� �������� �� ������ �������.
	ExitThread(1);

	AsmKeyEncCodeMrk(Fn2_KeyEnc1, l1, l2, Main);	// Encrypt-������ ������� ���� ����� ������� l1 � l2.
	AsmKeyEncCodeMrk(Fn2_KeyEnc2, l2, l3, Fn2);		// Encrypt-������ ������� ���� ����� ������� l2 � l3.
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  ��������� ��������� ������� ����� ����� � ��������� ����������. ��������� ���������,
//	����������� ���������� ��������� ����� ������������ ������ (scope, format � vendorcode),
//  ����������� � ���������������� ��������������� ����� ������� hasp_get_info(), ����� ����
//  ����� ���������������.

void KeyBackgroundChk(PVOID hwnd) {
	HANDLE hMsg = INVALID_HANDLE_VALUE;
	DWORD hMsgState = NULL;
	PCHAR info = 0;
	hasp_status_t status;
	UCHAR vc[sizeof(vendor_code)];
	
	// �������� ������������� ������-��� � ��������� ����������.
	CopyMemory(vc, vendor_code, sizeof(vc));

	while(TRUE) {

		GetExitCodeThread(hMsg, &hMsgState);

		// ��������� ������� �����. ����� ������� hasp_get_info ������������ ������������� ���������� 
		// scope, format � Vendor-���. ����� ����� ������ ����������� �� �������� ������������.
		status = hasp_get_info((CCHAR *)Dec(scope, sizeof(scope)), (CCHAR *)Dec(format, sizeof(format)), Dec(vc, sizeof(vc)), &info);
		Enc(scope, sizeof(scope)); Enc(format, sizeof(format)); Enc(vc, sizeof(vc));
		
		if(status != HASP_STATUS_OK) {		
			// ���� �� ���������.
			HaspKeyPresent = FALSE;
			if(hMsgState == 0) hMsg = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)KeyBackgroundChkMsg, (LPVOID)status, 0, NULL);
		} else {							
			// ���� ���������.
			HaspKeyPresent = TRUE;
			if(hMsgState == STILL_ACTIVE) TerminateThread(hMsg, 0);
			hasp_free(info);
		}

		Sleep(CheckKeyTimeout);
	}
	ExitThread(0);
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  ��������� ������� ���������, ����������� ������������ ������ ������� �������� �����.
void KeyBackgroundChkMsg(PVOID err) {
	MsgBox("Background Check", MB_SYSTEMMODAL | MB_ICONERROR, "Background check error #%d", err);
	ExitThread(0);
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  ��������� �������� ����� ������� �������� �����.

BOOL Noise = FALSE;

void CALLBACK KBChkProtect(HWND hwnd, UINT msg, UINT idTimer, DWORD dwTime) {
	DWORD hRSCState = 0;
	HANDLE hRSC = NULL;

	GetExitCodeThread(hRSC,&hRSCState);
	if(Noise != HaspKeyPresent) {		// ����� KeyBacgroundChk �������� ������. ������������� ������� �������.
		ProtectTimeout = rand() % (MaxReactionTimeout - MinReactionTimeout) + MinReactionTimeout;
	} else {							// ����� KeyBacgroundChk �� ��������.
		if(ProtectTimeout) {			// ���� ������� �� ����� - ��������� ��� �� �������.
			ProtectTimeout -= 1;	
		} else {						// ������� ����� - ��������� �������.
			// ������� �1. ��������� ���������� ���������� � ����������� �����.
			__asm ret 0x7FFF;
			// ������� �2. ���������� ������ KeyBacgroundChk.
//			hKeyBackgroundChk = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)KeyBackgroundChk, 0, 0, NULL);
//			SetThreadPriority(hKeyBackgroundChk, THREAD_PRIORITY_LOWEST);
		}  
	}

	// ���� ������� ������ ����������� ��������, ��������� �����, �����������, ��� �������������,
	// ��������� ����/������ ��� ������ �������� ����-��������.
	if(hRSCState == 0 && F1ErrCount > F1Trigger)
		hRSC = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)RSCDataScan, (LPVOID)EccListEntry.EntryPoint, 0, NULL);

	// ������ "���" � HaspKeyPresent � ��������� �� ����� �������� � Noise ��� ��������� �� ��������� ����� 
	// � ���������. ���� ����� KeyBacgroundChk "���", �� ����������� HaspKeyPresent "����������" ���������.
	Noise = HaspKeyPresent |= 0x00010000;
	return;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  ���������, ����������� ������������ �������������/������������ ������.

#define XOR 0x53

PBYTE Enc(PBYTE buffer, DWORD length) {

	buffer[0] ^= XOR;
	for(DWORD i = 1; i < length; i++) buffer[i] ^= buffer[i-1];
	return buffer;
}

PBYTE Dec(PBYTE buffer, DWORD length) {

	for(DWORD i = length-1; i > 0 ; i--) buffer[i] ^= buffer[i-1];
	buffer[0] ^= XOR;
	return buffer;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  VEH-���������� �������������� ��������.
LONG WINAPI VEH_Handler(PEXCEPTION_POINTERS ExceptionInfo) {

	// ���������� ������.
/*	MsgBox("VEH (all exceptions)", MB_OK, "Exception Code\t %.8X\nException Address\t %.8X\nInvalid Instruction\t %X", 
		    ExceptionInfo->ExceptionRecord->ExceptionCode, ExceptionInfo->ExceptionRecord->ExceptionAddress, 
			*(USHORT *)ExceptionInfo->ExceptionRecord->ExceptionAddress);
*/

	// �������� ������ � ���������-��������� �������������� �������. Ÿ ����� ����� � �������� ����������,
	// ��������� �� ������������ ��������, ��������� �������������� ��������.
	PRaiseExcept   exception  = (PRaiseExcept)ExceptionInfo->ExceptionRecord->ExceptionAddress;
	PKeyEncCodeDsc descriptor = (PKeyEncCodeDsc)exception->DescriptorAddr;

	// ���� ���� �������� ���������� ����� ��������, ������ ����������� ������� ���������� �����������������
	// �������� ��� ������� �������� ����� �������� ��������� �� ������� ������ �������� �������������/������������,
	// � ������ - "������" �������� ����� �������� ������� � ��� �����������. ��������� ���� ����������� ���������
	// ������� AES, ��� �������� � ������������� ����������������� �������������� �������� �������.
//	descriptor->Length += HardwareBPFlag(ExceptionInfo->ContextRecord);

	switch(exception->InvalidOpCode) {
		
		// ������������� ������� ����� ����.
		case KeyDecInvalidOpCode: 
			// ��������� ����� �����.
			if(exception->SafeEIPAddr == NULL) ExceptionInfo->ContextRecord->Eip += sizeof(RaiseExcept);
				else ExceptionInfo->ContextRecord->Eip = exception->SafeEIPAddr;
			KeyDecWithFixUp(descriptor);
//			KeyDec(descriptor);
			break;

		// ������������ ������� ����� ����.
		case KeyEncInvalidOpCode: 
			// ��������� ����� �����.
			if(exception->SafeEIPAddr == NULL) ExceptionInfo->ContextRecord->Eip += sizeof(RaiseExcept); 
				else ExceptionInfo->ContextRecord->Eip = exception->SafeEIPAddr;
			KeyEncWithFixUp(descriptor);
//			KeyEnc(descriptor);
			break;

		// �� "����" ����������, �������� ���������� ���������� ����������� � �������. 
		default: 
			return EXCEPTION_CONTINUE_SEARCH;	
	}
	return EXCEPTION_CONTINUE_EXECUTION;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  �������� ������� ������������� ���������� ����� ��������.
DWORD HardwareBPFlag(struct _CONTEXT *ContextRecord) {
	if(ContextRecord->Dr0 == 0 && ContextRecord->Dr1 == 0 && ContextRecord->Dr2 == 0 && ContextRecord->Dr3 == 0) return(0); 
	return(1);
}

//////////////////////////////////////////////////////////////////////////////////////////////
// ������� ��� ������������� ������� KeyEnc. � ������ ������������ ��������� ���������������
// ������� ������ ������������ ������ �� �����. ���� �� ���������� ���� ValidateFlag, ���������� ���.
void __stdcall KeyEncWithFixUp(PKeyEncCodeDsc data) {
	if(data->ValidateFlag != TRUE) data->ValidateFlag = TRUE;
	KeyEnc(data);
}

//////////////////////////////////////////////////////////////////////////////////////////////
// ������� ��� ������������� ������� KeyDec � ������, ���� � ������������� ������� �������
// ������������ ��������. � ����������� ������� ���� ���� ValidateFlag, �� ���������
// ������������������ ��������� FALSE. ��� ��������, ��� ����������� ������������ ������
// ��� �� ���������� �� ������������ ������������ �������� �������� ImageBase.
//
// ������� ��������� ������������ �������, ������������ �������� �������� ImageBase. ����
// ������� ImageBase ��������� � ��������������, �� ������ ������ �� ����� - ������ ���������.
// ���� ������ �������� �� ������, ��������� �� ��������������� ImageBase, �� ��� ��������, ���
// ��������� ��������� "��������" ������, �������� � ������������ ��������� ������ ���� �������
// ��������. ������ ������ ���������� ��������� ������������ ������� ��������. ��� ����, �����
// ���������� ���������� ������������� ������� ���������� ������� ���������:
//
// 1. ���������� ���������� ������������ ��������� � �������.
// 2. ������������ ������:
//    - ���� ������������ ��������� ���, �� ������ ���������, � ��� ����� ������������ ������� ��������.
//    - ���� � ������� ���� ������������ ��������, �� ��������� ��� �����, � ������������ �������� �����
//      ������������ � �������� ���������, �������� ��������������� ImageBase. ����� ����� ����� �������
//      ��������� ���������������� ������� �������� � ������������� �� ������� �������� ImageBase. �����,
//      �������� ������ ���������� ��� �������������� � ����������� ������.
// 3. ���������� ���� ValidateFlag � �������� TRUE.
//
// ������������ ���������� ����������: CurrentImageBase, PEHeader (���������������� � WinMain),
//                                     OrgPEValue (����������� ����� �� ��������������� ������).
void __stdcall KeyDecWithFixUp(PKeyEncCodeDsc data) {
	DWORD	ImageBaseDelta, RelocsNum, i;
	PDWORD	Relocs;
	PBYTE	Buffer;
	KeyEncCodeDsc dataCopy;

	// ���� ������ ��� �������� �� ������������, �������������� ��� � ������� �������.
	if(data->ValidateFlag == TRUE) {
		KeyDec(data);
		return;
	}

	// ��������� �������� ������-��������.
	ImageBaseDelta = CurrentImageBase - OrgPEValue.ImageBase;

	// ���������, �������� �� ����� �� ��������������� ImageBase (� ���� ������ ImageBaseDelta == 0). ���� ��, ��
	// ������������� ValidateFlag = TRUE � �������������� ������ � ������� ������� - ������� �������� �� ���������.
	if(ImageBaseDelta == 0) {
		KeyDec(data);
		data->ValidateFlag = TRUE;
		return;
	}

	// ����� �������� �� ImageBase, ��������� �� ���������������. 
	// �������� ������ ��� ������ ������� ������������ ���������.
	if((Relocs = (PDWORD)HeapAlloc(GetProcessHeap(), 0, data->Length)) == NULL) {
		MsgBox("KeyDecWithFixUp", MB_SYSTEMMODAL | MB_ICONERROR, "Memory allocation error for Relocs!");	
		return;
	}

	// ��������� ������ ������� ������������ ��������� �������������� �������. ���� ������ ����, �� ������ �����
	// ������ �� ����� - ������ �� �������� ������������ ��������� � ��� ����� ��������� ������������. ����� -
	// ������ ����� ������� � ����������� �������������� ������ �������� �� ��������������� ImageBase. �����
	// �������������� �, ����������� ������������ �������� �������������� �������� �������� ImageBase � ��������
	// �������� ������ ���������������� ����� ������� ������.
	RelocsNum = SearchingRelocs(Relocs, data->Addr, data->Length);
	if(RelocsNum == 0) {

		// ������ �� �������� ������������ ���������. ������ �������������� ���.
		KeyDec(data);

	} else {

		// �������� ������ ��� ����� �������������� �������.
		if((Buffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, data->Length)) == NULL) {
			HeapFree(GetProcessHeap(), 0, Relocs);
			MsgBox("KeyDecWithFixUp", MB_SYSTEMMODAL | MB_ICONERROR, "Memory allocation error for Buffer!");	
			return;
		}

		// �������� ������������� ������ � �����.
		CopyMemory(Buffer, data->Addr, data->Length);

		// �������� ����� ������� � ���������, ��������������� �������� �� ��������������� ImageBase,
		// ���� ���������� ������� ������������� �������� �� �������� ������-��������. 
		for(i = 0; i < RelocsNum; i++) *(PDWORD)&Buffer[Relocs[i] - (DWORD)data->Addr] -= ImageBaseDelta;

		// ��������� ���������� ��� ����� ������� (���������� ��� ������ KeyDec)
		dataCopy.Addr = Buffer;
		dataCopy.Length = data->Length;
		dataCopy.KeySessionAddr = data->KeySessionAddr;

		// �������������� ����� �������
		KeyDec(&dataCopy);

		// �������� ����� ������� � ���������, ��������������� �������� �� �������� ImageBase,
		// ���� ���������� ������� ������������� �������� �� �������� ������-��������. 
		for(i = 0; i < RelocsNum; i++) *(PDWORD)&Buffer[Relocs[i] - (DWORD)data->Addr] += ImageBaseDelta;

		// �������� �������� ������ ��� �������������� � ����������� ������
		CopyMemory(data->Addr, Buffer, data->Length);

		HeapFree(GetProcessHeap(), 0, Buffer);

		MsgBox("Correcting FixUp and decrypting", MB_ICONINFORMATION, "Start Address\t%Xh\nData Length\t%d(%Xh)\n"
			"FixUp quantity\t%d", data->Addr, data->Length, data->Length, RelocsNum);

	}

	HeapFree(GetProcessHeap(), 0, Relocs);
	data->ValidateFlag = TRUE;
	return;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  ���������, ����������� ������������ �������������/������������ ���� ����� ����. ���������
//  ������ � ������ ��������������, � ������ �� ���������� ��-�� ���������������� ������������
//  �����, ������������ �������������� ������. 

void KeyEnc(PKeyEncCodeDsc data) {

	data->KeySessionAddr->status = hasp_encrypt(data->KeySessionAddr->handle, data->Addr, data->Length);
	// ���������, �� ��������� �� ������ � ������
	if(data->KeySessionAddr->status == HASP_BROKEN_SESSION || data->KeySessionAddr->status == HASP_INV_HND) {
		HaspReLogin(data->KeySessionAddr);
		data->KeySessionAddr->status = hasp_encrypt(data->KeySessionAddr->handle, data->Addr, data->Length);
	}
}

void KeyDec(PKeyEncCodeDsc data){

	data->KeySessionAddr->status = hasp_decrypt(data->KeySessionAddr->handle, data->Addr, data->Length);
	// ���������, �� ��������� �� ������ � ������
	if(data->KeySessionAddr->status == HASP_BROKEN_SESSION || data->KeySessionAddr->status == HASP_INV_HND) {
		HaspReLogin(data->KeySessionAddr);
		data->KeySessionAddr->status = hasp_decrypt(data->KeySessionAddr->handle, data->Addr, data->Length);
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////
// ��������� ��������������� ������, ����������� ��-�� ���������������� ������������ �����.
void HaspReLogin(PHaspSession session) {
	UCHAR vc[sizeof(vendor_code)];

	// �������� ������������� ������-��� ������ � ��������� ����������.
	CopyMemory(vc, vendor_code, sizeof(vc));
	
	// ����������� ����� "������" ������
	hasp_logout(session->handle);
	
	// �������� ��������� ������ � ������. ���� ����� ��� - ���� ��� ��������� � �����.
	while(session->status != HASP_STATUS_OK) {
		session->status = hasp_login(session->feature, Dec(vc, sizeof(vc)), (PDWORD)&session->handle);
		Enc(vc, sizeof(vc));
		Sleep(CheckKeyTimeout);
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ����� ���� �������� ����/������, ���������� ������������ �������.
// ���������� FALSE, ���� ���� �� ���� ������� �� ������ ��������.
BOOL CRCDataScan(PCrcDsc EntryPoint) {
	PCrcDsc  dscr;
	BOOL	 Res = TRUE;
	INT		 ImageBaseDelta = CurrentImageBase - OrgPEValue.ImageBase;

	// ��������� ����� ������� ������������ �������� �������� NULL � ���� NextDsc �������� �����������.
	// ������, ��� ���� �������� ������������ ���������, �������, ��� �������� �� �������� ������, ���������
	// �� ���������������, ��� �������� ����� ��������������� �� �������� ������� ��������, �.�. � ��� �����
	// ���������� �� NULL, � ������ ����� ������� � �������������� ���������� ImageBase. � ������ ����� � 
	// �������� ������� ������ �� ����� �������� ������� ������������.
	for(dscr = EntryPoint; (INT)dscr != ImageBaseDelta; dscr = (PCrcDsc)dscr->NextDsc) {
		if(!CheckCRC32WithFixUp(dscr)) Res = FALSE;
	}
	return Res;
}

//////////////////////////////////////////////////////////////////////////////////////////////
// ������� ��� ������������� ������� CheckCRC32 � ������, ���� � ���������� ������� �������
// ������������ ��������. � ����������� ������� ������������ ���� ValidateFlag, �� ���������
// ������������������ ��������� FALSE. ��� ��������, ��� ������, ����������� ������������,
// ��� �� ���������� �� ������������ ������������ �������� �������� ImageBase.
//
// ������� ��������� ������������ �������, ������������ ������������, ������������ �������� ��������
// ImageBase. ���� ������� ImageBase ��������� � ��������������, �� ������ ������ �� ����� - ������
// ���������. ���� ������ �������� �� ��������� �� ��������������� ImageBase, ����� ��� ����������
// �������� � ������������ � ������� �����. ��� ����� ����������:
//
// 1. ������� ����� �������, ����� � ��� ������������ �������� � ��������� � ��� ������� ��������
//    ������������ ��������������� ImageBase, ����� �������, ������� ������ � ���������, ���������������
//    �������� �� ��������������� ImageBase, ��� �������� � ����������� ��������� ����������� �����.
// 2. ��������� ����������� ����� ���������������� ����� �������. ���� ����� ������� � ���������, ������
//    ������ �� ����������� ���� ����������, ����� �������� ������� ��������, � � ���� ������ ������� 
//    ����������� ����� ������� �������� ���������. ���������� � ���� ValidateFlag �������� TRUE.
// 3. ���� ����� �� ������� � ���������, ������ � ������ ���� ������� ������������������� ���������, � �
//    ���� ������ ������ ����� �� ��������, �.�. ���������� ����� ��������� ����������� ����� ����������,
//    ��-�� ����, ��� ������ ���������� ������� �� ��������� � �������� ����������. ����� ���������� �
//    ���� ValidateFlag �������� TRUE, �.�. ��������� � ���� ������ ����� ����� ����� ��, ��� � ���
//    ��������������� ������� ����������� �����, � �������� �������� ������� ����������. ������, ���� 
//    ���� �� ������ ������� ����� ��������� ������, �� ������������� ���� �� �������. ��� ������ ������
//    ����� ������������ ��������� ����-��������, ����� ����� ���������� ����� ��������� �����������
//    ����� � ��� ����� ������� ������������� ���� ����.
//
// ��� � CheckCRC32, ������� ���������� ���������� ��������: 
//    TRUE  � ������, ���� ������ ���������.
//    FALSE � ������, ���� ������ �� ������� �������� � ������������ � ������� ����� (������ ���������
//    ������, ������ ��� ������������������ ������� � �.�.).
//
// ������������ ���������� ����������: CurrentImageBase, PEHeader (���������������� � WinMain),
//                                     OrgPEValue (����������� ����� �� ��������������� ������).

BOOL CheckCRC32WithFixUp(PCrcDsc descriptor) {
	INT		ImageBaseDelta;
	DWORD   RelocsNum, i;
	PDWORD	Relocs;
	PBYTE	Buffer;
	CrcDsc	dscCopy;
	BOOL	Res;

	// ���� ������ ��� ������������� �� ������������, ��������� ��� � ������� �������.
	if(descriptor->ValidateFlag == TRUE) return CheckCRC32(descriptor);

	// ��������� �������� ������-��������.
	ImageBaseDelta = CurrentImageBase - OrgPEValue.ImageBase;

	// ���������, �������� �� ����� �� ��������������� ImageBase (� ���� ������ ImageBaseDelta == 0).
	// ���� ��, �� ������������� ���� ValidateFlag = TRUE � ��������� ����������� ����� � ������� �������.
	if(ImageBaseDelta == 0) {
		Res = CheckCRC32(descriptor);
		descriptor->ValidateFlag = TRUE;
		return Res;
	}

	// ����� �������� �� ImageBase, ��������� �� ���������������. ��������� ������.

	// �������� ������ ��� ������ ������� ������������ ���������.
	if((Relocs = (PDWORD)HeapAlloc(GetProcessHeap(), 0, descriptor->Length)) == NULL) { 
		MsgBox("CheckCRC32WithFixUp", MB_SYSTEMMODAL | MB_ICONERROR, "Memory allocation error for Relocs!");	
		return FALSE;
	}

	// ��������� ������ ������� ������������ ��������� ����������� �������. ���� ������ ����, �� ������ �����
	// ������ �� ����� - ������ �� �������� ������������ ���������, ��������� ����������� ����� ��������� � 
	// ������������� ��������� �������. ����� - ������ ����� �������, ����������� � �������������� ������
	// �������� �� ��������������� ImageBase � ������� � ��������� ����������� ������.
	RelocsNum = SearchingRelocs(Relocs, descriptor->Addr, descriptor->Length);
	if(RelocsNum == 0) {

		// ������ �� �������� ������������ ���������. ������ ����� ������ �� ���������.
		Res = CheckCRC32(descriptor);
		descriptor->ValidateFlag = TRUE;

	} else {

		// �������� ������ ��� ����� ����������� �������.
		if((Buffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, descriptor->Length)) == NULL) {
			HeapFree(GetProcessHeap(), 0, Relocs);
			MsgBox("CheckCRC32WithFixUp", MB_SYSTEMMODAL | MB_ICONERROR, "Memory allocation error for Buffer!");	
			return FALSE; 
		}

		// �������� ���������� ������ � �����.
		CopyMemory(Buffer, descriptor->Addr, descriptor->Length);

		// �������� ����� ������� � ���������, ��������������� �������� �� ��������������� ImageBase,
		// ���� ���������� ������� ������������� �������� �� �������� ������-��������. 
		for(i = 0; i < RelocsNum; i++) *(PDWORD)&Buffer[Relocs[i] - (DWORD)descriptor->Addr] -= ImageBaseDelta;

		// ��������� ���������� ��� ����� ������� (���������� ��� ������ CheckCRC32)
		dscCopy.Addr   = Buffer;
		dscCopy.Length = descriptor->Length;
		dscCopy.OrgCrc = descriptor->OrgCrc;

		// ��������� ����������� ����� �������, ����������� � ������������ ��������������� ImageBase.
		CheckCRC32(descriptor);
		if((Res = CheckCRC32(&dscCopy)) == TRUE) {

			// ����� ������� ���������, �������� ��������� ����������� ����� ������� �� �������.
			DWORD OrgCRC = descriptor->OrgCrc;			// ��������� ������������ �������� ��� ������ �����������.
			descriptor->OrgCrc = descriptor->CurrCrc;
			descriptor->ValidateFlag = TRUE;

			MsgBox("CRC32 recalculating", MB_ICONINFORMATION, "Region ID\t\t%04d\nStart Address\t%Xh\nData Length\t%d(%Xh)\n"
				"Old Original CRC\t%08Xh\nNew Original CRC\t%08Xh\nFixUp quantity\t%d", descriptor->Id, descriptor->Addr,
				descriptor->Length, descriptor->Length, OrgCRC, descriptor->OrgCrc, RelocsNum);

		} else {

			// ����� ������� �����������. ��������� ������ ���������� �������, ������ ������ �������� 
			// ����������� ����� ����������. ��������� ��� ��� ����, ������ ������ �� �����.
			
			MsgBox("CRC32 recalculating", MB_ICONWARNING, "Region ID\t\t%04d\nStart Address\t%Xh\nData Length\t%d(%Xh)\n"
				   "Old Original CRC\t%08Xh\nNew Original CRC\tCRC Error! Recalculation impossible!\nFixUp quantity\t%d", 
				    descriptor->Id, descriptor->Addr, descriptor->Length, descriptor->Length, descriptor->OrgCrc, RelocsNum);

		}
		HeapFree(GetProcessHeap(), 0, Buffer);
	}
	HeapFree(GetProcessHeap(), 0, Relocs);
	return Res;
}

//////////////////////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ���������� ������� � ��������� ����������� ���� ��� �������, �����������
// ����� ����������. ��� ������� ����������� ���� ������������ ���� �� ���������� ��������� CRC32.
// �������, ������������ ��� ������� ����������� �����, ������������. ��� �� �������� ����������
// ��������� ������� ������� �������� � ����������� ����. 
BOOL CheckCRC32(PCrcDsc descriptor) {
    DWORD i, j, crc, crc_table[256], length = descriptor->Length; 
	PBYTE buffer = (PBYTE)descriptor->Addr;
	DWORD mask = 0xF5D92187, crc32poly = 0x1861A2A7;	// crc32poly ^ mask -> 0xEDB88320	
    
	for (i = 0; i < 256; i++) {
        crc = i;
        for (j = 0; j < 8; j++) crc = crc & 1 ? (crc >> 1) ^ crc32poly ^ mask : crc >> 1;
        crc_table[i] = crc;
    }
	
    crc = 0xFFFFFFFFUL;
	while(length--) crc = crc_table[(crc ^ *buffer++) & 0xFF] ^ (crc >> 8);
	descriptor->CurrCrc = crc ^ 0xFFFFFFFFUL;
	if(descriptor->CurrCrc == descriptor->OrgCrc) return TRUE; 
	return FALSE;
}

//////////////////////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ����� ���� �������� ����/������, ���������� ����� ��������� ������.
void RSCDataScan(PVOID EntryPoint) {
	PEccDsc  dscr;
	CHAR	 str[70], listing[1024] = "";
	INT		 ImageBaseDelta = CurrentImageBase - OrgPEValue.ImageBase;
	
	F1ErrCount = 0;

	// ��������� ����� ������� ������������ �������� �������� NULL � ���� NextDsc �������� �����������.
	// ������, ��� ���� �������� ������������ ���������, �������, ��� �������� �� �������� ������, ���������
	// �� ���������������, ��� �������� ����� ��������������� �� �������� ������� ��������, �.�. � ��� �����
	// ���������� �� NULL, � ������ ����� ������� � �������������� ���������� ImageBase. � ������ ����� � 
	// �������� ������� ������ �� ����� �������� ������� ������������.
	for(dscr = (PEccDsc)EntryPoint; (INT)dscr != ImageBaseDelta; dscr = (PEccDsc)dscr->NextDsc) {
		switch(RSCDataFixingWithFixUp(dscr)) {
		case 0: sprintf_s(str, sizeof(str), "Region #%02d --> No Errors.\n", dscr->Id);
			break;
		case 1: sprintf_s(str, sizeof(str), "Region #%02d --> Correction done. %u error(s) fixed.\n", dscr->Id, RSGetErrors()); 
			break;
		case 2: sprintf_s(str, sizeof(str), "Region #%02d --> Restoring is impossible. Errors is more than %d\n", dscr->Id, dscr->EccLength/2); 
			break;
		}
		strcat_s(listing, sizeof(listing), str);
	}
	RSLibClose();
	MessageBox(NULL, listing, "Reed-Solomon Codec", MB_SYSTEMMODAL | MB_ICONINFORMATION);
}

//////////////////////////////////////////////////////////////////////////////////////////////
// ������� ��� ������������� ������� RSCDataFixing � ������, ���� � ���������� ������� �������
// ������������ ��������. � ����������� ������� ������������ ���� ValidateFlag, �� ���������
// ������������������ ��������� FALSE. ��� ��������, ��� ������, ����������� ������������,
// ��� �� ���������� �� ������������ ������������ �������� �������� ImageBase.
//
// ������� ��������� ������������ �������, ������������ ������������, ������������ �������� ��������
// ImageBase. ���� ������� ImageBase ��������� � ��������������, �� ������ ������ �� ����� - ������
// ���������. ���� ������ �������� �� ��������� �� ��������������� ImageBase, ����� ��� ����������
// �������� � ������������ � ������� �����. ��� ����� ����������:
//
// 1. ������� ����� �������, ����� � ��� ������������ �������� � ��������� � ��� ������� ��������
//    ������������ ��������������� ImageBase, ����� ������� ������� ������ � ���������, ���������������
//    �������� �� ��������������� ImageBase, ��� �������� � ���������� ��� ��������� ������.
// 2. ��������� ����������� ���������������� ����� �������. ���� ��������� �� ����������, ������
//    ������ �� ����������� ���� ����������, ����� �������� ������� ��������, � � ���� ������ ����������
//    ��������� ����� ��� ��������� ������ ��� ����������� �������. ���������� � ���� ValidateFlag
//    �������� TRUE.
// 3. ���� ����������� ����� ������� ��������, ������ � ������ ���� ������� ������������������� ���������.
//	  ����� ������������ ����� ������� � �������� ����, ��������� ��������� ��� ��������� ������. ����
//    �������������� ������ �������, ����� ��������� � ��������������� ����� ������� ������� ��������, 
//	  ���������� ��� � ������������ � ������� ��������� ImageBase. ����� ����� ���������� ��������� �� 
//	  ����� ����� ��� ��������� ������. �����, ������������ ������, ���������� � ���� ��������������� �
//    ����������� �����. ���������� � ���� ValidateFlags �������� TRUE.
// 4. ���� ����������� ����� ������� ��������, � ������������ � � �������� ���� �� �������, ��, � ���� 
//    ������ ������ ����� �� ��������. ���������� ����� ��� ��������� ������ �� �������, ��������� ������
//    ���������� ������� �� ��������� � �������� ����������, � �������������� ����������� ���� ������������ 
//    ��� ����������� ������. ����� ���������� � ���� ValidateFlags �������� TRUE, �.�. ��������� � ����
//    ������ ����� ����� ����� ��, ��� � ��� ��������������� ������� ���� ��������� ������, � ��������
//    �������� ������� ����������.
//
// ��� � RSCDataFixing, ������� ���������� ���� �� ��������: 
//    0 - ������ ��������� � �� ���� ������.
//    1 - ������ ���������, ���� ������, ��� ��� ����������.
//    2 - ������ �� ������� �������� � ������������ � ������� ����� (������ ��������� ������, ������ ����� 
//        ������� ����� ������, � �.�.).
//
// ������������ ���������� ����������: CurrentImageBase, PEHeader (���������������� � WinMain),
//                                     OrgPEValue (����������� ����� �� ��������������� ������).

DWORD RSCDataFixingWithFixUp(PEccDsc descriptor) {
	CHAR	OldEcc[128], NewEcc[128];
	INT		ImageBaseDelta;
	DWORD	RelocsNum, i;
	PDWORD	Relocs;
	PBYTE	Buffer;
	EccDsc  dscCopy;
	BOOL	Res;

	// ���� ������ ��� ������������� �� ������������, ��������� ��� � ������� �������.
	if(descriptor->ValidateFlag == TRUE) return RSCDataFixing(descriptor);

	// ��������� �������� ������-��������.
	ImageBaseDelta = CurrentImageBase - OrgPEValue.ImageBase;

	// ���������, �������� �� ����� �� ��������������� ImageBase (� ���� ������ ImageBaseDelta == 0).
	// ���� ��, �� ������������� ���� ValidateFlag = TRUE � ��������� ����������� ����� � ������� �������.
	if(ImageBaseDelta == 0) {
		Res = RSCDataFixing(descriptor);
		descriptor->ValidateFlag = TRUE;
		return Res;
	}

	// ����� �������� �� ImageBase, ��������� �� ���������������.
	// �������� ������ ��� ������ ������� ������������ ���������. 
	if((Relocs = (PDWORD)HeapAlloc(GetProcessHeap(), 0, descriptor->Length)) == NULL) {
		MsgBox("RSCDataFixingWithFixUp", MB_SYSTEMMODAL | MB_ICONERROR, "Memory allocation error for Relocs!");	
		return 2;
	}

	// ��������� ������ ������� ������������ ��������� ����������� �������. ���� ������ ����, �� ������ �����
	// ������ �� ����� - ������ �� �������� ������������ ���������, ��� ��������� ������ �� ������� ����������
	// � ������������� ��������� �������. ����� - ������ ����� �������, ����������� � �������������� ������
	// �������� �� ��������������� ImageBase � ��������� �����������.
	RelocsNum = SearchingRelocs(Relocs, descriptor->Addr, descriptor->Length);
	if(RelocsNum == 0) {

		// ������ �� �������� ������������ ���������. ������ ����� ������ �� ���������.
		Res = RSCDataFixing(descriptor);

	} else {

		// �������� ������ ��� ����� ����������� �������.
		if((Buffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, descriptor->Length)) == NULL) {
			HeapFree(GetProcessHeap(), 0, Relocs);
			MsgBox("RSCDataFixingWithFixUp", MB_SYSTEMMODAL | MB_ICONERROR, "Memory allocation error for Buffer!");	
			return 2; 
		}

		// �������� ���������� ������ � �����.
		CopyMemory(Buffer, descriptor->Addr, descriptor->Length);

		// �������� ����� ������� � ���������, ��������������� �������� �� ��������������� ImageBase,
		// ���� ���������� ������� ������������� �������� �� �������� ������-��������. 
		for(i = 0; i < RelocsNum; i++) *(PDWORD)&Buffer[Relocs[i] - (DWORD)descriptor->Addr] -= ImageBaseDelta;

		// ��������� ���������� ��� ����� ������� (���������� ��� ������ RSCDataFixing)
		dscCopy.Addr      = Buffer;
		dscCopy.Length    = descriptor->Length;
		dscCopy.EccLength = descriptor->EccLength;
		CopyMemory(dscCopy.Ecc, descriptor->Ecc, descriptor->EccLength);
		
		// ��������� ������ ������������� ECC ��� ������ �����������
		sprintf_s(OldEcc, "%02X %02X %02X %02X %02X %02X %02X ...", descriptor->Ecc[0], descriptor->Ecc[1],
			      descriptor->Ecc[2], descriptor->Ecc[3], descriptor->Ecc[4], descriptor->Ecc[5], descriptor->Ecc[6]);

		// ��������� ����������� ����� �������, ����������� � ������������ ��������������� ImageBase.
		Res = RSCDataFixing(&dscCopy);
		if(Res == 0) {

			// ����������� �� ��������, ������ ������ �� ����������� ���� ����������, ����� �������� ������� 
			// ��������. ����������� ����� ��� ��������� ������ ��� ����������� �������.

			RSLibInit(descriptor->Length, descriptor->EccLength, NULL);
			RSCalcECC(descriptor->Addr, descriptor->Ecc);

		} else if(Res == 1) {

			// ����������� ������� ��������, ������, ����� ������������������� ��������� �� ���������
			// �������������� ����������� ����, � ����� ������� ���� ��������� � �������� ���������.

			// ����������� ��������������� ����� ������� ������� �� ������� ImageBase
			for(i = 0; i < RelocsNum; i++) *(PDWORD)&Buffer[Relocs[i] - (DWORD)descriptor->Addr] += ImageBaseDelta;

			// ����������� ����� ��� ��������� ������ ��� ��������������� ����� �������.
			RSLibInit(dscCopy.Length, dscCopy.EccLength, NULL);
			RSCalcECC(dscCopy.Addr, dscCopy.Ecc);

			// �������� ��������������� ������ � ����� ��� ��������� ������ �� ������� �����.
			CopyMemory(descriptor->Addr, Buffer, descriptor->Length);
			CopyMemory(descriptor->Ecc, dscCopy.Ecc, descriptor->EccLength);

		} else if(Res == 2) {

			// ����������� ������� ��������, �������������� ����������� ���� ������������ ���  
			// ��������������. ��������� ������ ���������� �������, ������ ������ ���� ��������� 
			// ������ ����������. ��������� ��� ��� ����, ������ ������ �� �����.

			MsgBox("ECC recalculating", MB_ICONWARNING, "Region ID\t\t%04d\nStart Address\t%Xh\nData Length\t%d(%Xh)\n"
				   "Old ECC\t\t%s\nNew ECC\t\tECC Error! Recalculation impossible!\nFixUp quantity\t%d", descriptor->Id,
				    descriptor->Addr, descriptor->Length, descriptor->Length, OldEcc, RelocsNum);
		}

		// ����� �����������
		if(Res == 0 || Res == 1) {
			sprintf_s(NewEcc, "%02X %02X %02X %02X %02X %02X %02X ...", descriptor->Ecc[0], descriptor->Ecc[1],
				    descriptor->Ecc[2], descriptor->Ecc[3], descriptor->Ecc[4], descriptor->Ecc[5], descriptor->Ecc[6]);
			MsgBox("ECC recalculating", MB_ICONINFORMATION, "Region ID\t\t%04d\nStart Address\t%Xh\nData Length\t%d(%Xh)\n"
				   "Old ECC\t\t%s\nNew ECC\t\t%s\nFixUp quantity\t%d", descriptor->Id, descriptor->Addr,
				    descriptor->Length, descriptor->Length, OldEcc, NewEcc, RelocsNum);
		}

		HeapFree(GetProcessHeap(), 0, Buffer);
	}
	HeapFree(GetProcessHeap(), 0, Relocs);
	descriptor->ValidateFlag = TRUE;
	return Res;
}

//////////////////////////////////////////////////////////////////////////////////////////////
// ��������� ��������� �������� ����������� �, � ������ �������������, ���� �� ���������
// �������������� ����������� ECC, �������������� ����/������, ���������� ���� ECC
DWORD RSCDataFixing(PEccDsc descriptor) {
	
	RSLibInit(descriptor->Length, descriptor->EccLength, NULL);
	if(RSCheckData(descriptor->Addr, descriptor->Ecc)  == 0) return 0;	// ��� ������
	if(RSRepairData(descriptor->Addr, descriptor->Ecc) == 1) return 1;	// ������ ����, ��� ����������
	return 2;															// ������ ������� �����, ��������� ����������
}

//////////////////////////////////////////////////////////////////////////////////////////////
// ������� ���������� ���������� ������������ ��������� ������ ���������� ��������� �������. 
// ���������� ������ ��������� ������������ ��������� ���������� � ������ Reloc. 
// 
// ������������ ���������� ����������: CurrentImageBase, PEHeader (���������������� � WinMain).
DWORD SearchingRelocs(PDWORD Reloc, PBYTE Addr, DWORD Length) {
	DWORD	RegStartAddr = (DWORD)Addr, RegEndAddr = (DWORD)Addr + Length;
	DWORD	FixupIndex, FixupMaxIndex, PageStartAddr, FixupAddr;
	DWORD	BlockRVA, RelocDirSize, RelocDirEndAddr, RelocsNum = 0;
	PIMAGE_BASE_RELOCATION Block;

	// ������ ������������ ��������� ������������ ��� ������������������ ������ ������� ��������.
	// ������ ���� ��������� ������������ �������� �� �������� �������� � 4 ��, � ����� ���������,
	// ���������� RVA-����� �������� � ������ � ����� �����, ������� ��������� (+2 DWORD).

	// �� PE-��������� �������� RVA-����� ������� ����� � ������ ������ ������ ������������ ���������.
	BlockRVA = PEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	RelocDirSize = PEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	// ����� ������ �����, ����������� ��������, � ������� ������������ �������� ������� ����������� �������.
	Block = (PIMAGE_BASE_RELOCATION)(CurrentImageBase + BlockRVA);		// ������ ���� ������� ��������
	RelocDirEndAddr = CurrentImageBase + BlockRVA + RelocDirSize;		// ����� ����� ���������� �����
	for(; (DWORD)Block < RelocDirEndAddr; Block = (PIMAGE_BASE_RELOCATION)((DWORD)Block + Block->SizeOfBlock)) {

		// ���� ��������, ����������� ������� ������ ������� ��������, ��� �� �������� ������� ����������� 
		// �������, ���������� �. ���� ��� �� �������� - ��������� ����, �.�. ���, ��� �����, ��� �������. 
		PageStartAddr = CurrentImageBase + Block->VirtualAddress;
		if(PageStartAddr < (RegStartAddr & 0xFFFFF000)) continue;
		if(PageStartAddr > (RegEndAddr & 0xFFFFF000)) break;

		// ����� ������ ������ ����� ������� �������� (fixup'�) �� ��������� ������� ����������� �������.
		FixupIndex = sizeof(IMAGE_BASE_RELOCATION)/sizeof(WORD);  // ������ fixup - ������ ����� ��������� �����
		FixupMaxIndex = Block->SizeOfBlock/sizeof(WORD);		  // ������������ ������ ��� fixup'� � �����
		for(; FixupIndex < FixupMaxIndex; FixupIndex++) {

			// ����� ���� ����� ������� �� ����� ������������� ��������, � ��� fixup
			FixupAddr = *(PWORD)((DWORD)Block + FixupIndex * sizeof(WORD)); 

			// ��������� ���������� ����� ������������� ��������, �� ������� ��������� ������� ��������. ��� ���� 
			// ������������ ������ fixup'� ���� IMAGE_REL_BASED_HIGHLOW (��� �������� � ������� ������� ����� fixup'�) 
			if((FixupAddr & 0xF000) != (IMAGE_REL_BASED_HIGHLOW << 12)) continue;
			FixupAddr = PageStartAddr + (FixupAddr & 0x0FFF);

			// ���� ����� ������������� �������� ��� �� �������� ������ ����������� �������, ���������� ���. 
			// ���� ��� �� �������� - ��������� ����. ���� ����� - ��������� ����� � ������.
			if(FixupAddr < RegStartAddr) continue;
			if(FixupAddr >= RegEndAddr) break;
			Reloc[RelocsNum++] = FixupAddr;
		}
	}
	return RelocsNum;	// ���������� ��������� ������������ ���������.
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
