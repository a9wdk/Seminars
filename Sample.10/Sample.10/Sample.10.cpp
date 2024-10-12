//*****************************************************************************
// (v10) ������ ���� ������� ���������� ������������� ���������� �����
// ����������� �������������� ��������.
//
// ����� - ������ ����� (Sergey.Uskov@safenet-inc.com, uskov@smtp.ru)
//*****************************************************************************

#include <windows.h>
#include <stdio.h>

#include "resource.h"
#include "hasp_api.h"
#include "macros.h"			// ��������� � ��������� ������, ������������ ��� �������� ���������� �� ������� �������.
#include "enc_str.h"		// ������, ���������� ������������ ��� ������ ������� �������.

#define MAX_LOADSTRING 100

#define xGap 50				// ���������� ����� ��������� ��������� ��� ������ ������.
#define yGap 20				// ���������� ����� ��������� �������� ��� ������ ������.

#define CheckKeyTimeout		500						// �������� �������� ������ ����� (� �������������).
#define CheckThreadTimeout	CheckKeyTimeout*2		// �������� �������� ��������� ������ �������� ������ �����
#define MinReactionTimeout	10						// ����������� �������� (� ���.) �� ������� �� ���������� ������.
#define MaxReactionTimeout	20						// ������������ �������� (� ���.) �� ������� �� ���������� ������.

//////////////////////////////////////////////////////////////////////////////////////////////
// ����������� �������������� ��������.

EXCEPTION_DISPOSITION __cdecl SEH_Handler(struct _EXCEPTION_RECORD *ExceptionRecord, void *EstablisherFrame, 
                                          struct _CONTEXT *ContextRecord, void *DispatcherContext);

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

int	TimerID, ProtectTimeout = MaxReactionTimeout;

// ����� ������� ���������� ���� ������� ������� ������������� ��������� ���������� �������������� ��������.
// ��� ����� ��������� ��� ������������� ���������� hVEH_Handler, �� ����� ���������� startup-���� �������.

PVOID  hVEH_Handler = AddVectoredExceptionHandler(0, VEH_Handler);	// ������������� VEH-�����������

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
void				KeyEnc(PKeyEncCodeDsc data);
void				KeyDec(PKeyEncCodeDsc data);
void				HaspReLogin(PHaspSession session);
DWORD				MsgBox(PCHAR title, UINT style, PCHAR format, ...);

//////////////////////////////////////////////////////////////////////////////////////////////

HaspSession Main = {HASP_INVALID_HANDLE_VALUE, HASP_HASP_NOT_FOUND, HASP_DEFAULT_FID};

CstEncCodeDsc WM_CstEnc = {(PBYTE)0x78563412};		// Encrypt-���������� ������� ���� ����� ������� l1 � l2.

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	MSG msg;
	HWND hWnd;
	HACCEL hAccelTable;
	UCHAR vc[sizeof(vendor_code)];

	// ��������� ������������� ���������� � ���������� ����������.
	hInst = hInstance;
	
	// �������� ������������� ������-��� ������ � ��������� ����������.
	CopyMemory(vc, vendor_code, sizeof(vc));

	RaiseExceptionForCustomDecrypt(WM_CstEnc, NULL);	
	l1:			// ������ �������.

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
		RaiseExceptionForCustomEncrypt(WM_CstEnc, offset l3);	// ����� ��������� ���������� �������� ���������� �� l3.
	}
	
	// ������������ ����� ����, ������� ������� ���� ���������� � ���������� ���.
	RegisterWindowClass(hInst);
	if (!InitInstance (hInst, nCmdShow)) RaiseExceptionForCustomEncrypt(WM_CstEnc, offset l4);

	// ��������� �����, ����������� ������� ����� ����� � �������� ��� ���������.
	hKeyBackgroundChk = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)KeyBackgroundChk, 0, 0, NULL);
	SetThreadPriority(hKeyBackgroundChk, THREAD_PRIORITY_LOWEST);

	RaiseExceptionForCustomEncrypt(WM_CstEnc, NULL);	
	l2:			// ����� �������.

	// ��������� ���� ��������� ���������.
	while (GetMessage(&msg, NULL, 0, 0)) {
		if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}
	Main.status = hasp_logout(Main.handle);
	return 0;

	l3:		// ����� - ���������� ��� ��������.
	MsgBox("WinMain", MB_SYSTEMMODAL | MB_ICONINFORMATION, "The application already started!");
	return -1;

	l4:
	return -2;

	AsmCstEncCodeMrk(WM_CstEnc, l1, l2);		// Encrypt-������ ������� ���� ����� ������� l1 � l2.
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
	
	hWnd = CreateWindow(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, 0, 930, 606, NULL, NULL, hInstance, NULL);

	// ���������� ����������, ���� ��� �����. ��, ���, ���� �����-���� �������� ��� ������ CreateWindow(...)
   if(!hWnd || Main.status) return FALSE;
	ShowWindow(hWnd, nCmdShow);
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

#define F1_Feature 1								// ����� ���� �����, ������� ����� ������������ �������.

HaspSession Fn1 = {HASP_INVALID_HANDLE_VALUE, HASP_HASP_NOT_FOUND, F1_Feature};

KeyEncCodeDsc  Fn1_KeyEnc1 = {(PHaspSession)0x78563412};	// Encrypt-���������� ������� ���� ����� ������� l1 � l2.
KeyEncCodeDsc  Fn1_KeyEnc2 = {(PHaspSession)0x78563412};	// Encrypt-���������� ������� ���� ����� ������� l2 � l3.

void Function1(PVOID hwnd) {
	HDC		hDC;
	RECT	rect;
	INT		delay, x, y;
	UINT	z_min = 0x0000, z_max = 0x0080, z_xor = 0xFF00, z_and = 0x00FF;
	UINT	z0 = 0, z1 = 0, z2 = 0;
	TCHAR	szTxt[8];
	UCHAR vc[sizeof(vendor_code)];
	
	InstallHandler(SEH_Handler);
	
	RaiseExceptionForKeyDecrypt(Fn1_KeyEnc1, NULL);	
	l1:		// ������ 1-�� �������.

	// �������� ������������� ������-��� � ��������� ����������.
	CopyMemory(vc, vendor_code, sizeof(vc));
	
	// ��������� Login �� Feature 1, ���� ������ - ������� ��������� � ��������� ������ �������. ����� 
	// ������� Login ������������ ������������� Vendor-����, ����� ����� ������ - �������� ������������.
	Fn1.status = hasp_login(Fn1.feature, Dec(vc, sizeof(vc)), &Fn1.handle);
	Enc(vc, sizeof(vc));
	if(Fn1.status != HASP_STATUS_OK) {
		MsgBox("Feature ID = 1", MB_SYSTEMMODAL | MB_ICONERROR, "Login error #%d", Fn1.status);
		EnableMenuItem(hMainMenu, IDM_F1Start, MF_ENABLED);
		EnableMenuItem(hMainMenu, IDM_F1Stop, MF_GRAYED);
		RaiseExceptionForKeyEncrypt(Fn1_KeyEnc1, offset l4);	// ����� ��������� ���������� �������� ���������� �� l4.
	}

	RaiseExceptionForKeyDecrypt(Fn1_KeyEnc2, NULL);	
	l2:	// ����� 1-�� � ������ 2-�� ��������.
	RaiseExceptionForKeyEncrypt(Fn1_KeyEnc1, NULL);

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
				z0 = ((rand() % (z_max - z_min) + z_min) ^ (z_xor & z_and)) & 0x0000FFFF;

				// ���� ��������� "������ �������" - ��� ���������� ����� ������ - ������� 
				// ��������� �� ��� ����� ������ � ������ ������� ��������. �������� ������ ��� 
				// 128 ������� ������� ������ (��� ������� �����), ��� ������ ����� ��������� 
				// ������� � ���������� ������� ������.
				
				if(z1 == z0 && z2 == z0) {
					SetTextColor(hDC, RGB(0, 0, 192));
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
	// ������������ ����� ���� "Start" � ����������� "Stop".
	EnableMenuItem(hMainMenu, IDM_F1Start, MF_ENABLED);
	EnableMenuItem(hMainMenu, IDM_F1Stop, MF_GRAYED);

	RaiseExceptionForKeyEncrypt(Fn1_KeyEnc2, NULL);
	l3:		// ����� 2-�� �������.

	Fn1.status = hasp_logout(Fn1.handle);
	RemoveHandler;
	ExitThread(0);

	l4:		// ����� �� ������ ��� ��������� ���������� hasp_login
	RemoveHandler;
	ExitThread(1);

	AsmKeyEncCodeMrk(Fn1_KeyEnc1, l1, l2, Main);		// Encrypt-������ ������� ���� ����� ������� l1 � l2.
	AsmKeyEncCodeMrk(Fn1_KeyEnc2, l2, l3, Fn1);			// Encrypt-������ ������� ���� ����� ������� l2 � l3.
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  ��������� ���������� ������-��������� ����� � ��������� [128; 255] � ��������� ������.
//  ��� �������� � �������� �������� ��������� ������� ������, ��� ������ - �������. ��� ��, 
//  � ��������� ����������� ������� �� "������ �������" - ��������� ������������ ������������������
//  �� ��� ����� ������, ������������ ���� �� ����� �� �������, ��������� �� ��� ��������� ����� ������.

#define F2_Feature 2								// ����� ���� �����, ������� ����� ������������ �������.

HaspSession Fn2 = {HASP_INVALID_HANDLE_VALUE, HASP_HASP_NOT_FOUND, F2_Feature};

KeyEncCodeDsc  Fn2_KeyEnc1 = {(PHaspSession)0x78563412};	// Encrypt-���������� ������� ���� ����� ������� l1 � l2.
KeyEncCodeDsc  Fn2_KeyEnc2 = {(PHaspSession)0x78563412};	// Encrypt-���������� ������� ���� ����� ������� l2 � l3.

void Function2(PVOID hwnd) {
	HDC		hDC;
	RECT	rect;
	INT		delay, x, y;
	UINT	z_min = 0x0080, z_max = 0x00FF, z_xor = 0xFF00, z_and = 0x00FF;
	UINT	z0 = 0, z1 = 0, z2 = 0;
	TCHAR	szTxt[8];
	UCHAR vc[sizeof(vendor_code)];
	
	InstallHandler(SEH_Handler);
	
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
	RemoveHandler;
	ExitThread(0);

	l4:		// ����� ��� ���������� �������� �� ������ �������.
	RemoveHandler;
	ExitThread(1);

	AsmKeyEncCodeMrk(Fn2_KeyEnc1, l1, l2, Main);	// Encrypt-������ ������� ���� ����� ������� l1 � l2.
	AsmKeyEncCodeMrk(Fn2_KeyEnc2, l2, l3, Fn2);		// Encrypt-������ ������� ���� ����� ������� l2 � l3.
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  ��������� ��������� ������� ����� ����� � ��������� ����������. ��������� ���������,
//	����������� ���������� ��������� ����� ������������ ������ (scope, format � vendorcode),
//  ����������� � ���������������� ��������������� ����� ������� hasp_get_info(), ����� ����
//  ����� ���������������.

CstEncCodeDsc KBChk_CstEnc = {(PBYTE)0x78563412};		// Encrypt-���������� ������� ���� ����� ������� l1 � l2.

void KeyBackgroundChk(PVOID hwnd) {
	HANDLE hMsg = INVALID_HANDLE_VALUE;
	DWORD hMsgState = NULL;
	char *info = 0;
	hasp_status_t status;
	UCHAR vc[sizeof(vendor_code)];
	
	// �������� ������������� ������-��� � ��������� ����������.
	CopyMemory(vc, vendor_code, sizeof(vc));

	while(TRUE) {
		RaiseExceptionForCustomDecrypt(KBChk_CstEnc, NULL);	
		l1:			// ������ �������.

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

		RaiseExceptionForCustomEncrypt(KBChk_CstEnc, NULL);	
		l2:			// ����� �������.

		Sleep(CheckKeyTimeout);
	}
	ExitThread(0);

	AsmCstEncCodeMrk(KBChk_CstEnc, l1, l2);		// Encrypt-������ ������� ���� ����� ������� l1 � l2.
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
//  �������������� SEH-���������� �������������� ��������.
EXCEPTION_DISPOSITION __cdecl SEH_Handler(struct _EXCEPTION_RECORD *ExceptionRecord, void *EstablisherFrame,
                                          struct _CONTEXT *ContextRecord, void *DispatcherContext) {
	// ���������� ������.
/*	MsgBox("SEH", MB_OK, "Exception Code\t %.8X\nException Address\t %.8X\nInvalid Instruction\t %X", 
		    ExceptionRecord->ExceptionCode, ExceptionRecord->ExceptionAddress, 
			*(USHORT *)ExceptionRecord->ExceptionAddress);
*/

	// �������� ������ � ���������-��������� �������������� �������. Ÿ ����� ����� � �������� ����������,
	// ��������� �� ������������ ��������, ��������� �������������� ��������.
	PRaiseExcept   exception  = (PRaiseExcept)ExceptionRecord->ExceptionAddress;
	PKeyEncCodeDsc descriptor = (PKeyEncCodeDsc)exception->DescriptorAddr;
	
	// ���� ���� �������� ���������� ����� ��������, ������ ����������� ������� ���������� �����������������
	// �������� ��� ������� �������� ����� �������� ��������� �� ������� ������ �������� �������������/������������,
	// � ������ - "������" �������� ����� �������� ������� � ��� �����������. ��������� ���� ����������� ���������
	// ������� AES, ��� �������� � ������������� ����������������� �������������� �������� �������.
	descriptor->Length += HardwareBPFlag(ContextRecord);
	
	switch(exception->InvalidOpCode) {
		
		// ������������� ������� ����� ����.
		case KeyDecInvalidOpCode: 
			// ��������� ����� �����.
			if(exception->SafeEIPAddr == NULL) ContextRecord->Eip += sizeof(RaiseExcept);
				else ContextRecord->Eip = exception->SafeEIPAddr;
			KeyDec(descriptor);
			break;
			
		// ������������ ������� ����� ����.
		case KeyEncInvalidOpCode: 
			// ��������� ����� �����.
			if(exception->SafeEIPAddr == NULL) ContextRecord->Eip += sizeof(RaiseExcept); 
				else ContextRecord->Eip = exception->SafeEIPAddr;
			KeyEnc(descriptor);
			break;
			
		// �� "����" ����������, �������� ���������� ���������� ����������� � �������. 
		default: return ExceptionContinueSearch;	
	}
	return ExceptionContinueExecution;
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
	PCstEncCodeDsc descriptor = (PCstEncCodeDsc)exception->DescriptorAddr;

	switch(exception->InvalidOpCode) {
		
		// ������������� ������� ��������� ����������.
		case CstDecInvalidOpCode: 
			// ��������� ����� �����.
			if(exception->SafeEIPAddr == NULL) ExceptionInfo->ContextRecord->Eip += sizeof(RaiseExcept); 
				else ExceptionInfo->ContextRecord->Eip = exception->SafeEIPAddr;
			Dec(descriptor->Addr, descriptor->Length);
			break;
			
		// ������������ ������� ��������� ����������.
		case CstEncInvalidOpCode: 
			// ��������� ����� �����.
			if(exception->SafeEIPAddr == NULL) ExceptionInfo->ContextRecord->Eip += sizeof(RaiseExcept); 
				else ExceptionInfo->ContextRecord->Eip = exception->SafeEIPAddr;
			Enc(descriptor->Addr, descriptor->Length);
			break;

		// �� "����" ����������, �������� ���������� ���������� ����������� � �������. 
		default: 

			// ���������� ������.
/*			MsgBox("VEH (others exceptions)", MB_OK, "Exception Code\t %.8X\nException Address\t %.8X\nInvalid Instruction\t %X", 
				    ExceptionInfo->ExceptionRecord->ExceptionCode, ExceptionInfo->ExceptionRecord->ExceptionAddress, 
					*(USHORT *)ExceptionInfo->ExceptionRecord->ExceptionAddress);
*/
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
//  ����� MessageBox � ��������� ������� ������.
DWORD MsgBox(PCHAR title, UINT style, PCHAR format, ...) {
	char buffer[1024];
	va_list arg_ptr;

	va_start(arg_ptr, format);
	vsprintf_s(buffer, sizeof(buffer), format, arg_ptr);
	va_end(arg_ptr);
	return MessageBox(NULL, buffer, title, style);
}
