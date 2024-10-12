//*****************************************************************************
// (v01) ���������� ������, ��������������� ����������� �����������:  
// ���� ���� ���� - ���������� �����������,
// ���� ����� ��� - ��������� ��������� �� ������, ���������� �� �����������.
//
// ����� - ������ ����� (Sergey.Uskov@safenet-inc.com, uskov@smtp.ru)
//*****************************************************************************

#include <windows.h>
#include <stdio.h>

#include "resource.h"
#include "hasp_api.h"
#include "hasp_vcode.h"

#define MAX_LOADSTRING 100

#define xGap 50		// ���������� ����� ��������� ��������� ��� ������ ������.
#define yGap 20		// ���������� ����� ��������� �������� ��� ������ ������.

#define int3	__asm int 3		\
				__asm nop

//////////////////////////////////////////////////////////////////////////////////////////////
// ���������-��������� ������ � ������.

struct HaspSession {
	hasp_handle_t	handle;		// ����� ������� ������ � ������.
	hasp_status_t	status;		// ��� ������ ��������� ��������.
	hasp_feature_t	feature;	// ���� ��� ������� ������.
};

//////////////////////////////////////////////////////////////////////////////////////////////
// ���������� ����������.
HINSTANCE hInst;							
HMENU hMainMenu;
TCHAR szTitle[MAX_LOADSTRING];				
TCHAR szWindowClass[MAX_LOADSTRING];		
TCHAR szText[128];

HANDLE hF1Thread, hF2Thread;					// �������������� ���������� �������
BOOL f1Terminate = TRUE, f2Terminate = TRUE;	// �������� ���������� �������

HaspSession Main = {HASP_INVALID_HANDLE_VALUE, HASP_HASP_NOT_FOUND, HASP_DEFAULT_FID};

//////////////////////////////////////////////////////////////////////////////////////////////

ATOM				RegisterWindowClass(HINSTANCE hInstance);
BOOL				InitInstance(HINSTANCE, int);
LRESULT CALLBACK	About(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
void				Function1(PVOID hwnd);
void				Function2(PVOID hwnd);

//////////////////////////////////////////////////////////////////////////////////////////////

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	MSG msg;
	HACCEL hAccelTable;
	HWND hWnd;

	// ��������� ������������� ���������� � ���������� ����������.
	hInst = hInstance;

	// ��������� Login �� Feature ID 0, ���� ������ - ������� ��������� � ��������� ������.
	Main.status = hasp_login(Main.feature, vendor_code, &Main.handle);
	if(Main.status != HASP_STATUS_OK) {
		sprintf_s(szText, sizeof(szText), "Login error #%d", Main.status);
		MessageBox(NULL, szText, "Feature ID = 0", MB_SYSTEMMODAL | MB_ICONERROR);
		return Main.status;
	}

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

	// ��������� ���� ��������� ���������.
	while (GetMessage(&msg, NULL, 0, 0)) {
		if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}
	Main.status = hasp_logout(Main.handle);
	return 0;
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
	return RegisterClassEx(&wcex);
}

//////////////////////////////////////////////////////////////////////////////////////////////
// ��������� ��������� �������� � ����������� �������� ���� ����������.
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow) {
	HWND hWnd;

	hWnd = CreateWindow(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, 0, 930, 606, NULL, NULL, hInstance, NULL);	if(!hWnd) return FALSE;
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
			break;

		case WM_DESTROY:
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
void Function1(PVOID hwnd) {
	HDC		hDC;
	RECT	rect;
	INT		delay, x, y;
	UINT	z_min = 0x0000, z_max = 0x0080, z_xor = 0xFF00, z_and = 0x00FF;
	UINT	z0 = 0, z1 = 0, z2 = 0;
	TCHAR	szTxt[8];

	while(!f1Terminate) {
		hDC = GetDC((HWND)hwnd);
		GetWindowRect((HWND)hwnd, &rect);
		delay = 50;

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
	ExitThread(0);
}

//////////////////////////////////////////////////////////////////////////////////////////////
//  ��������� ���������� ������-��������� ����� � ��������� [128; 255] � ��������� ������.
//  ��� �������� � �������� �������� ��������� ������� ������, ��� ������ - �������. ��� ��, 
//  � ��������� ����������� ������� �� "������ �������" - ��������� ������������ ������������������
//  �� ��� ����� ������, ������������ ���� �� ����� �� �������, ��������� �� ��� ��������� ����� ������.
void Function2(PVOID hwnd) {
	HDC		hDC;
	RECT	rect;
	INT		delay, x, y;
	UINT	z_min = 0x0080, z_max = 0x00FF, z_xor = 0xFF00, z_and = 0x00FF;
	UINT	z0 = 0, z1 = 0, z2 = 0;
	TCHAR	szTxt[8];
	
	while(!f2Terminate) {
		hDC = GetDC((HWND)hwnd);
		GetWindowRect((HWND)hwnd, &rect);
		delay = 50;
		
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
	ExitThread(0);
}
