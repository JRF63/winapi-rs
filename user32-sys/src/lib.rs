// Copyright © 2015, Peter Atashian
// Licensed under the MIT License <LICENSE.md>
//! FFI bindings to user32.
#![no_std]
#![unstable]
#[cfg(test)] extern crate std;
extern crate winapi;
use winapi::*;
extern "system" {
    pub fn ActivateKeyboardLayout(hkl: HKL, flags: UINT) -> HKL;
    pub fn AddClipboardFormatListener(hWnd: HWND) -> BOOL;
    pub fn AdjustWindowRect(lpRect: LPRECT, dwStyle: DWORD, bMenu: BOOL) -> BOOL;
    pub fn AdjustWindowRectEx(
        lpRect: LPRECT, dwStyle: DWORD, bMenu: BOOL, dwExStyle: DWORD,
    ) -> BOOL;
    pub fn AllowSetForegroundWindow(dwProcessId: DWORD) -> BOOL;
    // pub fn AnimateWindow();
    pub fn AnyPopup() -> BOOL;
    // pub fn AppendMenuA();
    // pub fn AppendMenuW();
    pub fn ArrangeIconicWindows(hWnd: HWND) -> UINT;
    pub fn AttachThreadInput(idAttach: DWORD, idAttachTo: DWORD, fAttach: BOOL) -> BOOL;
    // pub fn BeginDeferWindowPos();
    pub fn BeginPaint(hwnd: HWND, lpPaint: LPPAINTSTRUCT) -> HDC;
    pub fn BlockInput(fBlockIt: BOOL) -> BOOL;
    pub fn BringWindowToTop(hWnd: HWND) -> BOOL;
    // pub fn BroadcastSystemMessage();
    // pub fn BroadcastSystemMessageA();
    // pub fn BroadcastSystemMessageExA();
    // pub fn BroadcastSystemMessageExW();
    // pub fn BroadcastSystemMessageW();
    // pub fn CalculatePopupWindowPosition();
    // pub fn CallMsgFilter();
    // pub fn CallMsgFilterA();
    // pub fn CallMsgFilterW();
    // pub fn CallNextHookEx();
    // pub fn CallWindowProcA();
    // pub fn CallWindowProcW();
    // pub fn CancelShutdown();
    // pub fn CascadeChildWindows();
    // pub fn CascadeWindows();
    pub fn ChangeClipboardChain(hwndRemove: HWND, hwndNewNext: HWND) -> BOOL;
    // pub fn ChangeDisplaySettingsA();
    // pub fn ChangeDisplaySettingsExA();
    pub fn ChangeDisplaySettingsExW(
        lpszDeviceName: LPCWSTR, lpDevMode: *mut DEVMODEW, hwnd: HWND, dwFlags: DWORD,
        lParam: LPVOID,
    ) -> LONG;
    pub fn ChangeDisplaySettingsW(lpDevMode: *mut DEVMODEW, dwFlags: DWORD) -> LONG;
    // pub fn ChangeMenuA();
    // pub fn ChangeMenuW();
    // pub fn ChangeWindowMessageFilter();
    // pub fn ChangeWindowMessageFilterEx();
    // pub fn CharLowerA();
    // pub fn CharLowerBuffA();
    // pub fn CharLowerBuffW();
    // pub fn CharLowerW();
    // pub fn CharNextA();
    // pub fn CharNextExA();
    // pub fn CharNextW();
    // pub fn CharPrevA();
    // pub fn CharPrevExA();
    // pub fn CharPrevW();
    // pub fn CharToOemA();
    // pub fn CharToOemBuffA();
    // pub fn CharToOemBuffW();
    // pub fn CharToOemW();
    // pub fn CharUpperA();
    // pub fn CharUpperBuffA();
    // pub fn CharUpperBuffW();
    // pub fn CharUpperW();
    // pub fn CheckDlgButton();
    // pub fn CheckMenuItem();
    // pub fn CheckMenuRadioItem();
    // pub fn CheckRadioButton();
    // pub fn ChildWindowFromPoint();
    // pub fn ChildWindowFromPointEx();
    // pub fn ClientToScreen();
    pub fn ClipCursor(lpRect: *const RECT) -> BOOL;
    pub fn CloseClipboard() -> BOOL;
    // pub fn CloseDesktop();
    // pub fn CloseGestureInfoHandle();
    // pub fn CloseTouchInputHandle();
    pub fn CloseWindow(hWnd: HWND) -> BOOL;
    pub fn CloseWindowStation(hWinSta: HWINSTA) -> BOOL;
    // pub fn CopyAcceleratorTableA();
    // pub fn CopyAcceleratorTableW();
    // pub fn CopyIcon();
    // pub fn CopyImage();
    // pub fn CopyRect();
    pub fn CountClipboardFormats() -> c_int;
    // pub fn CreateAcceleratorTableA();
    // pub fn CreateAcceleratorTableW();
    pub fn CreateCaret(hWnd: HWND, hBitmap: HBITMAP, nWidth: c_int, nHeight: c_int) -> BOOL;
    pub fn CreateCursor(
        hInst: HINSTANCE, xHotSpot: c_int, yHotSpot: c_int, nWidth: c_int, nHeight: c_int,
        pvAndPlane: *const VOID, pvXORPlane: *const VOID,
    ) -> HCURSOR;
    // pub fn CreateDesktopA();
    // pub fn CreateDesktopExA();
    // pub fn CreateDesktopExW();
    // pub fn CreateDesktopW();
    // pub fn CreateDialogIndirectParamA();
    // pub fn CreateDialogIndirectParamW();
    // pub fn CreateDialogParamA();
    // pub fn CreateDialogParamW();
    // pub fn CreateIcon();
    // pub fn CreateIconFromResource();
    // pub fn CreateIconFromResourceEx();
    // pub fn CreateIconIndirect();
    // pub fn CreateMDIWindowA();
    // pub fn CreateMDIWindowW();
    // pub fn CreateMenu();
    // pub fn CreatePopupMenu();
    // pub fn CreateWindowExA();
    pub fn CreateWindowExW(
        dwExStyle: DWORD, lpClassName: LPCWSTR, lpWindowName: LPCWSTR, dwStyle: DWORD, x: c_int,
        y: c_int, nWidth: c_int, nHeight: c_int, hWndParent: HWND, hMenu: HMENU,
        hInstance: HINSTANCE, lpParam: LPVOID,
    ) -> HWND;
    // pub fn CreateWindowStationA();
    // pub fn CreateWindowStationW();
    // pub fn DdeAbandonTransaction();
    // pub fn DdeAccessData();
    // pub fn DdeAddData();
    // pub fn DdeClientTransaction();
    // pub fn DdeCmpStringHandles();
    // pub fn DdeConnect();
    // pub fn DdeConnectList();
    // pub fn DdeCreateDataHandle();
    // pub fn DdeCreateStringHandleA();
    // pub fn DdeCreateStringHandleW();
    // pub fn DdeDisconnect();
    // pub fn DdeDisconnectList();
    // pub fn DdeEnableCallback();
    // pub fn DdeFreeDataHandle();
    // pub fn DdeFreeStringHandle();
    // pub fn DdeGetData();
    // pub fn DdeGetLastError();
    // pub fn DdeImpersonateClient();
    // pub fn DdeInitializeA();
    // pub fn DdeInitializeW();
    // pub fn DdeKeepStringHandle();
    // pub fn DdeNameService();
    // pub fn DdePostAdvise();
    // pub fn DdeQueryConvInfo();
    // pub fn DdeQueryNextServer();
    // pub fn DdeQueryStringA();
    // pub fn DdeQueryStringW();
    // pub fn DdeReconnect();
    // pub fn DdeSetQualityOfService();
    // pub fn DdeSetUserHandle();
    // pub fn DdeUnaccessData();
    // pub fn DdeUninitialize();
    // pub fn DefDlgProcA();
    // pub fn DefDlgProcW();
    // pub fn DefFrameProcA();
    // pub fn DefFrameProcW();
    // pub fn DefMDIChildProcA();
    // pub fn DefMDIChildProcW();
    // pub fn DefRawInputProc();
    // pub fn DefWindowProcA();
    pub fn DefWindowProcW(hWnd: HWND, Msg: UINT, wParam: WPARAM, lParam: LPARAM) -> LRESULT;
    // pub fn DeferWindowPos();
    pub fn DeleteMenu(hMenu: HMENU, uPosition: UINT, uFlags: UINT) -> BOOL;
    // pub fn DeregisterShellHookWindow();
    pub fn DestroyAcceleratorTable(hAccel: HACCEL) -> BOOL;
    pub fn DestroyCaret() -> BOOL;
    pub fn DestroyCursor(hCursor: HCURSOR) -> BOOL;
    pub fn DestroyIcon(hIcon: HICON) -> BOOL;
    pub fn DestroyMenu(hMenu: HMENU) -> HMENU;
    pub fn DestroyWindow(hWnd: HWND) -> BOOL;
    // pub fn DialogBoxIndirectParamA();
    // pub fn DialogBoxIndirectParamW();
    // pub fn DialogBoxParamA();
    // pub fn DialogBoxParamW();
    // pub fn DisableProcessWindowsGhosting();
    // pub fn DispatchMessageA();
    pub fn DispatchMessageW(lpmsg: *const MSG) -> LRESULT;
    // pub fn DisplayConfigGetDeviceInfo();
    // pub fn DisplayConfigSetDeviceInfo();
    // pub fn DlgDirListA();
    // pub fn DlgDirListComboBoxA();
    // pub fn DlgDirListComboBoxW();
    // pub fn DlgDirListW();
    // pub fn DlgDirSelectComboBoxExA();
    // pub fn DlgDirSelectComboBoxExW();
    // pub fn DlgDirSelectExA();
    // pub fn DlgDirSelectExW();
    // pub fn DragDetect();
    // pub fn DragObject();
    // pub fn DrawAnimatedRects();
    // pub fn DrawCaption();
    // pub fn DrawEdge();
    // pub fn DrawFocusRect();
    // pub fn DrawFrame();
    // pub fn DrawFrameControl();
    // pub fn DrawIcon();
    // pub fn DrawIconEx();
    // pub fn DrawMenuBar();
    // pub fn DrawStateA();
    // pub fn DrawStateW();
    // pub fn DrawTextA();
    // pub fn DrawTextExA();
    // pub fn DrawTextExW();
    // pub fn DrawTextW();
    // pub fn EditWndProc();
    pub fn EmptyClipboard() -> BOOL;
    // pub fn EnableMenuItem();
    // pub fn EnableMouseInPointer();
    pub fn EnableScrollBar(hWnd: HWND, wSBflags: UINT, wArrows: UINT) -> BOOL;
    // pub fn EnableSessionForMMCSS();
    pub fn EnableWindow(hWnd: HWND, bEnable: BOOL) -> BOOL;
    // pub fn EndDeferWindowPos();
    // pub fn EndDialog();
    // pub fn EndMenu();
    pub fn EndPaint(hWnd: HWND, lpPaint: *const PAINTSTRUCT) -> BOOL;
    // pub fn EndTask();
    // pub fn EnumChildWindows();
    pub fn EnumClipboardFormats(format: UINT) -> UINT;
    // pub fn EnumDesktopWindows();
    // pub fn EnumDesktopsA();
    // pub fn EnumDesktopsW();
    // pub fn EnumDisplayDevicesA();
    pub fn EnumDisplayDevicesW(
        lpDevice: LPCWSTR, iDevNum: DWORD, lpDisplayDevice: PDISPLAY_DEVICEW, dwFlags: DWORD,
    ) -> BOOL;
    // pub fn EnumDisplayMonitors();
    // pub fn EnumDisplaySettingsA();
    // pub fn EnumDisplaySettingsExA();
    pub fn EnumDisplaySettingsExW(
        lpszDeviceName: LPCWSTR, iModeNum: DWORD, lpDevMode: *mut DEVMODEW, dwFlags: DWORD,
    ) -> BOOL;
    // pub fn EnumDisplaySettingsW();
    // pub fn EnumPropsA();
    // pub fn EnumPropsExA();
    // pub fn EnumPropsExW();
    // pub fn EnumPropsW();
    // pub fn EnumThreadWindows();
    // pub fn EnumWindowStationsA();
    // pub fn EnumWindowStationsW();
    // pub fn EnumWindows();
    // pub fn EqualRect();
    // pub fn EvaluateProximityToPolygon();
    // pub fn EvaluateProximityToRect();
    // pub fn ExcludeUpdateRgn();
    // pub fn ExitWindowsEx();
    pub fn FillRect(hDC: HDC, lprc: *const RECT, hbr: HBRUSH) -> c_int;
    pub fn FindWindowA (lpClassName: LPCSTR, lpWindowName: LPCSTR) -> HWND;
    // pub fn FindWindowExA();
    // pub fn FindWindowExW();
    // pub fn FindWindowW();
    // pub fn FlashWindow();
    // pub fn FlashWindowEx();
    // pub fn FrameRect();
    // pub fn FreeDDElParam();
    pub fn GetActiveWindow() -> HWND;
    // pub fn GetAltTabInfo();
    // pub fn GetAltTabInfoA();
    // pub fn GetAltTabInfoW();
    // pub fn GetAncestor();
    pub fn GetAsyncKeyState(vKey: c_int) -> SHORT;
    // pub fn GetAutoRotationState();
    // pub fn GetCIMSSM();
    // pub fn GetCapture();
    pub fn GetCaretBlinkTime() -> UINT;
    pub fn GetCaretPos(lpPoint: LPPOINT) -> BOOL;
    // pub fn GetClassInfoA();
    // pub fn GetClassInfoExA();
    pub fn GetClassInfoExW(
        hinst: HINSTANCE, lpszClass: LPCWSTR, lpwcx: LPWNDCLASSEXW
    ) -> BOOL;
    // pub fn GetClassInfoW();
    // pub fn GetClassLongA();
    // #[cfg(target_arch = "x86_64")]
    // pub fn GetClassLongPtrA();
    // #[cfg(target_arch = "x86_64")]
    // pub fn GetClassLongPtrW();
    pub fn GetClassLongW(hWnd: HWND, nIndex: c_int) -> DWORD;
    // pub fn GetClassNameA();
    // pub fn GetClassNameW();
    pub fn GetClassWord(hWnd: HWND, nIndex: c_int) -> WORD;
    pub fn GetClientRect(hWnd: HWND, lpRect: LPRECT) -> BOOL;
    pub fn GetClipCursor(lpRect: LPRECT) -> BOOL;
    pub fn GetClipboardData(uFormat: UINT) -> HANDLE;
    // pub fn GetClipboardFormatNameA();
    // pub fn GetClipboardFormatNameW();
    pub fn GetClipboardOwner() -> HWND;
    // pub fn GetClipboardSequenceNumber();
    pub fn GetClipboardViewer() -> HWND;
    // pub fn GetComboBoxInfo();
    // pub fn GetCurrentInputMessageSource();
    pub fn GetCursor() -> HCURSOR;
    // pub fn GetCursorInfo();
    pub fn GetCursorPos(lpPoint: LPPOINT) -> BOOL;
    pub fn GetDC(hWnd: HWND) -> HDC;
    // pub fn GetDCEx();
    // pub fn GetDesktopWindow();
    // pub fn GetDialogBaseUnits();
    // pub fn GetDisplayAutoRotationPreferences();
    // pub fn GetDisplayConfigBufferSizes();
    // pub fn GetDlgCtrlID();
    // pub fn GetDlgItem();
    // pub fn GetDlgItemInt();
    // pub fn GetDlgItemTextA();
    // pub fn GetDlgItemTextW();
    // pub fn GetDoubleClickTime();
    pub fn GetFocus() -> HWND;
    pub fn GetForegroundWindow() -> HWND;
    // pub fn GetGUIThreadInfo();
    // pub fn GetGestureConfig();
    // pub fn GetGestureExtraArgs();
    // pub fn GetGestureInfo();
    // pub fn GetGuiResources();
    // pub fn GetIconInfo();
    // pub fn GetIconInfoExA();
    // pub fn GetIconInfoExW();
    // pub fn GetInputDesktop();
    // pub fn GetInputLocaleInfo();
    // pub fn GetInputState();
    pub fn GetKBCodePage() -> UINT;
    pub fn GetKeyNameTextA(lparam: LONG, lpString: LPSTR, cchSize: c_int) -> c_int;
    pub fn GetKeyNameTextW(lParam: LONG, lpString: LPWSTR, cchSize: c_int) -> c_int;
    pub fn GetKeyState(nVirtKey: c_int) -> SHORT;
    pub fn GetKeyboardLayout(idThread: DWORD) -> HKL;
    pub fn GetKeyboardLayoutList(nBuff: c_int, lpList: *mut HKL) -> c_int;
    pub fn GetKeyboardLayoutNameA(pwszKLID: LPSTR) -> BOOL;
    pub fn GetKeyboardLayoutNameW(pwszKLID: LPWSTR) -> BOOL;
    pub fn GetKeyboardState(lpKeyState: PBYTE) -> BOOL;
    pub fn GetKeyboardType(nTypeFlag: c_int) -> c_int;
    // pub fn GetLastActivePopup();
    // pub fn GetLastInputInfo();
    // pub fn GetLayeredWindowAttributes();
    // pub fn GetListBoxInfo();
    // pub fn GetMenu();
    // pub fn GetMenuBarInfo();
    // pub fn GetMenuCheckMarkDimensions();
    // pub fn GetMenuContextHelpId();
    // pub fn GetMenuDefaultItem();
    // pub fn GetMenuInfo();
    // pub fn GetMenuItemCount();
    // pub fn GetMenuItemID();
    // pub fn GetMenuItemInfoA();
    // pub fn GetMenuItemInfoW();
    // pub fn GetMenuItemRect();
    // pub fn GetMenuState();
    // pub fn GetMenuStringA();
    // pub fn GetMenuStringW();
    // pub fn GetMessageA();
    // pub fn GetMessageExtraInfo();
    // pub fn GetMessagePos();
    // pub fn GetMessageTime();
    pub fn GetMessageW(lpMsg: LPMSG, hWnd: HWND, wMsgFilterMin: UINT, wMsgFilterMax: UINT) -> BOOL;
    // pub fn GetMonitorInfoA();
    // pub fn GetMonitorInfoW();
    // pub fn GetMouseMovePointsEx();
    // pub fn GetNextDlgGroupItem();
    // pub fn GetNextDlgTabItem();
    pub fn GetOpenClipboardWindow() -> HWND;
    // pub fn GetParent();
    pub fn GetPhysicalCursorPos(lpPoint: LPPOINT) -> BOOL;
    // pub fn GetPointerCursorId();
    // pub fn GetPointerDevice();
    // pub fn GetPointerDeviceCursors();
    // pub fn GetPointerDeviceProperties();
    // pub fn GetPointerDeviceRects();
    // pub fn GetPointerDevices();
    // pub fn GetPointerFrameInfo();
    // pub fn GetPointerFrameInfoHistory();
    // pub fn GetPointerFramePenInfo();
    // pub fn GetPointerFramePenInfoHistory();
    // pub fn GetPointerFrameTouchInfo();
    // pub fn GetPointerFrameTouchInfoHistory();
    // pub fn GetPointerInfo();
    // pub fn GetPointerInfoHistory();
    // pub fn GetPointerInputTransform();
    // pub fn GetPointerPenInfo();
    // pub fn GetPointerPenInfoHistory();
    // pub fn GetPointerTouchInfo();
    // pub fn GetPointerTouchInfoHistory();
    // pub fn GetPointerType();
    // pub fn GetPriorityClipboardFormat();
    // pub fn GetProcessDefaultLayout();
    // pub fn GetProcessWindowStation();
    // pub fn GetPropA();
    // pub fn GetPropW();
    // pub fn GetQueueStatus();
    // pub fn GetRawInputBuffer();
    // pub fn GetRawInputData();
    // pub fn GetRawInputDeviceInfoA();
    // pub fn GetRawInputDeviceInfoW();
    // pub fn GetRawInputDeviceList();
    // pub fn GetRawPointerDeviceData();
    // pub fn GetRegisteredRawInputDevices();
    // pub fn GetScrollBarInfo();
    // pub fn GetScrollInfo();
    pub fn GetScrollPos(hWnd: HWND, nBar: c_int) -> c_int;
    pub fn GetScrollRange(hWnd: HWND, nBar: c_int, lpMinPos: LPINT, lpMaxPos: LPINT) -> BOOL;
    // pub fn GetShellWindow();
    // pub fn GetSubMenu();
    pub fn GetSysColor(nIndex: c_int) -> DWORD;
    // pub fn GetSysColorBrush();
    // pub fn GetSystemMenu();
    pub fn GetSystemMetrics(nIndex: c_int) -> c_int;
    // pub fn GetTabbedTextExtentA();
    // pub fn GetTabbedTextExtentW();
    // pub fn GetThreadDesktop();
    // pub fn GetTitleBarInfo();
    // pub fn GetTopWindow();
    // pub fn GetTouchInputInfo();
    // pub fn GetUnpredictedMessagePos();
    // pub fn GetUpdateRect();
    // pub fn GetUpdateRgn();
    // pub fn GetUpdatedClipboardFormats();
    // pub fn GetUserObjectInformationA();
    // pub fn GetUserObjectInformationW();
    // pub fn GetUserObjectSecurity();
    // pub fn GetWindow();
    // pub fn GetWindowContextHelpId();
    // pub fn GetWindowDC();
    // pub fn GetWindowDisplayAffinity();
    // pub fn GetWindowFeedbackSetting();
    // pub fn GetWindowInfo();
    // pub fn GetWindowLongA();
    // #[cfg(target_arch = "x86_64")]
    // pub fn GetWindowLongPtrA();
    // #[cfg(target_arch = "x86_64")]
    // pub fn GetWindowLongPtrW();
    // pub fn GetWindowLongW();
    // pub fn GetWindowModuleFileName();
    // pub fn GetWindowModuleFileNameA();
    // pub fn GetWindowModuleFileNameW();
    pub fn GetWindowPlacement(hWnd: HWND, lpwndpl: *mut WINDOWPLACEMENT) -> BOOL;
    pub fn GetWindowRect(hWnd: HWND, lpRect: LPRECT) -> BOOL;
    // pub fn GetWindowRgn();
    // pub fn GetWindowRgnBox();
    // pub fn GetWindowTextA();
    // pub fn GetWindowTextLengthA();
    // pub fn GetWindowTextLengthW();
    // pub fn GetWindowTextW();
    // pub fn GetWindowThreadProcessId();
    // pub fn GetWindowWord();
    // pub fn GrayStringA();
    // pub fn GrayStringW();
    pub fn HideCaret(hWnd: HWND) -> BOOL;
    // pub fn HiliteMenuItem();
    // pub fn IMPGetIMEA();
    // pub fn IMPGetIMEW();
    // pub fn IMPQueryIMEA();
    // pub fn IMPQueryIMEW();
    // pub fn IMPSetIMEA();
    // pub fn IMPSetIMEW();
    // pub fn ImpersonateDdeClientWindow();
    // pub fn InSendMessage();
    // pub fn InSendMessageEx();
    // pub fn InflateRect();
    // pub fn InitializeTouchInjection();
    // pub fn InjectTouchInput();
    // pub fn InsertMenuA();
    // pub fn InsertMenuItemA();
    // pub fn InsertMenuItemW();
    // pub fn InsertMenuW();
    // pub fn InternalGetWindowText();
    // pub fn IntersectRect();
    pub fn InvalidateRect(hWnd: HWND, lpRect: *const RECT, bErase: BOOL) -> BOOL;
    // pub fn InvalidateRgn();
    // pub fn InvertRect();
    // pub fn IsCharAlphaA();
    // pub fn IsCharAlphaNumericA();
    // pub fn IsCharAlphaNumericW();
    // pub fn IsCharAlphaW();
    // pub fn IsCharLowerA();
    // pub fn IsCharLowerW();
    // pub fn IsCharUpperA();
    // pub fn IsCharUpperW();
    // pub fn IsChild();
    pub fn IsClipboardFormatAvailable(format: UINT) -> BOOL;
    // pub fn IsDialogMessage();
    // pub fn IsDialogMessageA();
    // pub fn IsDialogMessageW();
    // pub fn IsDlgButtonChecked();
    // pub fn IsGUIThread();
    // pub fn IsHungAppWindow();
    // pub fn IsIconic();
    // pub fn IsImmersiveProcess();
    // pub fn IsInDesktopWindowBand();
    // pub fn IsMenu();
    // pub fn IsMouseInPointerEnabled();
    // pub fn IsProcessDPIAware();
    // pub fn IsRectEmpty();
    // pub fn IsTouchWindow();
    // pub fn IsWinEventHookInstalled();
    // pub fn IsWindow();
    pub fn IsWindowEnabled(hWnd: HWND) -> BOOL;
    // pub fn IsWindowUnicode();
    // pub fn IsWindowVisible();
    // pub fn IsWow64Message();
    // pub fn IsZoomed();
    // pub fn KillTimer();
    // pub fn LoadAcceleratorsA();
    // pub fn LoadAcceleratorsW();
    // pub fn LoadBitmapA();
    // pub fn LoadBitmapW();
    // pub fn LoadCursorA();
    // pub fn LoadCursorFromFileA();
    pub fn LoadCursorFromFileW(lpFileName: LPCWSTR) -> HCURSOR;
    pub fn LoadCursorW(hInstance: HINSTANCE, lpCursorName: LPCWSTR) -> HCURSOR;
    // pub fn LoadIconA();
    // pub fn LoadIconW();
    pub fn LoadImageA(
        hInst: HINSTANCE, name: LPCSTR, type_: UINT, cx: c_int, cy: c_int, fuLoad: UINT,
    ) -> HANDLE;
    pub fn LoadImageW(
        hInst: HINSTANCE, name: LPCWSTR, type_: UINT, cx: c_int, cy: c_int, fuLoad: UINT,
    ) -> HANDLE;
    // pub fn LoadKeyboardLayoutA();
    // pub fn LoadKeyboardLayoutW();
    // pub fn LoadMenuA();
    // pub fn LoadMenuIndirectA();
    // pub fn LoadMenuIndirectW();
    // pub fn LoadMenuW();
    // pub fn LoadStringA();
    // pub fn LoadStringW();
    // pub fn LockSetForegroundWindow();
    // pub fn LockWindowUpdate();
    // pub fn LockWorkStation();
    // pub fn LogicalToPhysicalPoint();
    // pub fn LogicalToPhysicalPointForPerMonitorDPI();
    // pub fn LookupIconIdFromDirectory();
    // pub fn LookupIconIdFromDirectoryEx();
    // pub fn MapDialogRect();
    // pub fn MapVirtualKeyA();
    // pub fn MapVirtualKeyExA();
    // pub fn MapVirtualKeyExW();
    // pub fn MapVirtualKeyW();
    // pub fn MapWindowPoints();
    // pub fn MenuItemFromPoint();
    // pub fn MessageBeep();
    pub fn MessageBoxA(hWnd: HWND, lpText: LPCSTR, lpCaption: LPCSTR, uType: UINT) -> c_int;
    pub fn MessageBoxExA(
        hWnd: HWND, lpText: LPCSTR, lpCaption: LPCSTR, uType: UINT, wLanguageId: WORD,
    ) -> c_int;
    pub fn MessageBoxExW(
        hWnd: HWND, lpText: LPCWSTR, lpCaption: LPCWSTR, uType: UINT, wLanguageId: WORD,
    ) -> c_int;
    // pub fn MessageBoxIndirectA();
    // pub fn MessageBoxIndirectW();
    // pub fn MessageBoxTimeoutA();
    // pub fn MessageBoxTimeoutW();
    pub fn MessageBoxW(hWnd: HWND, lpText: LPCWSTR, lpCaption: LPCWSTR, uType: UINT) -> c_int;
    // pub fn ModifyMenuA();
    // pub fn ModifyMenuW();
    // pub fn MonitorFromPoint();
    // pub fn MonitorFromRect();
    // pub fn MonitorFromWindow();
    // pub fn MoveWindow();
    // pub fn MsgWaitForMultipleObjects();
    // pub fn MsgWaitForMultipleObjectsEx();
    // pub fn NotifyWinEvent();
    // pub fn OemKeyScan();
    // pub fn OemToCharA();
    // pub fn OemToCharBuffA();
    // pub fn OemToCharBuffW();
    // pub fn OemToCharW();
    // pub fn OffsetRect();
    pub fn OpenClipboard(hWnd: HWND) -> BOOL;
    // pub fn OpenDesktopA();
    // pub fn OpenDesktopW();
    // pub fn OpenIcon();
    // pub fn OpenInputDesktop();
    // pub fn OpenWindowStationA();
    // pub fn OpenWindowStationW();
    // pub fn PackDDElParam();
    // pub fn PackTouchHitTestingProximityEvaluation();
    // pub fn PaintDesktop();
    // pub fn PeekMessageA();
    pub fn PeekMessageW(
        lpMsg: LPMSG, hWnd: HWND, wMsgFilterMin: UINT, wMsgFilterMax: UINT, wRemoveMsg: UINT,
    ) -> BOOL;
    // pub fn PhysicalToLogicalPoint();
    // pub fn PhysicalToLogicalPointForPerMonitorDPI();
    // pub fn PostMessageA();
    pub fn PostMessageW(hWnd: HWND, Msg: UINT, wParam: WPARAM, lParam: LPARAM) -> BOOL;
    pub fn PostQuitMessage(nExitCode: c_int);
    // pub fn PostThreadMessageA();
    // pub fn PostThreadMessageW();
    // pub fn PrintWindow();
    // pub fn PrivateExtractIconsA();
    // pub fn PrivateExtractIconsW();
    // pub fn PtInRect();
    // pub fn QueryDisplayConfig();
    // pub fn RealChildWindowFromPoint();
    // pub fn RealGetWindowClass();
    // pub fn RealGetWindowClassA();
    // pub fn RealGetWindowClassW();
    // pub fn RedrawWindow();
    // pub fn RegisterClassA();
    // pub fn RegisterClassExA();
    pub fn RegisterClassExW(lpWndClass: *const WNDCLASSEXW) -> ATOM;
    // pub fn RegisterClassW();
    // pub fn RegisterClipboardFormatA();
    // pub fn RegisterClipboardFormatW();
    // pub fn RegisterDeviceNotificationA();
    // pub fn RegisterDeviceNotificationW();
    // pub fn RegisterHotKey();
    // pub fn RegisterPointerDeviceNotifications();
    // pub fn RegisterPointerInputTarget();
    // pub fn RegisterPowerSettingNotification();
    // pub fn RegisterRawInputDevices();
    // pub fn RegisterShellHookWindow();
    // pub fn RegisterSuspendResumeNotification();
    // pub fn RegisterTouchHitTestingWindow();
    // pub fn RegisterTouchWindow();
    // pub fn RegisterWindowMessageA();
    // pub fn RegisterWindowMessageW();
    // pub fn ReleaseCapture();
    // pub fn ReleaseDC();
    // pub fn RemoveClipboardFormatListener();
    // pub fn RemoveMenu();
    // pub fn RemovePropA();
    // pub fn RemovePropW();
    // pub fn ReplyMessage();
    // pub fn ReuseDDElParam();
    // pub fn ScreenToClient();
    pub fn ScrollDC(
        hDC: HDC, dx: c_int, dy: c_int, lprcScroll: *const RECT, lprcClip: *const RECT,
        hrgnUpdate: HRGN, lprcUpdate: LPRECT
    ) -> BOOL;
    pub fn ScrollWindow(
        hWnd: HWND, xAmount: c_int, yAmount: c_int, lpRect: *const RECT, lpClipRect: *const RECT
    ) -> BOOL;
    pub fn ScrollWindowEx(
        hWnd: HWND, dx: c_int, dy: c_int, prcScroll: *const RECT, prcClip *const RECT,
        hrgnUpdate: HRGN, prcUpdate: LPRECT, flags: UINT
    ) -> c_int;
    // pub fn SendDlgItemMessageA();
    // pub fn SendDlgItemMessageW();
    // pub fn SendIMEMessageExA();
    // pub fn SendIMEMessageExW();
    pub fn SendInput(cInputs: UINT, pInputs: LPINPUT, cbSize: c_int) -> UINT;
    pub fn SendMessageA(hWnd: HWND, Msg: UINT, wParam: WPARAM, lParam: LPARAM) -> LRESULT;
    // pub fn SendMessageCallbackA();
    // pub fn SendMessageCallbackW();
    // pub fn SendMessageTimeoutA();
    // pub fn SendMessageTimeoutW();
    pub fn SendMessageW(hWnd: HWND, Msg: UINT, wParam: WPARAM, lParam: LPARAM) -> LRESULT;
    // pub fn SendNotifyMessageA();
    // pub fn SendNotifyMessageW();
    pub fn SetActiveWindow(hWnd: HWND) -> HWND;
    // pub fn SetCapture();
    pub fn SetCaretBlinkTime(uMSeconds: UINT) -> BOOL;
    pub fn SetCaretPos(x: c_int, y: c_int) -> BOOL;
    // pub fn SetClassLongA();
    // #[cfg(target_arch = "x86_64")]
    // pub fn SetClassLongPtrA();
    // #[cfg(target_arch = "x86_64")]
    // pub fn SetClassLongPtrW();
    pub fn SetClassLongW(hWnd: HWND, nIndex: c_int, dwNewLong: LONG) -> DWORD;
    // pub fn SetClassWord();
    // pub fn SetClipboardData();
    pub fn SetClipboardViewer(hWndNewViewer: HWND) -> HWND;
    // pub fn SetCoalescableTimer();
    pub fn SetCursor(hCursor: HCURSOR) -> HCURSOR;
    pub fn SetCursorPos(x: c_int, y: c_int) -> BOOL;
    // pub fn SetDebugErrorLevel();
    // pub fn SetDeskWallpaper();
    // pub fn SetDisplayAutoRotationPreferences();
    // pub fn SetDisplayConfig();
    // pub fn SetDlgItemInt();
    // pub fn SetDlgItemTextA();
    // pub fn SetDlgItemTextW();
    // pub fn SetDoubleClickTime();
    pub fn SetFocus(hWnd: HWND) -> HWND;
    pub fn SetForegroundWindow(hWnd: HWND) -> BOOL;
    // pub fn SetGestureConfig();
    // pub fn SetKeyboardState();
    // pub fn SetLastErrorEx();
    // pub fn SetLayeredWindowAttributes();
    // pub fn SetMenu();
    // pub fn SetMenuContextHelpId();
    // pub fn SetMenuDefaultItem();
    // pub fn SetMenuInfo();
    // pub fn SetMenuItemBitmaps();
    // pub fn SetMenuItemInfoA();
    // pub fn SetMenuItemInfoW();
    // pub fn SetMessageExtraInfo();
    // pub fn SetMessageQueue();
    // pub fn SetParent();
    pub fn SetPhysicalCursorPos(x: c_int, y: c_int) -> BOOL;
    // pub fn SetProcessDPIAware();
    // pub fn SetProcessDefaultLayout();
    // pub fn SetProcessRestrictionExemption();
    // pub fn SetProcessWindowStation();
    // pub fn SetPropA();
    // pub fn SetPropW();
    // pub fn SetRect();
    // pub fn SetRectEmpty();
    // pub fn SetScrollInfo();
    pub fn SetScrollPos(hWnd: HWND, nBar: c_int, nPos: c_int, bRedraw: BOOl) -> c_int;
    pub fn SetScrollRange(
        hWnd HWND, nBar: c_int, nMinPos: c_int, nMaxPos: c_int, bRedraw: BOOL) -> BOOL;
    // pub fn SetShellWindow();
    // pub fn SetSysColors();
    pub fn SetSystemCursor(hcur: HCURSOR, id: DWORD) -> BOOL;
    // pub fn SetThreadDesktop();
    // pub fn SetTimer();
    // pub fn SetUserObjectInformationA();
    // pub fn SetUserObjectInformationW();
    // pub fn SetUserObjectSecurity();
    // pub fn SetWinEventHook();
    // pub fn SetWindowContextHelpId();
    // pub fn SetWindowDisplayAffinity();
    // pub fn SetWindowFeedbackSetting();
    // pub fn SetWindowLongA();
    // #[cfg(target_arch = "x86_64")]
    // pub fn SetWindowLongPtrA();
    // #[cfg(target_arch = "x86_64")]
    // pub fn SetWindowLongPtrW();
    // pub fn SetWindowLongW();
    // pub fn SetWindowPlacement();
    pub fn SetWindowPos(
        hWnd: HWND, hWndInsertAfter: HWND, X: c_int, Y: c_int, cx: c_int, cy: c_int, uFlags: UINT,
    ) -> BOOL;
    // pub fn SetWindowRgn();
    // pub fn SetWindowTextA();
    pub fn SetWindowTextW(hWnd: HWND, lpString: LPCWSTR) -> BOOL;
    // pub fn SetWindowWord();
    // pub fn SetWindowsHookA();
    // pub fn SetWindowsHookExA();
    // pub fn SetWindowsHookExW();
    // pub fn SetWindowsHookW();
    pub fn ShowCaret(hWnd: HWND) -> BOOL;
    pub fn ShowCursor(bShow: BOOL) -> c_int;
    // pub fn ShowOwnedPopups();
    // pub fn ShowScrollBar();
    // pub fn ShowSystemCursor();
    pub fn ShowWindow(hWnd: HWND, nCmdShow: c_int) -> BOOL;
    pub fn ShowWindowAsync(hWnd: HWND, nCmdShow: c_int) -> BOOL;
    // pub fn ShutdownBlockReasonCreate();
    // pub fn ShutdownBlockReasonDestroy();
    // pub fn ShutdownBlockReasonQuery();
    // pub fn SkipPointerFrameMessages();
    // pub fn SoundSentry();
    // pub fn SubtractRect();
    // pub fn SwapMouseButton();
    // pub fn SwitchDesktop();
    // pub fn SwitchToThisWindow();
    // pub fn SystemParametersInfoA();
    // pub fn SystemParametersInfoW();
    // pub fn TabbedTextOutA();
    // pub fn TabbedTextOutW();
    // pub fn TileChildWindows();
    // pub fn TileWindows();
    // pub fn ToAscii();
    // pub fn ToAsciiEx();
    // pub fn ToUnicode();
    // pub fn ToUnicodeEx();
    // pub fn TrackMouseEvent();
    // pub fn TrackPopupMenu();
    // pub fn TrackPopupMenuEx();
    // pub fn TranslateAccelerator();
    // pub fn TranslateAcceleratorA();
    // pub fn TranslateAcceleratorW();
    // pub fn TranslateMDISysAccel();
    pub fn TranslateMessage(lpmsg: *const MSG) -> BOOL;
    // pub fn UnhookWinEvent();
    // pub fn UnhookWindowsHook();
    // pub fn UnhookWindowsHookEx();
    // pub fn UnionRect();
    // pub fn UnloadKeyboardLayout();
    // pub fn UnpackDDElParam();
    // pub fn UnregisterClassA();
    // pub fn UnregisterClassW();
    // pub fn UnregisterDeviceNotification();
    // pub fn UnregisterHotKey();
    // pub fn UnregisterPointerInputTarget();
    // pub fn UnregisterPowerSettingNotification();
    // pub fn UnregisterSuspendResumeNotification();
    // pub fn UnregisterTouchWindow();
    // pub fn UpdateLayeredWindow();
    // pub fn UpdateLayeredWindowIndirect();
    pub fn UpdateWindow(hWnd: HWND) -> BOOL;
    // pub fn UserHandleGrantAccess();
    // pub fn ValidateRect();
    // pub fn ValidateRgn();
    // pub fn VkKeyScanA();
    // pub fn VkKeyScanExA();
    // pub fn VkKeyScanExW();
    // pub fn VkKeyScanW();
    // pub fn WINNLSEnableIME();
    // pub fn WINNLSGetEnableStatus();
    // pub fn WINNLSGetIMEHotkey();
    // pub fn WaitForInputIdle();
    pub fn WaitMessage() -> BOOL;
    // pub fn WinHelpA();
    // pub fn WinHelpW();
    // pub fn WindowFromDC();
    // pub fn WindowFromPhysicalPoint();
    // pub fn WindowFromPoint();
    // pub fn keybd_event();
    // pub fn mouse_event();
    // pub fn wsprintfA();
    // pub fn wsprintfW();
    // pub fn wvsprintfA();
    // pub fn wvsprintfW();
}
