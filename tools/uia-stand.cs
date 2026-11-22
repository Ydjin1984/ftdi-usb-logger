using System;
using System.Runtime.InteropServices;

// Нативный Win32-стенд для проверки регистрации кнопок чтения и записи.
// Кнопки — настоящий класс BUTTON (как в Delphi/VCL), а не WinForms: у WinForms
// события фокуса через MSAA-мост не приходят, и проверять на нём нечего.
internal static class Stand
{
    private const int WS_OVERLAPPEDWINDOW = 0x00CF0000;
    private const int WS_CHILD = 0x40000000;
    private const int WS_VISIBLE = 0x10000000;
    private const int WS_TABSTOP = 0x00010000;
    private const int BS_PUSHBUTTON = 0x00000000;
    private const int CW_USEDEFAULT = unchecked((int)0x80000000);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WNDCLASSEX
    {
        public int cbSize;
        public int style;
        public IntPtr lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public IntPtr hInstance;
        public IntPtr hIcon;
        public IntPtr hCursor;
        public IntPtr hbrBackground;
        public string lpszMenuName;
        public string lpszClassName;
        public IntPtr hIconSm;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MSG
    {
        public IntPtr hwnd;
        public uint message;
        public IntPtr wParam;
        public IntPtr lParam;
        public uint time;
        public int ptX;
        public int ptY;
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ushort RegisterClassEx(ref WNDCLASSEX cls);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateWindowEx(int exStyle, string className, string title,
        int style, int x, int y, int width, int height, IntPtr parent, IntPtr menu, IntPtr instance, IntPtr param);

    [DllImport("user32.dll")]
    private static extern IntPtr DefWindowProc(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    private static extern bool GetMessage(out MSG msg, IntPtr hwnd, uint min, uint max);

    [DllImport("user32.dll")]
    private static extern bool TranslateMessage(ref MSG msg);

    [DllImport("user32.dll")]
    private static extern IntPtr DispatchMessage(ref MSG msg);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandle(string name);

    private static IntPtr WndProc(IntPtr hwnd, uint msg, IntPtr wp, IntPtr lp)
    {
        if (msg == 0x0002) Environment.Exit(0); // WM_DESTROY
        return DefWindowProc(hwnd, msg, wp, lp);
    }

    [STAThread]
    private static void Main()
    {
        IntPtr instance = GetModuleHandle(null);
        var cls = new WNDCLASSEX();
        cls.cbSize = Marshal.SizeOf(typeof(WNDCLASSEX));
        cls.lpfnWndProc = Marshal.GetFunctionPointerForDelegate(KeepAlive);
        cls.hInstance = instance;
        cls.lpszClassName = "UiaStandWindow";
        ushort atom = RegisterClassEx(ref cls);
        if (atom == 0) { Console.WriteLine("RegisterClassEx failed: " + Marshal.GetLastWin32Error()); return; }

        IntPtr window = CreateWindowEx(0, "UiaStandWindow", "UIA Simulator Stand",
            WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 420, 180,
            IntPtr.Zero, IntPtr.Zero, instance, IntPtr.Zero);

        CreateWindowEx(0, "BUTTON", "\u0427\u0442\u0435\u043d\u0438\u0435",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 30, 40, 150, 34,
            window, IntPtr.Zero, instance, IntPtr.Zero);
        CreateWindowEx(0, "BUTTON", "\u0417\u0430\u043f\u0438\u0441\u044c",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 220, 40, 150, 34,
            window, IntPtr.Zero, instance, IntPtr.Zero);
        CreateWindowEx(0, "STATIC", "simulator: read / write buttons",
            WS_CHILD | WS_VISIBLE, 30, 100, 350, 24, window, IntPtr.Zero, instance, IntPtr.Zero);

        if (window == IntPtr.Zero) { Console.WriteLine("CreateWindowEx failed: " + Marshal.GetLastWin32Error()); return; }
        Console.WriteLine("window=" + window); Console.Out.Flush();
        MSG msg;
        while (GetMessage(out msg, IntPtr.Zero, 0, 0))
        {
            TranslateMessage(ref msg);
            DispatchMessage(ref msg);
        }
    }

    private delegate IntPtr WndProcDelegate(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);
    // Делегат обязан жить всё время работы окна, иначе GC освободит его и
    // DefWindowProc упадёт на первом же сообщении.
    private static readonly WndProcDelegate KeepAlive = WndProc;
}
