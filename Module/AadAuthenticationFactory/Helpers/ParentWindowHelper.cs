using System;
using System.Runtime.InteropServices;

internal enum GetAncestorFlags
{
    GetParent = 1,
    GetRoot = 2,
    /// <summary>
    /// Retrieves the owned root window by walking the chain of parent and owner windows returned by GetParent.
    /// </summary>
    GetRootOwner = 3
}

public static class ParentWindowHelper
{
    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern IntPtr GetAncestor(IntPtr hwnd, GetAncestorFlags flags);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern bool IsWindow(IntPtr hWnd);

    /// <summary>
    /// Delegate MSAL can call to obtain a parent window handle (HWND).
    /// Keep it public so PowerShell can override if needed.
    /// </summary>
    public static Func<IntPtr> ConsoleWindowHandleProvider = () =>
    {
        try
        {
            //just return the currently focused window; this will work in most cases, including when launched from a console/terminal. It also allows support for non-console apps like VS Code.
            IntPtr fg = Normalize(GetForegroundWindow());
            if (fg != IntPtr.Zero)
                return fg;

            // try Classic console host (conhost.exe)
            IntPtr consoleHandle = GetConsoleWindow();
            if (consoleHandle != IntPtr.Zero)
            {
                IntPtr rootOwner = GetAncestor(consoleHandle, GetAncestorFlags.GetRootOwner);
                IntPtr normalized = Normalize(rootOwner);
                if (normalized != IntPtr.Zero)
                    return normalized;
            }

            // 3) No usable window handle
            return IntPtr.Zero;
        }
        catch
        {
            // Never throw from a parent window provider; let caller fall back to browser/device code
            return IntPtr.Zero;
        }
    };

    /// <summary>
    /// Convenience method if you prefer a direct call.
    /// </summary>
    public static IntPtr GetConsoleOrTerminalWindow()
    {
        return ConsoleWindowHandleProvider();
    }

    private static IntPtr Normalize(IntPtr hwnd)
    {
        if (hwnd == IntPtr.Zero)
            return IntPtr.Zero;

        // Avoid returning invalid handles
        if (!IsWindow(hwnd))
            return IntPtr.Zero;

        return hwnd;
    }
}