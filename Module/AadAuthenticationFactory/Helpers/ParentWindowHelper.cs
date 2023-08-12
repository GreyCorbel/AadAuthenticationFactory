using System;
using System.Runtime.InteropServices;

enum GetAncestorFlags
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
    static extern IntPtr GetAncestor(IntPtr hwnd, GetAncestorFlags flags);
    
    [DllImport("kernel32.dll")]
    static extern IntPtr GetConsoleWindow();
    
    // This is your window handle!
    public static IntPtr GetConsoleOrTerminalWindow()
    {
        IntPtr consoleHandle = GetConsoleWindow();
        if(null == consoleHandle)
            throw new System.PlatformNotSupportedException("Could not get console window handle on this OS platform");
        IntPtr handle = GetAncestor(consoleHandle, GetAncestorFlags.GetRootOwner );
        
        return handle;
    }
}
