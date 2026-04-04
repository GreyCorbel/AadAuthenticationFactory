using System;
using System.Runtime.InteropServices;

public static class Kernel32
{
    // LoadLibrary loads a DLL into the calling process.
    // Returns a module handle, or IntPtr.Zero on failure.
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr LoadLibrary(string lpFileName);

    // Optional: free a module handle returned by LoadLibrary.
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool FreeLibrary(IntPtr hModule);

    // Optional: returns the calling thread's last-error code value.
    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();

    // Optional: alters the DLL search path for the process.
    // Can be used if you want to point Windows loader at a directory.
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetDllDirectory(string lpPathName);
}