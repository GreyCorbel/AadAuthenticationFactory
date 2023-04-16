using System;
using System.Security;
using System.Runtime.InteropServices;
using System.Text;

internal static class SecureStringExtensions
{
    public static string ToPlainText(this SecureString secureString)
    {
        if (secureString == null)
            return null;

        var buffer = new char[secureString.Length];
        StringBuilder sb = new StringBuilder();
        IntPtr secureStringPtr = Marshal.SecureStringToCoTaskMemUnicode(secureString);
        for (int i = 0; i < secureString.Length; i++)
            sb.Append( (char)Marshal.ReadInt16(secureStringPtr, i * 2) );

        Marshal.ZeroFreeCoTaskMemUnicode(secureStringPtr);
        
        return sb.ToString();
    }
}
