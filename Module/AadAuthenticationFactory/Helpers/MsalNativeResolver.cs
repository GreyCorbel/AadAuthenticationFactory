using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

public static class MsalNativeResolver
    {
        private static string _nativePath;
        private static string _fileName;
        private static bool _registered;

        public static void RegisterFor(Assembly assembly, string nativePath)
        {
            _nativePath = nativePath;
            _fileName = Path.GetFileNameWithoutExtension(nativePath);
            if (_registered) return;
            NativeLibrary.SetDllImportResolver(assembly, Resolve);
            _registered = true;
        }

        private static IntPtr Resolve(string name, Assembly asm, DllImportSearchPath? sp)
        {   
            if (name.Equals(_fileName, StringComparison.OrdinalIgnoreCase))
            {
                if (File.Exists(_nativePath))
                {
                    return NativeLibrary.Load(_nativePath);
                }
            }
            return IntPtr.Zero;
        }
    }
