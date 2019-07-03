using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace HookSharp
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine($"DllName\t\tOffset\t\tOriginal\tNew");

            ScanDll("Notepad++", "ntdll.dll");
            ScanDll("Notepad++", "kernel32.dll");
            ScanDll("Notepad++", "user32.dll");

            Console.WriteLine($"");
            Console.Write($"Scan completed...");
            Console.ReadKey();
        }

        static void ScanDll (string remoteProcessName, string dllName)
        {
            byte[] bytesFromMyMemory = ProcessHelper.GetByteFromProcessModule(Process.GetCurrentProcess(), dllName);
            byte[] bytesFromRemoteMemory = ProcessHelper.GetByteFromProcessModule(Process.GetProcessesByName(remoteProcessName).FirstOrDefault(), dllName);

            byte e_lfanew = bytesFromMyMemory[0x3C];
            byte optionalHeaderOffset = 0x18;

            int sizeOfCodeOffset = e_lfanew + optionalHeaderOffset + 0x4;
            int BaseOfCodeOffset = e_lfanew + optionalHeaderOffset + 0x14;

            uint BaseOfCode = BitConverter.ToUInt32(bytesFromMyMemory, BaseOfCodeOffset);
            uint sizeOfCode = BitConverter.ToUInt32(bytesFromMyMemory, sizeOfCodeOffset);

            for (uint i = BaseOfCode; i < sizeOfCode; i++)
            {
                byte a = bytesFromMyMemory[i];
                byte b = bytesFromRemoteMemory[i];

                if (a != b)
                {
                    Console.WriteLine($"{dllName}\t0x{i.ToString("X")}\t\t0x{a.ToString("X")}\t\t0x{b.ToString("X")}");
                }
            }
        }
    }

    public static class ProcessHelper
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(int hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        public static byte[] GetByteFromProcessModule (Process process, string moduleName)
        {
            ProcessModule module = process.Modules.Cast<ProcessModule>().Where(x => x.ModuleName.ToUpper() == moduleName.ToUpper()).FirstOrDefault();

            int bytesRead = 0;

            byte[] buffer = new byte[module.ModuleMemorySize];

            IntPtr processHandle = OpenProcess(0x0010, false, process.Id);

            ReadProcessMemory((int)processHandle, module.BaseAddress, buffer, buffer.Length, ref bytesRead);

            CloseHandle(processHandle);

            return buffer;
        }
    }
}
