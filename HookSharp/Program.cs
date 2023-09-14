using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace HookSharp
{
    class Program
    {
        static void Main(string[] args)
        {
            Process process = Process.GetProcessesByName("overwatch").FirstOrDefault();

            // Set the console to use UTF8 supported strings
            Console.OutputEncoding = System.Text.Encoding.UTF8;

            if (process == null)
            {
                Console.WriteLine("Process cannot be found.");
            }
            else
            {
                Console.WriteLine($"DllName\t\tOffset\t\tOriginal\tNew\tFunction");
                process.ScanHooks();
            }

            Console.WriteLine($"");
            Console.Write($"Scan completed...");
            Console.ReadKey();
        }
    }

    public static class ProcessHelper
    {
        public static void ScanHooks(this Process process)
        {
            foreach (ProcessModule module in process.Modules.Cast<ProcessModule>().Where(x => x.ModuleName.Contains(".dll")))
            {
                byte[] bytesFromRemoteMemory = process.GetBytesFromDll(module);
                byte[] bytesFromMyMemory = Process.GetCurrentProcess().GetBytesFromDll(module);

                // http://www.pinvoke.net/default.aspx/Structures.IMAGE_DOS_HEADER
                int e_lfanew = bytesFromMyMemory[0x3C];

                // https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-_image_optional_header
                int optionalHeaderOffset = 0x18;
                int sizeOfCodeOffset = e_lfanew + optionalHeaderOffset + 0x4;
                int BaseOfCodeOffset = e_lfanew + optionalHeaderOffset + 0x14;

                // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/262627d8-3418-4627-9218-4ffe110850b2
                uint BaseOfCode = BitConverter.ToUInt32(bytesFromMyMemory, BaseOfCodeOffset);
                uint sizeOfCode = BitConverter.ToUInt32(bytesFromMyMemory, sizeOfCodeOffset);

                for (uint i = BaseOfCode; i < sizeOfCode; i++)
                {
                    if (i >= bytesFromMyMemory.Length || i >= bytesFromRemoteMemory.Length)
                    {
                        break;
                    }

                    byte original = bytesFromMyMemory[i];
                    byte possiblyTampered = bytesFromRemoteMemory[i];
                    if (original != possiblyTampered)
                    {
                        var tModule = Process.GetCurrentProcess().GetProcessModule(module.ModuleName);
                        Console.WriteLine($"{module.ModuleName}" +
                            $"\t0x{i:X}" +
                            $"\t\t0x{original:X}" +
                            $"\t\t0x{possiblyTampered:X}"
                            + $"\t{GetFunctionNameFromAddress(tModule, (IntPtr)i)}"
                            );
                    }
                }
            }
        }

        public static byte[] GetBytesFromDll(this Process process, ProcessModule module)
        {
            // If we can find it in our own process then we retrieve those bytes, otherwise retrieve bytes from disk
            var procModule = process.GetProcessModule(module.ModuleName);

            if (procModule == null)
            {
                WinAPI.LoadLibrary(module.FileName);

                // Refresh the process modules list
                process = Process.GetProcessById(process.Id);
            }

            byte[] result = process.GetByteFromProcessModule(module.ModuleName);

            return result;
        }

        public static ProcessModule GetProcessModule(this Process process, string moduleName)
        {
            ProcessModule module = process.Modules.Cast<ProcessModule>().Where(x => x.ModuleName.ToUpper() == moduleName.ToUpper()).FirstOrDefault();
            return module;
        }

        public static byte[] GetByteFromProcessModule(this Process process, string moduleName)
        {
            // Get current process id
            Process currentProcess = Process.GetCurrentProcess();

            ProcessModule module = process.GetProcessModule(moduleName);

            int bytesRead = 0;

            byte[] buffer = new byte[module.ModuleMemorySize];

            // Only run this code if the process is not the same as the current process
            if (process.Id != currentProcess.Id)
            {
                WinAPI.SuspendProcess(process.Id);
            }

            IntPtr processHandle = WinAPI.OpenProcess(0x10 /* VirtualMemoryRead */, false, process.Id);

            WinAPI.ReadProcessMemory((int)processHandle, module.BaseAddress, buffer, buffer.Length, ref bytesRead);

            WinAPI.CloseHandle(processHandle);

            if (process.Id != currentProcess.Id)
            { 
                WinAPI.ResumeProcess(process.Id);
            }

            return buffer;
        }

        // Return the name of function which belongs to a memory address in a module
        public static string GetFunctionNameFromAddress(this ProcessModule module, IntPtr offset)
        {
            IntPtr address = (IntPtr)(module.BaseAddress.ToInt64() + offset.ToInt64());
            string result = Marshal.PtrToStringAuto(address);
            return result;
        }
    }
}
