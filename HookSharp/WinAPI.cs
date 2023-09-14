using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace HookSharp
{
    internal class WinAPI
    {
        [DllImport("kernel32.dll")]
        public static extern int SuspendThread(IntPtr hThread);
        [DllImport("kernel32.dll")]
        public static extern int ResumeThread(IntPtr hThread);
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenThread(int dwDesiredAccess, bool bInheritHandle, int dwThreadId);
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(int hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesRead);
        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);
        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr LoadLibraryExW([MarshalAs(UnmanagedType.LPWStr)]string lpFileName, IntPtr hReservedNull, uint dwFlags);

        public static IntPtr LoadLibrary(string dllPath)
        {
            IntPtr moduleHandle = LoadLibraryExW(dllPath, IntPtr.Zero, 0x1 /*DontResolveDllReferences*/);

            if (moduleHandle == IntPtr.Zero)
            {
                var lasterror = Marshal.GetLastWin32Error();

                var innerEx = new Win32Exception(lasterror);

                innerEx.Data.Add("LastWin32Error", lasterror);
            }
            return moduleHandle;
        }

        // Use the SuspendProcess methods to suspend and resume all threads in a process.
        public static void SuspendProcess(int pid)
        {
            Process process = Process.GetProcessById(pid);
            foreach (ProcessThread pT in process.Threads)
            {
                IntPtr pOpenThread = OpenThread(0x0002, false, pT.Id);
                if (pOpenThread == IntPtr.Zero)
                {
                    continue;
                }
                SuspendThread(pOpenThread);
                CloseHandle(pOpenThread);
            }
        }

        // Use the ResumeProcess method to resume all suspended threads in a process
        public static void ResumeProcess(int pid)
        {
            Process process = Process.GetProcessById(pid);
            foreach (ProcessThread pT in process.Threads)
            {
                IntPtr pOpenThread = OpenThread(0x0002, false, pT.Id);
                if (pOpenThread == IntPtr.Zero)
                {
                    continue;
                }
                ResumeThread(pOpenThread);
                CloseHandle(pOpenThread);
            }
        }
    }
}
