using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Remoting.Contexts;
using System.Text;
using System.Threading.Tasks;

namespace Injector
{
    internal class Native
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern bool ReadProcessMemory(int hProcess, uint lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern bool WriteProcessMemory(int hProcess, uint lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern uint VirtualAllocEx(int hProcess, uint lpAddress, int dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern bool VirtualFreeEx(int hProcess, uint lpAddress, int dwSize, AllocationType dwFreeType);

        [Flags]
        public enum AllocationType : uint
        {
            Commit     = 0x00001000,
            Reserve    = 0x00002000,
            Decommit   = 0x00004000,
            Release    = 0x00008000,
            Reset      = 0x00080000,
            Physical   = 0x00400000,
            TopDown    = 0x00100000,
            WriteWatch = 0x00200000,
            LargePages = 0x20000000,
        }

        [Flags]
        public enum MemoryProtection : uint
        {
            Execute          = 0x010,
            ReadExecute      = 0x020,
            ReadWriteExecute = 0x040,
            WriteCopyExecute = 0x080,
            NoAccess         = 0x001,
            ReadOnly         = 0x002,
            ReadWrite        = 0x004,
            WriteCopy        = 0x008,
            Guard            = 0x100,
            NoCache          = 0x200,
            WriteCombine     = 0x400,
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern int OpenProcess(ProcessAccess dwDesiredAccess, bool bInheritHandle, int dwProcId);

        [Flags]
        public enum ProcessAccess : uint
        {
            All                     = 0x001F0FFF,
            Terminate               = 0x00000001,
            CreateThread            = 0x00000002,
            VirtualMemoryOperation  = 0x00000008,
            VirtualMemoryRead       = 0x00000010,
            VirtualMemoryWrite      = 0x00000020,
            DuplicateHandle         = 0x00000040,
            CreateProcess           = 0x000000080,
            SetQuota                = 0x00000100,
            SetInformation          = 0x00000200,
            QueryInformation        = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize             = 0x00100000,
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern bool CloseHandle(int hThread);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern uint LoadLibraryA(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern bool FreeLibrary(uint hModule);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern uint GetProcAddress(uint hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern int OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, int dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern int SuspendThread(int hThread);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern int ResumeThread(int hThread);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern bool GetThreadContext(int hThread, ref ThreadContext lpContext);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern bool SetThreadContext(int hThread, ref ThreadContext lpContext);

        [Flags]
        public enum ThreadAccess : uint
        {
            Terminate         = 0x0001,
            SuspendResume     = 0x0002,
            GetContext        = 0x0008,
            SetContext        = 0x0010,
            SetInfo           = 0x0020,
            QueryInfo         = 0x0040,
            SetToken          = 0x0080,
            Impersonate       = 0x0100,
            DirectImpersonate = 0x0200,
        }

        [Flags]
        public enum ContextFlags : uint
        {
            I386             = 0x10000,
            Control          = I386 | 0x01,
            Integer          = I386 | 0x02,
            Segments         = I386 | 0x04,
            FloatingPoint    = I386 | 0x08,
            DebugRegisters   = I386 | 0x10,
            ExtendedRegisers = I386 | 0x20,
            Full             = Control | Integer | Segments,
            All              = Control | Integer | Segments | FloatingPoint | DebugRegisters | ExtendedRegisers,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct XmmSave
        {
            public int ControlWord;
            public int StatusWord;
            public int TagWord;
            public int ErrorOffset;
            public int ErrorSelector;
            public int DataOffset;
            public int DataSelector;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            public byte[] RegisterArea;
            public int Cr0NpxState;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ThreadContext
        {
            public ContextFlags Flags;
            public uint Dr0;
            public uint Dr1;
            public uint Dr2;
            public uint Dr3;
            public uint Dr6;
            public uint Dr7;
            public XmmSave Xmm;
            public uint SegGs;
            public uint SegFs;
            public uint SegEs;
            public uint SegDs;
            public uint Edi;
            public uint Esi;
            public uint Ebx;
            public uint Edx;
            public uint Ecx;
            public uint Eax;
            public uint Ebp;
            public uint Eip;
            public uint SegCs;
            public uint EFlags;
            public uint Esp;
            public uint SegSs;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] ExtendedRegisters;
        }

        [Flags]
        public enum SnapRules : uint
        {
            HeapList = 0x00000001,
            Process  = 0x00000002,
            Thread   = 0x00000004,
            Module   = 0x00000008,
            Module32 = 0x00000010,
            Inherit  = 0x80000000,
            SnapAll  = HeapList | Process | Thread | Module,
        }

        public const int InvalidHandle = -1;

        [StructLayout(LayoutKind.Sequential)]
        public struct ThreadEntry
        {
            public int Size;
            public uint UsageCount;
            public int ThreadId;
            public int ProcessId;
            public int KeBasePriority;
            public int DeltaPriority;
            public uint Flags;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern int CreateToolhelp32Snapshot(SnapRules dwFlags, int th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern bool Thread32First(int hSnapshot, ref ThreadEntry lpte);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern bool Thread32Next(int hSnapshot, ref ThreadEntry lpte);
    }
}