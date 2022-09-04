using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data.SqlTypes;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static Injector.Native;

namespace Injector
{
    [Serializable]
    public class InjectException : Exception
    {
        public InjectException(string message) : base(string.Format("Injection failed: {0}", message)) { }
    }

    public class Injector
    {
        // 60             | pushad                ; save registers
        // 68 00 00 00 00 | push offset lpDllPath ; push path pointer to stack
        // E8 00 00 00 00 | call lpLoadLibraryA   ; load the module
        // A3 00 00 00 00 | mov lpResult, eax     ; copy contents of eax (LLA return) to result
        // 61             | popad                 ; pop registers
        // E9 00 00 00 00 | jmp back              ; jump back to what thread was executing
        static readonly byte[] PayloadBase = { 0x60, 0x68, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x61, 0xE9, 0x00, 0x00, 0x00, 0x00 };

        class InjectCtx : IDisposable
        {
            // Process
            public Process Proc
            {
                set
                {
                    if (ProcHnd != 0) CloseHandle(ProcHnd);
                    ProcHnd = OpenProcess(ProcessAccess.All, false, value.Id);

                    // Get main thread
                    ThreadEntry te = new();
                    te.Size = Marshal.SizeOf(te);
                   
                    var hSnap = CreateToolhelp32Snapshot(SnapRules.Thread, value.Id);
                    if (hSnap == InvalidHandle)
                        throw new InjectException("Failed to create ToolHelp32 snapshot.");

                    for (var next = Thread32First(hSnap, ref te); next; next = Thread32Next(hSnap, ref te))
                    {
                        if (te.ProcessId == value.Id)
                        {
                            CloseHandle(hSnap);
                            ThreadId = te.ThreadId;
                            return;
                        }
                    }

                    CloseHandle(hSnap);
                    throw new InjectException("Failed to find main thread.");
                }
            }

            int _ThreadId;
            public int ThreadId
            {
                get => _ThreadId;
                private set
                {
                    _ThreadId = value;
                    if (ThreadHnd != 0) CloseHandle(ThreadHnd);
                    ThreadHnd = OpenThread(ThreadAccess.GetContext | ThreadAccess.SetContext | ThreadAccess.SuspendResume, false, value);
                }
            }

            // Handles
            int ProcHnd = 0;
            int ThreadHnd = 0;

            ThreadContext CachedContext = new() { Flags = ContextFlags.Full };
            bool Frozen = false;
            public void Freeze()
            {
                CachedContext = ThreadCtx;
                SuspendThread(ThreadHnd);
                Frozen = true;
            }

            public void Thaw()
            {
                ResumeThread(ThreadHnd);
                Frozen = false;
            }

            // Memory objects
            uint DllPathPointer = 0;
            public string DllPath
            {
                get
                {
                    var buf = new byte[260];
                    if (!ReadProcessMemory(ProcHnd, DllPathPointer, buf, 260, out _))
                    {
                        Dispose();
                        throw new InjectException("Failed to get DLL path.");
                    }
                    return Encoding.ASCII.GetString(buf);
                }
                set
                {
                    if (!File.Exists(value))
                    {
                        Dispose();
                        throw new InjectException(string.Format("DLL not found: {0}", value));
                    }

                    value = Path.GetFullPath(value);
                    if (!WriteProcessMemory(ProcHnd, DllPathPointer, Encoding.ASCII.GetBytes(value), value.Length, out _))
                    {
                        Dispose();
                        throw new InjectException("Failed to set DLL path.");
                    }
                }
            }

            public uint CavePointer = 0;
            public void GenCave()
            {
                var payload = new byte[PayloadBase.Length];
                Array.Copy(PayloadBase, payload, PayloadBase.Length);

                using (MemoryStream stm = new(payload))
                {
                    stm.Skip(2);
                    stm.WritePointer(DllPathPointer);
                    stm.Skip();
                    stm.WritePointer(LoadLibraryA - CavePointer - 11);
                    stm.Skip();
                    stm.WritePointer(ResultPointer);
                    stm.Skip(2);
                    stm.WritePointer(ThreadCtx.Eip - CavePointer - 22);
                }

                if (!WriteProcessMemory(ProcHnd, CavePointer, payload, PayloadBase.Length, out _))
                {
                    Dispose();
                    throw new InjectException("Failed to set code cave.");
                }
            }

            uint ResultPointer = 0;
            public uint Result
            {
                get
                {
                    var buf = new byte[sizeof(uint)];
                    if (!ReadProcessMemory(ProcHnd, ResultPointer, buf, sizeof(uint), out _))
                    {
                        Dispose();
                        throw new InjectException("Failed to read LoadLibraryA result.");
                    }
                    return BitConverter.ToUInt32(buf, 0);
                }
                private set
                {
                    if (!WriteProcessMemory(ProcHnd, ResultPointer, BitConverter.GetBytes(value), sizeof(uint), out _))
                    {
                        Dispose();
                        throw new InjectException("Failed to initially set LoadLibraryA result.");
                    }
                }
            }

            public void AllocObjects()
            {
                DllPathPointer = VirtualAllocEx(ProcHnd, 0, 260, AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ReadWriteExecute);
                if (DllPathPointer == 0)
                {
                    Dispose();
                    throw new InjectException("Failed to allocate DLL path.");
                }

                CavePointer = VirtualAllocEx(ProcHnd, 0, PayloadBase.Length, AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ReadWriteExecute);
                if (CavePointer == 0)
                {
                    Dispose();
                    throw new InjectException("Failed to allocate code cave.");
                }

                ResultPointer = VirtualAllocEx(ProcHnd, 0, sizeof(uint), AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ReadWrite);
                if (ResultPointer == 0)
                {
                    Dispose();
                    throw new InjectException("Failed to allocate LoadLibraryA result.");
                }

                Result = 0xFFFFFFFFu;
            }

            // Misc objects
            public ThreadContext ThreadCtx
            {
                get
                {
                    ThreadContext ctx = new() { Flags = ContextFlags.Full };
                    if (!GetThreadContext(ThreadHnd, ref ctx))
                    {
                        Dispose();
                        throw new InjectException("Failed to get thread context.");
                    }
                    return ctx;
                }
                set
                {
                    if (!SetThreadContext(ThreadHnd, ref value))
                    {
                        Dispose();
                        throw new InjectException("Failed to set thread context.");
                    }
                }
            }

            public void SetEip2Cave()
            {
                // I did this on purpose
                var tctx = ThreadCtx;
                tctx.Eip = CavePointer;
                ThreadCtx = tctx;
            }

            public uint LoadLibraryA
            {
                get
                {
                    var kernel32 = LoadLibraryA("kernel32.dll");
                    if (kernel32 == 0)
                    {
                        Dispose();
                        throw new InjectException("Failed to load Kernel32.");
                    }

                    var lla = GetProcAddress(kernel32, "LoadLibraryA");
                    if (lla == 0)
                    {
                        FreeLibrary(kernel32);
                        Dispose();
                        throw new InjectException("Failed to get LoadLibraryA.");
                    }

                    FreeLibrary(kernel32);
                    return lla;
                }
            }

            bool IsDispose = false;
            public virtual void Dispose()
            {
                if (IsDispose) return;
                IsDispose = true;

                try
                {
                    if (ProcHnd != 0)
                    {
                        if (CavePointer != 0) VirtualFreeEx(ProcHnd, CavePointer, 0, AllocationType.Release);
                        if (DllPathPointer != 0) VirtualFreeEx(ProcHnd, DllPathPointer, 0, AllocationType.Release);
                        if (ResultPointer != 0) VirtualFreeEx(ProcHnd, ResultPointer, 0, AllocationType.Release);
                        CloseHandle(ProcHnd);
                    }

                    if (Frozen)
                    {
                        ThreadCtx = CachedContext; // Replace with old
                        Thaw();
                    }

                    if (ThreadHnd != 0) CloseHandle(ThreadHnd);
                }
                catch { }
            }

            ~InjectCtx() => Dispose();
        }

        public static bool LoadLibrary(Process proc, string dllPath)
        {
            // First time trying this method of organization. I (sort of) like it.
            using var ictx = new InjectCtx { Proc = proc, };
            ictx.Freeze();
            ictx.AllocObjects();
            ictx.DllPath = dllPath;
            ictx.GenCave();
            ictx.SetEip2Cave();
            ictx.Dispose();
            ictx.Thaw();

            // Wait for return
            while (ictx.Result == 0xFFFFFFFFu)
                Thread.Sleep(10);

            return ictx.Result != 0; // hModule != 0
        }
    }
}
