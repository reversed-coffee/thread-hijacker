# Thread-Hijacker
A proof-of-concept C# project that can inject a DLL into a process by hijacking its main thread. The point of this project is to demonstrate how a DLL can be injected into a process without creating any new threads. I created this while studying the internals of Windows, and it was a fun project to work on. I hope you find it useful.

This project is completely PnP (plug n' play) — you should just be able to copy the source files to your .NET project and include the namespace to use it. This project was created for educational purposes only.

## Summary
The program will first attempt to find the target process by name. If the process is found, the program will then attempt to find the target's main thread. If the main thread is found, the program will then attempt to inject the DLL into the target process by hijacking the main thread of the process.

## How It Works
The program essentially follows this process to hijack the main thread of the target process:
- Suspend the target thread using `SuspendThread`.
- Save the thread's context using `GetThreadContext`.
- Allocate memory for the DLL path and write the DLL path to the allocated memory.
- Allocate memory for the return value of `LoadLibraryA`.
- Allocate memory for a code cave and write the code cave to the allocated memory. The code cave will call `LoadLibraryA` with the DLL path as the argument. Once `LoadLibraryA` is called, it will copy the contents of `eax` (the return argument of `LoadLibraryA`) to the allocated return memory. After that's done, it will then jump back to `eip` in the saved context. The mnemonics for the code cave is as follows:
    ```x86asm
    pushad                ; save registers to stack
    push offset dllPath   ; push path pointer to stack
    call LoadLibraryA     ; load the module
    mov [result], eax     ; copy contents of eax to result
    popad                 ; pop registers back to original state
    jmp back              ; jump back to what thread was executing
    ```
- Set the thread context's `eip` to the address of the code cave and update the thread's context using `SetThreadContext`.
- Resume the thread using `ResumeThread`, thereby executing the code cave and inevitably loading the DLL.

## License
This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for more information.
