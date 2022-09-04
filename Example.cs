using System;
using System.Diagnostics;
using Injector;

internal class Program
{
    static void Main(string[] args)
    {
        var procs = Process.GetProcessesByName("ac_client");
        if (procs.Length < 1)
        {
            Console.WriteLine("Game not found");
            return;
        }

        try
        {
            if (!Injector.LoadLibrary(procs[0], "hello_world.dll"))
            {
                Console.WriteLine("Injection failed"); // Nothing wrong happened on this end; most likely the DLL's fault.
            }
            // DLL successfully injected.
        }
        catch (InjectException ex) // Something wrong happened on this end.
        {
            Console.WriteLine(ex.Message);
        }
    }
}