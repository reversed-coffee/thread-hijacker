using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Injector
{
    internal static class StreamExtensions
    {
        public static void WritePointer(this MemoryStream stm, uint pointer)
        {
            stm.Write(BitConverter.GetBytes(pointer), 0, sizeof(uint));
        }

        public static void Skip(this MemoryStream stm, int n = 1)
        {
            stm.Position += n;
        }
    }
}
