using System;

namespace MonoSecurityTools
{
    public static class StringArrayExtensions
    {
        public static string GetArgumentByIndex(this string[] argArr, int idx, string argDescription)
        {
            if(idx >= argArr.Length)
                throw new ArgumentException(argDescription + " wasn't specified");
            return argArr[idx];
        }
    }
}

