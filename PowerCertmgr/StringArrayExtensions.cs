using System;

namespace MonoSecurityTools
{
    public static class StringArrayExtensions
    {
        public static string GetArgumentByIndex(this string[] argArr, int idx, string argDescription, bool isOptional = false)
        {
            if(isOptional && idx >= argArr.Length)
                return null;

            if(idx >= argArr.Length)
                throw new ArgumentException(argDescription + " wasn't specified");
            return argArr[idx];
        }
    }
}

