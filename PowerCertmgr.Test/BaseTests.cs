using System;
using NUnit.Framework;
using System.IO;
using MonoSecurityTools;

namespace PowerCertmgr.Test
{
    [TestFixture]
    public class BaseTests
    {
        [Test]
        public void Test_CalledWithZeroArgsShouldPrintUsage()
        {
            using (StringWriter sw = new StringWriter())
            {
                Console.SetOut(sw);

                PowerCertMgr.Main(new string[]{ });

                Assert.True(sw.ToString().Contains("Usage"));
            }
        }
    }
}

