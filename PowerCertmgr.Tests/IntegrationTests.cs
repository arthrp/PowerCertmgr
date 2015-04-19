using System;
using NUnit.Framework;
using System.IO;
using MonoSecurityTools;

namespace PowerCertmgr.Tests
{
    [TestFixture]
    public class IntegrationTests
    {
        [Test]
        public void CalledWithZeroArgsShouldPrintUsage()
        {
            using (StringWriter sw = new StringWriter())
            {
                Console.SetOut(sw);

                PowerCertMgr.Main(new string[]{ });

                Assert.True(sw.ToString().Contains("Usage"));
            }
        }

        [Test]
        public void PrintsHelpProperly()
        {
            using (StringWriter sw = new StringWriter())
            {
                Console.SetOut(sw);

                PowerCertMgr.Main(new string[]{ "--help" });
                Assert.True(sw.ToString().Contains("Usage:"));
            }
        }

        [Test]
        public void CallingAddWithoutMandatoryParamsPrintsError()
        {
            using (StringWriter sw = new StringWriter())
            {
                Console.SetOut(sw);

                PowerCertMgr.Main(new string[]{ "-add", "-c" });
                Assert.True(sw.ToString().Contains("Invalid arguments: store name wasn't specified"));
            }

            using (StringWriter sw = new StringWriter())
            {
                Console.SetOut(sw);

                PowerCertMgr.Main(new string[]{ "-add", "-crl" });
                Assert.True(sw.ToString().Contains("Invalid arguments: store name wasn't specified"));
            }

            using (StringWriter sw = new StringWriter())
            {
                Console.SetOut(sw);

                PowerCertMgr.Main(new string[]{ "-add", "-crap" });
                Assert.True(sw.ToString().Contains("Usage:"));
            }

            using (StringWriter sw = new StringWriter())
            {
                Console.SetOut(sw);

                PowerCertMgr.Main(new string[]{ "-add", "-c", "My" });
                Assert.True(sw.ToString().Contains("Invalid arguments: path to Certificate wasn't specified"));
            }
        }

        [Test]
        public void CallingDelWithoutMandatoryParamsPrintsError()
        {
            using (StringWriter sw = new StringWriter())
            {
                Console.SetOut(sw);

                PowerCertMgr.Main(new string[]{ "-del", "-c", "My" });
                Assert.True(sw.ToString().Contains("Invalid arguments: path to Certificate wasn't specified"));
            }
        }

        [Test]
        public void CallingListWithoutMandatiryParamsPrintsError()
        {
            using (StringWriter sw = new StringWriter())
            {
                Console.SetOut(sw);

                PowerCertMgr.Main(new string[]{ "-list", "-c" });
                Assert.True(sw.ToString().Contains("Usage:"));
            }
        }
    }
}

