using System;
using System.IO;
using Mono.Security.Authenticode;
using Mono.Security.Cryptography;
using Mono.Security.X509;
using Mono.Security.Protocol.Tls;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using SSCX = System.Security.Cryptography.X509Certificates;

namespace MonoSecurityTools
{
    public static class SslHelper
    {
        public static X509CertificateCollection GetCertificatesFromSslSession (string url) 
        {
            Uri uri = new Uri (url);
            IPHostEntry host = Dns.Resolve (uri.Host);
            IPAddress ip = host.AddressList [0];
            Socket socket = new Socket (ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            socket.Connect (new IPEndPoint (ip, uri.Port));
            NetworkStream ns = new NetworkStream (socket, false);
            SslClientStream ssl = new SslClientStream (ns, uri.Host, false, Mono.Security.Protocol.Tls.SecurityProtocolType.Default, null);
            //ssl.ServerCertValidationDelegate += new CertificateValidationCallback (CertificateValidation);

            try 
            {
                // we don't really want to write to the server (as we don't know
                // the protocol it using) but we must send something to be sure the
                // SSL handshake is done (so we receive the X.509 certificates).
                StreamWriter sw = new StreamWriter (ssl);
                sw.WriteLine (Environment.NewLine);
                sw.Flush ();
                socket.Poll (30000, SelectMode.SelectRead);
            }
            finally 
            {
                socket.Close ();
            }

            // we need a little reflection magic to get this information
            PropertyInfo pi = typeof (SslStreamBase).GetProperty ("ServerCertificates", BindingFlags.Instance | BindingFlags.NonPublic);
            if (pi == null) {
                Console.WriteLine ("Sorry but you need a newer version of Mono.Security.dll to use this feature.");
                return null;
            }
            return (X509CertificateCollection) pi.GetValue (ssl, null);
        }
    }
}

