using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using SSCX = System.Security.Cryptography.X509Certificates;
using System.Text;

using Mono.Security.Authenticode;
using Mono.Security.Cryptography;
using Mono.Security.X509;
using Mono.Security.Protocol.Tls;

namespace MonoSecurityTools
{
    public class PowerCertMgr
    {
        private const string APP_NAME = "power-certmgr";

        /// <summary>
        /// The default certificate stores are all except Untrusted
        /// </summary>
        private static List<X509Store> DefaultCertificateStores = new List<X509Store>() 
        {
                X509StoreManager.CurrentUser.TrustedRoot,
                X509StoreManager.CurrentUser.Personal,
                X509StoreManager.CurrentUser.IntermediateCA,
                X509StoreManager.CurrentUser.OtherPeople
        };

        static private void PrintVersion () 
        {
            Console.WriteLine("version "+Assembly.GetExecutingAssembly().GetName().Version);
        }

        static private void PrintHelp () 
        {
            Console.WriteLine ("Usage: "+APP_NAME+" <action> [object-type] [options] store [filename]");
            Console.WriteLine ("   or: "+APP_NAME+" -list object-type [options] store");
            Console.WriteLine ("   or: "+APP_NAME+" -del object-type [options] store certhash");
            Console.WriteLine ("   or: "+APP_NAME+" -ssl [options] url");
            Console.WriteLine ("   or: "+APP_NAME+" -put object-type [options] store certfile");
            Console.WriteLine ("   or: "+APP_NAME+" -importKey [options] store pkcs12file");
            Console.WriteLine ();
            Console.WriteLine ("actions:");
            Console.WriteLine ("\t-add\t\tAdd a certificate, CRL or CTL to specified store");
            Console.WriteLine ("\t-del\t\tRemove a certificate, CRL or CTL from specified store");
            Console.WriteLine ("\t-put\t\tCopy a certificate, CRL or CTL from a store to a file");
            Console.WriteLine ("\t-list\t\tList certificates, CRL or CTL in the specified store.");
            Console.WriteLine ("\t-ssl\t\tDownload and add certificates from an SSL session");
            Console.WriteLine ("\t-importKey\tImport PKCS12 privateKey to keypair store.");
            Console.WriteLine ("object types:");
            Console.WriteLine ("\t-c\t\tcertificate");
            Console.WriteLine ("\t-crl\t\tCertificate Revocation List (CRL)");
            Console.WriteLine ("\t-ctl\t\tCertificate Trust List (CTL) [unsupported]");
            Console.WriteLine ("other options:");
            Console.WriteLine ("\t-m\t\tuse the machine certificate store (default to user)");
            Console.WriteLine ("\t-v\t\tverbose mode (display status for every steps)");
            Console.WriteLine ("\t-p [password]\tPassword used to decrypt PKCS12");
            Console.WriteLine ("\t-pem\t\tPut certificate in Base-64 encoded format (default is DER encoded)");
            Console.WriteLine ("\t-?\t\th[elp]\tDisplay this help message");
            Console.WriteLine ();
            Console.WriteLine("stores:");
            PrintStores();
        }

        static void PrintStores()
        {
            Console.WriteLine ("\tValid stores are: {0}, {1}, {2}, {3} and {4}",
                X509Stores.Names.Personal,
                X509Stores.Names.OtherPeople, 
                X509Stores.Names.IntermediateCA, 
                X509Stores.Names.TrustedRoot, 
                X509Stores.Names.Untrusted);
        }

        static string GetCommand (string arg) 
        {
            if ((arg == null) || (arg.Length < 1))
                return null;

            switch (arg [0]) {
            case '/':
                return arg.Substring (1).ToUpper ();
            case '-':
                if (arg.Length < 2)
                    return null;
                int startIndex = ((arg [1] == '-') ? 2 : 1);
                return arg.Substring (startIndex).ToUpper ();
            default:
                return arg;
            }
        }

        static Action GetAction (string arg) 
        {
            Action action = Action.None;
            switch (GetCommand (arg)) {
            case "ADD":
                action = Action.Add;
                break;
            case "DEL":
            case "DELETE":
                action = Action.Delete;
                break;
            case "PUT":
                action = Action.Put;
                break;
            case "LST":
            case "LIST":
                action = Action.List;
                break;
            case "SSL":
            case "TLS":
                action = Action.Ssl;
                break;
            case "IMPORTKEY":
                action = Action.ImportKey;
                break;
            }
            return action;
        }

        static ObjectType GetObjectType (string arg) 
        {
            ObjectType type = ObjectType.None;
            switch (GetCommand (arg)) {
            case "C":
            case "CERT":
            case "CERTIFICATE":
                type = ObjectType.Certificate;
                break;
            case "CRL":
                type = ObjectType.CRL;
                break;
            case "CTL":
                type = ObjectType.CTL;
                break;
            }
            return type;
        }

        static X509Store GetStoreFromName (string storeName, bool machine) 
        {
            X509Stores stores = ((machine) ? X509StoreManager.LocalMachine : X509StoreManager.CurrentUser);
            X509Store store = null;
            switch (storeName) {
            case X509Stores.Names.Personal:
                return stores.Personal;
            case X509Stores.Names.OtherPeople:
                return stores.OtherPeople;
            case X509Stores.Names.IntermediateCA:
                return stores.IntermediateCA;
            case "Root": // special case (same as trusted root)
            case X509Stores.Names.TrustedRoot:
                return stores.TrustedRoot;
            case X509Stores.Names.Untrusted:
                return stores.Untrusted;
            }
            return store;
        }

        static byte[] GetPem (string type, byte[] data) 
        {
            string pem = Encoding.ASCII.GetString (data);
            string header = String.Format ("-----BEGIN {0}-----", type);
            string footer = String.Format ("-----END {0}-----", type);
            int startIdx = pem.IndexOf (header) + header.Length;
            int endIdx = pem.IndexOf (footer, startIdx);
            string base64 = pem.Substring (startIdx, (endIdx - startIdx));
            return Convert.FromBase64String (base64);
        }

        static byte[] ToPem (string type, byte[] data)
        {
            string header = String.Format ("-----BEGIN {0}-----", type);
            string footer = String.Format ("-----END {0}-----", type);

            string encodedString = Convert.ToBase64String (data);

            StringBuilder sb = new StringBuilder ();
            int remaining = encodedString.Length;
            sb.AppendLine (header);
            for (int i = 0; i <= encodedString.Length; i += 64) {
                if (remaining >= 64) {
                    sb.AppendLine (encodedString.Substring (i, 64));
                } else {
                    sb.AppendLine (encodedString.Substring (i, remaining));
                }
                remaining -= 64;
            }
            sb.AppendLine (footer);
            return Encoding.ASCII.GetBytes (sb.ToString ());
        }

        static X509CertificateCollection LoadCertificates (string filename, string password, bool verbose) 
        {
            X509Certificate x509 = null;
            X509CertificateCollection coll = new X509CertificateCollection ();
            switch (Path.GetExtension (filename).ToUpper ()) {
            case ".P7B":
            case ".SPC":
                SoftwarePublisherCertificate spc = SoftwarePublisherCertificate.CreateFromFile (filename);
                coll.AddRange (spc.Certificates);
                spc = null;
                break;
            case ".CER":
            case ".CRT":
                using (FileStream fs = File.OpenRead (filename)) {
                    byte[] data = new byte [fs.Length];
                    fs.Read (data, 0, data.Length);
                    if (data [0] != 0x30) {
                        // maybe it's ASCII PEM base64 encoded ?
                        data = GetPem ("CERTIFICATE", data);
                    }
                    if (data != null)
                        x509 = new X509Certificate (data);
                }
                if (x509 != null)
                    coll.Add (x509);
                break;
            case ".P12":
            case ".PFX":
                PKCS12 p12 = (password == null) ? PKCS12.LoadFromFile (filename)
                    : PKCS12.LoadFromFile (filename, password);
                X509CertificateCollection tmp = new X509CertificateCollection (p12.Certificates);

                for (int i = 0; i != p12.Keys.Count; i++) {
                    X509Certificate cert = p12.Certificates[i];
                    RSACryptoServiceProvider pk = p12.Keys[i] as RSACryptoServiceProvider;

                    if (pk == null || pk.PublicOnly)
                        continue;

                    if (verbose)
                        Console.WriteLine ("Found key for certificate: {0}", cert.SubjectName);

                    tmp[0].RSA = pk;
                }
                coll.AddRange(tmp);
                p12 = null;
                break;
            default:
                Console.WriteLine ("Unknown file extension: {0}", 
                    Path.GetExtension (filename));
                break;
            }
            return coll;
        }

        static ArrayList LoadCRLs (string filename) 
        {
            X509Crl crl = null;
            ArrayList list = new ArrayList ();
            switch (Path.GetExtension (filename).ToUpper ()) {
            case ".P7B":
            case ".SPC":
                SoftwarePublisherCertificate spc = SoftwarePublisherCertificate.CreateFromFile (filename);
                list.AddRange (spc.Crls);
                spc = null;
                break;
            case ".CRL":
                using (FileStream fs = File.OpenRead (filename)) 
                {
                    byte[] data = new byte [fs.Length];
                    fs.Read (data, 0, data.Length);
                    crl = new X509Crl (data);
                }
                list.Add (crl);
                break;
            default:
                Console.WriteLine ("Unknown file extension: {0}", 
                    Path.GetExtension (filename));
                break;
            }
            return list;
        }

        static void Add (ObjectType type, X509Store store, string file, string password, bool verbose) 
        {
            switch (type) {
            case ObjectType.Certificate:
                X509CertificateCollection coll = LoadCertificates (file, password, verbose);
                foreach (X509Certificate x509 in coll) {
                    store.Import (x509);
                }
                Console.WriteLine ("{0} certificate(s) added to store {1}.", 
                    coll.Count, store.Name);
                break;
            case ObjectType.CRL:
                ArrayList list = LoadCRLs (file);
                foreach (X509Crl crl in list) {
                    store.Import (crl);
                }
                Console.WriteLine ("{0} CRL(s) added to store {1}.", 
                    list.Count, store.Name);
                break;
            default:
                throw new NotSupportedException (type.ToString ());
            }
        }

        static void Delete (ObjectType type, X509Store store, string hash) 
        {
            switch (type) {
            case ObjectType.Certificate:
                foreach (X509Certificate x509 in store.Certificates) {
                    if (hash == CryptoConvert.ToHex (x509.Hash)) {
                        store.Remove (x509);
                        Console.WriteLine ("Certificate removed from store.");
                        return;
                    }
                }
                break;
            case ObjectType.CRL:
                foreach (X509Crl crl in store.Crls) {
                    if (hash == CryptoConvert.ToHex (crl.Hash)) {
                        store.Remove (crl);
                        Console.WriteLine ("CRL removed from store.");
                        return;
                    }
                }
                break;
            default:
                throw new NotSupportedException (type.ToString ());
            }
        }

        static void Put (ObjectType type, X509Store store, string file, bool isMachineCertificateStore, bool pem, bool beVerbose) 
        {
            if (String.IsNullOrEmpty (file)) {
                Console.Error.WriteLine("error: no filename provided to put the certificate.");
                PrintHelp();
                return;
            }

            switch (type) {
            case ObjectType.Certificate:
                for(int i = 0; i < store.Certificates.Count; i++) {
                    Console.WriteLine ("==============Certificate # {0} ==========", i + 1);
                    DisplayCertificate (store.Certificates[i], isMachineCertificateStore, beVerbose);
                }
                int selection;
                Console.Write("Enter cert # from the above list to put-->");
                if (!int.TryParse(Console.ReadLine(), out selection) || selection > store.Certificates.Count) {
                    Console.Error.WriteLine ("error: invalid selection.");
                    return;
                }

                SSCX.X509Certificate2 cert = new SSCX.X509Certificate2 (store.Certificates[selection-1].RawData);
                byte[] data = null;
                if(pem) {
                    data = ToPem ("CERTIFICATE", cert.Export (SSCX.X509ContentType.Cert));
                } else {
                    data = cert.Export (SSCX.X509ContentType.Cert);
                }

                using (FileStream fs = File.Create (file)) {
                    fs.Write(data, 0, data.Length);
                }

                Console.WriteLine ("Certificate put to {0}.", file);
                break;
            default:
                throw new NotSupportedException ("Put " + type + " not supported yet");
            }
        }

        static void DisplayCertificate (X509Certificate x509, bool machine, bool verbose)
        {
            Console.WriteLine ("{0}X.509 v{1} Certificate", (x509.IsSelfSigned ? "Self-signed " : String.Empty), x509.Version);
            Console.WriteLine ("  Serial Number: {0}", CryptoConvert.ToHex (x509.SerialNumber));
            Console.WriteLine ("  Issuer Name:   {0}", x509.IssuerName);
            Console.WriteLine ("  Subject Name:  {0}", x509.SubjectName);
            Console.WriteLine ("  Valid From:    {0}", x509.ValidFrom);
            Console.WriteLine ("  Valid Until:   {0}", x509.ValidUntil);
            Console.WriteLine ("  Unique Hash:   {0}", CryptoConvert.ToHex (x509.Hash));
            if (verbose) {
                Console.WriteLine ("  Key Algorithm:        {0}", x509.KeyAlgorithm);
                Console.WriteLine ("  Algorithm Parameters: {0}", (x509.KeyAlgorithmParameters == null) ? "None" :
                    CryptoConvert.ToHex (x509.KeyAlgorithmParameters));
                Console.WriteLine ("  Public Key:           {0}", CryptoConvert.ToHex (x509.PublicKey));
                Console.WriteLine ("  Signature Algorithm:  {0}", x509.SignatureAlgorithm);
                Console.WriteLine ("  Algorithm Parameters: {0}", (x509.SignatureAlgorithmParameters == null) ? "None" :
                    CryptoConvert.ToHex (x509.SignatureAlgorithmParameters));
                Console.WriteLine ("  Signature:            {0}", CryptoConvert.ToHex (x509.Signature));
                RSACryptoServiceProvider rsaCsp = x509.RSA as RSACryptoServiceProvider;
                RSAManaged rsaManaged = x509.RSA as RSAManaged;
                Console.WriteLine ("  Private Key:            {0}", ((rsaCsp != null && !rsaCsp.PublicOnly) 
                    || (rsaManaged != null && !rsaManaged.PublicOnly)));
                CspParameters cspParams = new CspParameters ();
                cspParams.KeyContainerName = CryptoConvert.ToHex (x509.Hash);
                cspParams.Flags = machine ? CspProviderFlags.UseMachineKeyStore : 0;
                KeyPairPersistence kpp = new KeyPairPersistence (cspParams);
                Console.WriteLine ("  KeyPair Key:            {0}", kpp.Load ());
            }
            Console.WriteLine ();
        }

        static void DisplayCrl (X509Crl crl, bool machine, bool verbose)
        {
            Console.WriteLine ("X.509 v{0} CRL", crl.Version);
            Console.WriteLine ("  Issuer Name:   {0}", crl.IssuerName);
            Console.WriteLine ("  This Update:   {0}", crl.ThisUpdate);
            Console.WriteLine ("  Next Update:   {0} {1}", crl.NextUpdate, crl.IsCurrent ? String.Empty : "update overdue!");
            Console.WriteLine ("  Unique Hash:   {0}", CryptoConvert.ToHex (crl.Hash));
            if (verbose) {
                Console.WriteLine ("  Signature Algorithm:  {0}", crl.SignatureAlgorithm);
                Console.WriteLine ("  Signature:            {0}", CryptoConvert.ToHex (crl.Signature));
                int n = 0;
                foreach (X509Crl.X509CrlEntry entry in crl.Entries) {
                    Console.WriteLine ("    #{0}: Serial: {1} revoked on {2}",
                        ++n, CryptoConvert.ToHex (entry.SerialNumber), entry.RevocationDate);
                }
            }
        }

        static void List (ObjectType type, X509Store store, bool machine, bool verbose) 
        {
            var stores = (store == null) ? DefaultCertificateStores : new List<X509Store>() { store };
            switch (type) {
            case ObjectType.Certificate:
                foreach (X509Store listedStore in stores)
                {
                    foreach (X509Certificate x509 in listedStore.Certificates)
                    {
                        DisplayCertificate(x509, machine, verbose);
                    }
                }
                break;
            case ObjectType.CRL:
                foreach (X509Store listedStore in stores)
                {
                    foreach (X509Crl crl in listedStore.Crls) 
                    {
                        DisplayCrl (crl, machine, verbose);
                    }
                }
                break;
            default:
                throw new NotSupportedException (type.ToString ());
            }
        }

        static X509CertificateCollection GetCertificatesFromSslSession (string url) 
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
            
        static void AddCertificatesFromSslSession (string host, bool machine, bool verbose) 
        {
            if (verbose) {
                Console.WriteLine ("Importing certificates from '{0}' into the {1} stores.",
                    host, machine ? "machine" : "user");
            }
            int addedCertificatesCount = 0;

            X509CertificateCollection sessionCertificates = GetCertificatesFromSslSession (host);

            if (sessionCertificates != null) {
                // start by the end (root) so we can stop adding them anytime afterward
                for (int i = sessionCertificates.Count - 1; i >= 0; i--) {
                    var prevCert = (i > 0) ? sessionCertificates[i - 1] : null;

                    ProcessSessionCertificate(sessionCertificates[i],prevCert,machine,verbose);
                }
            }

            Console.WriteLine ();
            if (addedCertificatesCount == 0) {
                Console.WriteLine ("No certificate were added to the stores.");
            } else {
                Console.WriteLine ("{0} certificate{1} added to the stores.", 
                    addedCertificatesCount, (addedCertificatesCount == 1) ? String.Empty : "s");
            }
        }

        private static bool ProcessSessionCertificate(X509Certificate certificate, X509Certificate prevCertificate, 
            bool machine, bool beVerbose)
        {
            bool isSelfSigned = false;
            bool failed = false;
            X509Store store = null;
            try {
                isSelfSigned = certificate.IsSelfSigned;
            }
            catch {
                // sadly it's hard to interpret old certificates with MD2
                // without manually changing the machine.config file
                failed = true;
            }

            if (isSelfSigned) {
                // this is a root
                store = GetStoreFromName (X509Stores.Names.TrustedRoot, machine);
            } else if (prevCertificate == null) {
                // server certificate isn't (generally) an intermediate CA
                store = GetStoreFromName (X509Stores.Names.OtherPeople, machine);
            } else {
                // all other certificates should be intermediate CA
                store = GetStoreFromName (X509Stores.Names.IntermediateCA, machine);
            }

            Console.WriteLine ("{0}{1}X.509 Certificate v{2}",     
                Environment.NewLine,
                isSelfSigned ? "Self-signed " : String.Empty,
                certificate.Version);
            Console.WriteLine ("   Issued from: {0}", certificate.IssuerName);
            Console.WriteLine ("   Issued to:   {0}", certificate.SubjectName);
            Console.WriteLine ("   Valid from:  {0}", certificate.ValidFrom);
            Console.WriteLine ("   Valid until: {0}", certificate.ValidUntil);

            if (!certificate.IsCurrent)
                Console.WriteLine ("   *** WARNING: Certificate isn't current ***");
            if ((prevCertificate != null) && !isSelfSigned) {
                X509Certificate signer = prevCertificate;
                bool isSigned = false;

                Console.WriteLine("Signature algorithm: " + CryptoHelper.HashAlgNameFromOid(certificate.SignatureAlgorithm));
                try {
                    if (signer.RSA != null) {
                        isSigned = certificate.VerifySignature (signer.RSA);
                    } else if (signer.DSA != null) {
                        isSigned = certificate.VerifySignature (signer.DSA);
                    } else {
                        Console.WriteLine ("   *** WARNING: Couldn't not find who signed this certificate ***");
                        isSigned = true; // skip next warning
                    }

                    if (!isSigned)
                        Console.WriteLine ("   *** WARNING: Certificate signature is INVALID ***");
                }
                catch {
                    failed = true;
                }
            }
            if (failed) {
                Console.WriteLine ("   *** ERROR: Couldn't decode certificate properly ***\n");
                //Console.WriteLine ("   *** try 'man certmgr' for additional help or report to bugzilla.novell.com ***");
                //throw new Exception("Certificate decoding failed");
                return false;
            }

            if (store.Certificates.Contains (certificate)) {
                Console.WriteLine ("This certificate is already in the {0} store.", store.Name);
            } else {
                Console.Write ("Import this certificate into the {0} store (Y/N)?", store.Name);
                string answer = Console.ReadLine ().ToUpper ();
                if ((answer == "YES") || (answer == "Y")) {
                    store.Import (certificate);
                    return true;
                } else {
                    if (beVerbose) {
                        Console.WriteLine ("Certificate not imported into store {0}.", 
                            store.Name);
                    }
                    //throw new Exception("");
                }
            }

            return false;
        }

        static void ImportKey (ObjectType type, bool machine, string file, string password, bool verbose)
        {
            switch (type) {
            case ObjectType.Certificate:
                X509CertificateCollection coll = LoadCertificates (file, password, verbose);
                int count = 0;

                foreach (X509Certificate x509 in coll) {
                    RSACryptoServiceProvider pk = x509.RSA as RSACryptoServiceProvider;

                    if (pk == null || pk.PublicOnly)
                        continue;

                    CspParameters csp = new CspParameters ();
                    csp.KeyContainerName = CryptoConvert.ToHex (x509.Hash);
                    csp.Flags = machine ? CspProviderFlags.UseMachineKeyStore : 0;
                    var rsa = new RSACryptoServiceProvider (csp);
                    rsa.ImportParameters (pk.ExportParameters (true));
                    rsa.PersistKeyInCsp = true;
                    count++;
                }
                Console.WriteLine ("{0} keys(s) imported to KeyPair {1} persister.", 
                    count, machine ? "LocalMachine" : "CurrentUser");
                break;
            default:
                throw new NotSupportedException (type.ToString ());
            }
        }

        static void ProcessMain(string[] args)
        {
            string password = null;
            bool verbose = false;
            bool isPem = false;
            bool isMachineCertificateStore = false;

            PrintVersion ();

            if (args.Length < 2) {
                PrintHelp ();
                return;
            }

            Action action = GetAction (args [0]);
            ObjectType objectType = ObjectType.None;

            int currentArgArrIndex = 1;
            if (action != Action.Ssl) {
                objectType = GetObjectType (args.GetArgumentByIndex(currentArgArrIndex, "object type"));

                //Console.WriteLine("Type:" + type.ToString());
                if (objectType != ObjectType.None)
                    currentArgArrIndex++;
            }

            //Console.WriteLine("curr:" + currentArgArrIndex + " " + args.Length);

            for (int i = currentArgArrIndex; i < args.Length; i++) {            
                string command = GetCommand(args.GetArgumentByIndex(i, "command"));
                switch (command) {
                    case "V":
                        verbose = true;
                        currentArgArrIndex++;
                        break;
                    case "M":
                        isMachineCertificateStore = true;
                        currentArgArrIndex++;
                        break;
                    case "P":
                        password = args.GetArgumentByIndex(currentArgArrIndex++, "password");
                        currentArgArrIndex++;
                        break;
                    case "PEM":
                        isPem = true;
                        currentArgArrIndex++;
                        break;
                }
            }

            X509Store store = null;
            string storeName = null;
            if (action != Action.Ssl) {
                if ((action == Action.None) || (objectType == ObjectType.None)) {
                    Console.WriteLine("Error: Unknown action or object type");
                    PrintHelp ();
                    return;
                }
                if (objectType == ObjectType.CTL) {
                    Console.WriteLine ("CTLs are not supported");
                    return;
                }

                bool isStoreNameOptional = (action == Action.List);
                storeName = args.GetArgumentByIndex(currentArgArrIndex++, "store name", isStoreNameOptional);
                store = GetStoreFromName (storeName, isMachineCertificateStore);
                Console.WriteLine("Store(s):" + ((storeName != null) ? storeName : 
                    "all (except untrusted)"));
                if (store == null && !isStoreNameOptional) {
                    Console.WriteLine ("Invalid Store: {0}", storeName);
                    PrintStores();
                    return;
                }
            }


            string file = null;
            if(action != Action.List)
                file = args.GetArgumentByIndex(currentArgArrIndex++, String.Format("path to {0}",objectType.ToString()));

            // now action!
            try {
                switch (action) {
                    case Action.Add:
                        Add (objectType, store, file, password, verbose);
                        break;
                    case Action.Delete:
                        Delete (objectType, store, file);
                        break;
                    case Action.Put:
                        Put (objectType, store, file, isMachineCertificateStore, isPem, verbose);
                        break;
                    case Action.List:
                        List (objectType, store, isMachineCertificateStore, verbose);
                        break;
                    case Action.Ssl:
                        AddCertificatesFromSslSession (file, isMachineCertificateStore, verbose);
                        break;
                    case Action.ImportKey:
                        ImportKey (objectType, isMachineCertificateStore, file, password, verbose);
                        break;
                    default:
                        throw new NotSupportedException (action.ToString ());
                }
            }
            catch (UnauthorizedAccessException uae) 
            {
                Console.WriteLine ("Access to the {0} '{1}' certificate store has been denied.", 
                    (isMachineCertificateStore ? "machine" : "user"), storeName);
                if (verbose) {
                    Console.WriteLine (uae);
                }
            }
        }

        [STAThread]
        public static void Main (string[] args)
        {
            try
            {
                ProcessMain(args);
            }
            catch(ArgumentException ae)
            {
                Console.WriteLine("Invalid arguments: " + ae.Message);
            }
            catch(SocketException s)
            {
                Console.WriteLine("Network error: " + s.Message);
            }
            catch(UriFormatException)
            {
                Console.WriteLine("Error: Invalid url");
            }
        }
    }
}
