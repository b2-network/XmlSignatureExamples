// tool to sign an XML file



using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;

using System.Xml;
using CommandLine;
using CommandLine.Text;
using Egelke.EHealth.Client.Pki;
using IM.Xades;

namespace XmlSign
{
    public class Options
    {
        [Option('v', "verbose", Required = false, HelpText = "Set output to verbose messages.")]
        public bool Verbose { get; set; }

        [Option('i', "xmlin", Required = true, HelpText = "Set XML Input file name.")]
        public string? XmlInput { get; set; }

        [Option('o', "xmlout", Required = true, HelpText = "Set XML Output file name.")]
        public string? XmlOutput { get; set; }

        [Option('c', "cert", Required = true, HelpText = "Set pkcs#12 certificate file name.")]
        public string? Certificate { get; set; }

        [Option('p', "password", Required = false, HelpText = "Set pkcs#12 certificate password.")]
        public string? CertificatePassword { get; set; }

        [Usage(ApplicationAlias = "signerTool")]
        public static IEnumerable<Example> Examples =>
            new List<Example>()
            {
                new Example("sign input XML file, and save it to output",
                    new Options
                    {
                        XmlInput = "in.xml", XmlOutput = "out.xml", Certificate = "cert.p12",
                        CertificatePassword = "password"
                    })
            };
    }

    class SignerTool
    {
        static int Main(string[] args)
        {
            Console.WriteLine("XML Signing Tool, (c) B2 Network 2023");
            var result = Parser.Default.ParseArguments<Options>(args);
            var r = result.Value;
            if (r == null)
            {
                return 2;
            }

            var xmlIn = r.XmlInput;
            var xmlOut = r.XmlOutput;
            var cert = r.Certificate;
            var pass = Environment.GetEnvironmentVariable(@"PASSWORD") ?? r.CertificatePassword;

            if (!File.Exists(cert))
            {
                Console.WriteLine("Input certificate file not found: {0}", cert);
                Console.WriteLine("Current directory: {0}", Directory.GetCurrentDirectory());
                return 3;
            }

            if (null == pass)
            {
                pass = "";
            }

            if (!File.Exists(xmlIn))
            {
                Console.WriteLine("Input XML file not found: {0}", xmlIn);
                Console.WriteLine("Current directory: {0}", Directory.GetCurrentDirectory());
                return 2;
            }

            if (File.Exists(xmlOut))
            {
                Console.WriteLine("Output XML file exists");
                File.Delete(xmlOut);
            }

            var xmlDoc = LoadXml(xmlIn);
            xmlDoc.PreserveWhitespace = true;
           
            _ = SignXml(xmlDoc, cert, pass);
            if (null != xmlOut)
            {
                SaveXml(xmlDoc, xmlOut);
                Console.WriteLine("Saved XML into {0}/{1}", Directory.GetCurrentDirectory(), xmlOut);
            } else {
                Console.WriteLine("XML Not saved, missing --xmlout option");
            }
            return 0;
        }

        /// <summary>
        /// Return XML Document from File
        /// </summary>
        /// <param name="input">Xml Document filename</param>
        /// <returns>XmlDocument</returns>
        static XmlDocument LoadXml(string input)
        {
            var xmlDoc = new XmlDocument();
            var myXmlReader = new XmlTextReader(input);
            xmlDoc.Load(myXmlReader);
            return xmlDoc;
        }

        static void SaveXml(XmlDocument xml, string output)
        {
            var xmlTextWriter = new XmlTextWriter(output, null);
            xmlTextWriter.Formatting = Formatting.Indented;
            xml.WriteTo(xmlTextWriter);
            xmlTextWriter.Close();
        }

        // see https://www.glennwatson.net/posts/rfc-3161-signing
       
        static string stampURI = "http://timestamp.digicert.com/";
   
        static XmlDocument SignXml(XmlDocument xmlDoc, string certfile, string password)
        {
            var certificate = new X509Certificate2(certfile, password);
           
            var xades = new XadesCreator(certificate);

            xades.TimestampProvider = new Rfc3161TimestampProvider(new Uri(stampURI));
            xades.DataTransforms.Add(new XmlDsigBase64Transform());

            var xmlDigitalSignature = xades.CreateXadesT(xmlDoc);

            xmlDoc.DocumentElement?.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));

            return xmlDoc;
        }
    }
}