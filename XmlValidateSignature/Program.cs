// tool to sign an XML file


using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using CommandLine;
using CommandLine.Text;

namespace XmlSign
{
    public class Options
    {
        [Option('v', "verbose", Required = false, HelpText = "Set output to verbose messages.")]
        public bool Verbose { get; set; }

        [Option('i', "xml", Required = true, HelpText = "Set XML Input file name.")]
        public string? XmlInput { get; set; }
        
        [Option('r', "rsa", Required = true, HelpText = "RSA public key.")]
        public string? Certificate { get; set; }
        
        [Usage(ApplicationAlias = "signerValidateTool")]
        public static IEnumerable<Example> Examples =>
            new List<Example>()
            {
                new Example("validate input XML file",
                    new Options
                    {
                        XmlInput = "in.xml", Certificate = "cert.pem"
                    })
            };
    }

    static class SignerVerifierTool
    {
        static int Main(string[] args)
        {
            Console.WriteLine("XML Validation Tool, (c) B2 Network 2022");
            var result = Parser.Default.ParseArguments<Options>(args);
            var r = result.Value;
            if (r == null)
            {
                return 2;
            }

            var xml = r.XmlInput;
            var cert = r.Certificate;

            if (!File.Exists(cert))
            {
                Console.WriteLine("Public certificate file not found: {0}", cert);
                Console.WriteLine("Current directory: {0}", Directory.GetCurrentDirectory());
                return 3;
            }
            
            if (!File.Exists(xml))
            {
                Console.WriteLine("Input XML file not found: {0}", xml);
                Console.WriteLine("Current directory: {0}", Directory.GetCurrentDirectory());
                return 2;
            }
            
            var xmlDoc = LoadXml(xml);
            if (VerifyXml(xmlDoc, cert))
            {
                Console.WriteLine("XML was successfully verified");
            }
            else
            {
                Console.WriteLine("XML was NOT verified, content must not be trusted");
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
        
        static bool VerifyXml(XmlDocument xmlDoc, string cert)
        {
            var certificate = new X509Certificate2(cert);
            var key = certificate.GetRSAPublicKey();
            
            // create a signedXML and load xml doc
            var signedXml = new SignedXml(xmlDoc);
            
            // Find the "Signature" node
            XmlNodeList nodeList = xmlDoc.GetElementsByTagName("Signature");

            if (nodeList.Count <= 0)
            {
                throw new CryptographicException("Verification Failed, no signature found in document");
            }

            if (nodeList.Count >= 2)
            {
                throw new CryptographicException("Verification Failed, too many signatures found in document");
            }
            
            signedXml.LoadXml((XmlElement)nodeList[0]);
            return signedXml.CheckSignature(key);
        }
    }
}