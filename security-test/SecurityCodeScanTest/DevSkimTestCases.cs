// INTENTIONALLY VULNERABLE CODE — DO NOT MERGE TO MAIN.
//
// Purpose: validate DevSkim's detection rate against known-bad patterns
// before deciding whether to adopt it in the Link.Cloud pipeline.
// Each method plants exactly one vulnerability class DevSkim's default
// ruleset is documented to detect. Delete this file once the comparison
// against Semgrep/Roslyn/SecurityCodeScan is done.
//
// Tracking: see security-test/RESULTS.md for the expected-vs-found checklist.

using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Xml;

namespace SecurityTest
{
    public class DevSkimTestCases
    {
        // 1. Hardcoded credentials
        private const string DbPassword = "P@ssw0rd123!";
        private static readonly string ApiKey = "hardcoded-api-key-not-a-real-secret-1234567890";

        // 2. Weak / broken hashing (MD5, SHA1 for security-sensitive use)
        public string HashPassword(string password)
        {
            using var md5 = MD5.Create();
            var bytes = md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            return Convert.ToBase64String(bytes);
        }

        // 3. Insecure randomness for a security token
        public string GenerateResetToken()
        {
            var rnd = new Random();
            return rnd.Next(100000, 999999).ToString();
        }

        // 4. SQL injection via raw string concatenation
        public void GetUserByName(string username)
        {
            var conn = new SqlConnection("Server=.;Database=eShop;Trusted_Connection=True;");
            var cmd = new SqlCommand("SELECT * FROM Users WHERE Username = '" + username + "'", conn);
            conn.Open();
            cmd.ExecuteReader();
        }

        // 5. Command injection
        public void PingHost(string userSuppliedHost)
        {
            var psi = new ProcessStartInfo("cmd.exe", "/c ping " + userSuppliedHost);
            Process.Start(psi);
        }

        // 6. Path traversal
        public string ReadUserFile(string fileName)
        {
            return File.ReadAllText("C:\\uploads\\" + fileName);
        }

        // 7. Insecure deserialization
        public object DeserializeUserData(byte[] data)
        {
            var formatter = new BinaryFormatter();
            using var ms = new MemoryStream(data);
            return formatter.Deserialize(ms);
        }

        // 8. XXE — XmlDocument with external entities not disabled
        public void LoadXmlFromUser(string xmlContent)
        {
            var doc = new XmlDocument();
            doc.XmlResolver = new XmlUrlResolver();
            doc.LoadXml(xmlContent);
        }

        // 9. Disabled TLS certificate validation
        public void CallInsecureEndpoint()
        {
            ServicePointManager.ServerCertificateValidationCallback =
                (sender, cert, chain, errors) => true;
        }

        // 10. Weak/obsolete TLS protocol pinned explicitly
        public void ForceOldTls()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3;
        }
    }
}
