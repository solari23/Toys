using System;
using System.Security;
using System.Text;

namespace CredentialManager
{
    class Program
    {
        static void Main(string[] args)
        {
            using (CredentialManager credMan = new CredentialManager("foo.db"))
            {
                credMan.LoadCredentialsDatabase();
                credMan.AccrueCredentialFromConsole("jack");

                Console.WriteLine(credMan.GenerateTokenForCredential("jack", ss => SecureStringToString(ss)));
                credMan.SaveCredentialsToDatabase();
            }

            using (CredentialManager credMan = new CredentialManager("foo.db"))
            {
                credMan.LoadCredentialsDatabase();
                Console.WriteLine(credMan.GenerateTokenForCredential("jack", ss => SecureStringToString(ss)));
            }

            Console.ReadKey(true);
        }

        static string SecureStringToString(SecureString ss)
        {
            // This is technically breaching the security of the credential manager. Unfortunately,
            // a plaintext password is strictly required for some applications (basic auth).
            //
            IntPtr bstrCredential = System.Runtime.InteropServices.Marshal.SecureStringToBSTR(ss);
            string plaintextCredential = System.Runtime.InteropServices.Marshal.PtrToStringBSTR(bstrCredential);
            System.Runtime.InteropServices.Marshal.ZeroFreeBSTR(bstrCredential);
            return plaintextCredential;
        }
    }
}
