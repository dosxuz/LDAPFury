using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices;

namespace LDAPFury
{
    internal class Program
    {
        static void Main(string[] args)
        {
            //object properties domain 

            DirectoryEntry de = new DirectoryEntry("LDAP://RootDSE");
            string rootldap = "LDAP://" + de.Properties["defaultNamingContext"][0].ToString();

            DirectoryEntry d = new DirectoryEntry(rootldap);
            DirectorySearcher ds = new DirectorySearcher(d);
            ds.Filter = args[0];
            string[] properties = args[1].Split(',');
            foreach (string i in properties)
            {
                ds.PropertiesToLoad.Add(i.ToLower());
            }
            try
            {
                SearchResultCollection results = ds.FindAll();
                if (results.Count > 0)
                {
                    foreach (SearchResult result in results)
                    {
                        foreach (string i in properties)
                        {
                            if (result.Properties[i.ToLower()].Count > 0)
                            {
                                var prop = result.Properties[i.ToLower()][0];
                                Type tp = prop.GetType();
                                if (tp.Equals(typeof(string)))
                                {
                                    Console.WriteLine(i + " : " + prop.ToString());
                                }
                                else if (tp.Equals(typeof(byte[])) && i.ToLower().Contains("sid"))
                                {
                                    byte[] bytearray = (byte[])prop;
                                    string bytestring = ConvertByteToStringSid(bytearray);
                                    Console.WriteLine(i + " : " + bytestring);
                                }
                                else if (tp.Equals(typeof(byte[])) && i.ToLower().Contains("guid"))
                                {
                                    byte[] binaryData = prop as byte[];
                                    string strHex = BitConverter.ToString(binaryData);
                                    Guid id = new Guid(strHex.Replace("-", ""));
                                    Console.WriteLine(i + " : " + id.ToString());
                                }
                                else
                                {
                                    Console.WriteLine(i + " : " + prop.ToString());
                                }
                            }
                            else
                                Console.WriteLine(i + " : " + "Not Found");
                        }
                        Console.WriteLine();
                        Console.WriteLine("------------------------------------------");
                        Console.WriteLine();
                    }
                }
                else
                {
                    Console.WriteLine("No result found");
                }
            }
            catch (ArgumentException e)
            {
                if (e.ToString().Contains("search filter is invalid"))
                {
                    Console.WriteLine("Invalid LDAP Query");
                }
            }
        }

        public static string ConvertByteToStringSid(Byte[] sidBytes)
        {
            StringBuilder strSid = new StringBuilder();
            strSid.Append("S-");
            try
            {
                // Add SID revision.
                strSid.Append(sidBytes[0].ToString());
                // Next six bytes are SID authority value.
                if (sidBytes[6] != 0 || sidBytes[5] != 0)
                {
                    string strAuth = String.Format
                        ("0x{0:2x}{1:2x}{2:2x}{3:2x}{4:2x}{5:2x}",
                        (Int16)sidBytes[1],
                        (Int16)sidBytes[2],
                        (Int16)sidBytes[3],
                        (Int16)sidBytes[4],
                        (Int16)sidBytes[5],
                        (Int16)sidBytes[6]);
                    strSid.Append("-");
                    strSid.Append(strAuth);
                }
                else
                {
                    Int64 iVal = (Int32)(sidBytes[1]) +
                        (Int32)(sidBytes[2] << 8) +
                        (Int32)(sidBytes[3] << 16) +
                        (Int32)(sidBytes[4] << 24);
                    strSid.Append("-");
                    strSid.Append(iVal.ToString());

                    // Get sub authority count...
                    int iSubCount = Convert.ToInt32(sidBytes[7]);
                    int idxAuth = 0;
                    for (int i = 0; i < iSubCount; i++)
                    {
                        idxAuth = 8 + i * 4;
                        UInt32 iSubAuth = BitConverter.ToUInt32(sidBytes, idxAuth);
                        strSid.Append("-");
                        strSid.Append(iSubAuth.ToString());
                    }
                }
            }
            catch (Exception ex)
            {

            }
            return strSid.ToString();
        }
    }
}

//.\LDAPFury.exe "(&(objectCategory=user))" "name,CN,lastLogon,logonCount,description,objectClass,objectSid,adminCount,ADSPath,ObjectCategory,memberof,instanceType,mail"