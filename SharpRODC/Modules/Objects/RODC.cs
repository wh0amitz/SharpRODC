/*
 Author:     WHOAMI
 Blog:       https://whoamianony.top/
 Twitter:    @wh0amitz
 Modules:    Check DACLs for sensitive Domain Controllers Objects
*/
using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;

namespace SharpRODC.Modules.Objects
{
    internal class RODC
    {
        protected LdapSearch ldapSearch;
        protected string DistinguishedName;
        protected string LdapFilter = "(primaryGroupID=521)";
        protected SearchScope Scope = SearchScope.OneLevel;
        protected string[] returnAttributeList = new string[] {
            "distinguishedName",
            "objectSid",
            "nTSecurityDescriptor",
            "managedBy",
            "msDS-KrbTgtLink",
            "msDS-RevealOnDemandGroup",
            "msDS-NeverRevealGroup",
            "msDS-RevealedList"
        };

        public RODC(LdapSearch ldapSearch)
        {
            this.ldapSearch = ldapSearch;
            this.DistinguishedName = "OU=Domain Controllers," + this.ldapSearch.RootDN;
        }

        public ArrayList Run()
        {
            SearchResultEntryCollection Entries = this.ldapSearch.GetSearchResultEntries(this.DistinguishedName, this.LdapFilter, this.Scope, this.returnAttributeList);
            DACLSearch dACLSearch = new DACLSearch(this.ldapSearch);
            ArrayList RodcLists = new ArrayList();
            int count = 1;

            Console.WriteLine($"[*] {Entries.Count} RODCs found");

            foreach (SearchResultEntry entry in Entries)
            {
                Console.WriteLine($"\n>>> ------------------------------------ RODC {count} ------------------------------------ <<<\n");
                Console.WriteLine("[*] Read-Only Domain Controllers: \n");

                string rodc = entry.Attributes["distinguishedName"][0].ToString();
                RodcLists.Add(entry.Attributes["objectSid"][0]);
                Console.WriteLine("    " + rodc);
                dACLSearch.DistinguishedName = rodc;
                dACLSearch.Run();

                Console.WriteLine("[*] managedBy: \n");

                if (entry.Attributes.Contains("managedBy"))
                {
                    foreach (byte[] manageby in entry.Attributes["managedBy"])
                    {
                        string manager = System.Text.Encoding.Default.GetString(manageby);
                        Console.WriteLine("    " + manager);

                        DACLSearch rodcAdmins = new RODCAdmins(ldapSearch, manager);
                        rodcAdmins.Run();
                    }
                }
               
                Console.WriteLine("[*] Krbtgt Account: \n");

                if (entry.Attributes.Contains("msDS-KrbTgtLink"))
                {
                    Console.WriteLine("    " + entry.Attributes["msDS-KrbTgtLink"][0].ToString());
                }
                    
                Console.WriteLine("\n[*] msDS-RevealOnDemandGroup: \n");

                if (entry.Attributes.Contains("msDS-RevealOnDemandGroup"))
                {
                    foreach (byte[] reveal in entry.Attributes["msDS-RevealOnDemandGroup"])
                    {
                        Console.WriteLine("    " + System.Text.Encoding.Default.GetString(reveal));
                    }
                }
                

                Console.WriteLine("\n[*] msDS-NeverRevealGroup: \n");

                if (entry.Attributes.Contains("msDS-NeverRevealGroup"))
                {
                    foreach (byte[] never in entry.Attributes["msDS-NeverRevealGroup"])
                    {
                        Console.WriteLine("    " + System.Text.Encoding.Default.GetString(never));
                    }
                }

                Console.WriteLine("\n[*] msDS-RevealedList: \n");

                if (entry.Attributes.Contains("msDS-RevealedList"))
                {
                    List<string> RevealedLists = new List<string>();

                    foreach (byte[] revealed in entry.Attributes["msDS-RevealedList"])
                    {
                        string RevealedStr = System.Text.Encoding.Default.GetString(revealed);

                        RevealedLists.Add(RevealedStr.Substring(RevealedStr.LastIndexOf(':') + 1));
                    }

                    HashSet<string> RevealedSet = new HashSet<string>(RevealedLists);
                    foreach (var c in RevealedSet)
                    {
                        Console.WriteLine("    " + c);
                    }
                }

                count += 1;
            }

            return RodcLists;
        }
    }
}
