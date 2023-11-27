using System;
using System.Collections;
using System.DirectoryServices.Protocols;

namespace SharpRODC.Modules.Objects
{
    internal class RODCAdmins : DACLSearch
    {
        public RODCAdmins(LdapSearch ldapSearch, string DistinguishedName) : base(ldapSearch, DistinguishedName)
        {
            base.ldapSearch = ldapSearch;
            base.DistinguishedName = DistinguishedName;
            base.returnAttributeList = new string[] { "distinguishedName", "nTSecurityDescriptor", "member" };
        }

        public override void Run()
        {
            ArrayList ADRulesList = SearchMothed();
            if (ADRulesList != null)
            {
                Utils.FormatOutput(DistinguishedName, ADRulesList);
            }

            SearchResultEntryCollection Entries = this.ldapSearch.GetSearchResultEntries(this.DistinguishedName, this.LdapFilter, this.Scope, this.returnAttributeList);
            foreach (SearchResultEntry entry in Entries)
            {
                foreach (byte[] member in entry.Attributes["member"])
                {
                    string manager = System.Text.Encoding.Default.GetString(member);
                    Console.WriteLine("    " + manager);
                    base.DistinguishedName = manager;
                    ADRulesList = SearchMothed();
                    if (ADRulesList != null)
                    {
                        Utils.FormatOutput(DistinguishedName, ADRulesList);
                    }
                }  
            }
        }
    }
}
