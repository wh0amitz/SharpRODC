/*
 Author:     WHOAMI
 Blog:       https://whoamianony.top/
 Twitter:    @wh0amitz
 Modules:    Check DACLs for domain object
*/
using System;
using System.Collections;
using System.DirectoryServices.Protocols;

namespace SharpRODC.Modules.Objects
{
    internal class DomainPartition : DACLSearch
    {
        public DomainPartition(LdapSearch ldapSearch, ArrayList RodcLists) : base(ldapSearch, RodcLists)
        {
            base.ldapSearch = ldapSearch;
            base.DistinguishedName = this.ldapSearch.RootDN;
            base.SecurityIdentifierList = RodcLists;
            base.returnAttributeList = new string[] { "distinguishedName", "objectSid", "nTSecurityDescriptor" };
        }

        public override void Run()
        {
            Console.WriteLine("[*] " + this.DistinguishedName);
            SearchResultEntryCollection Entries = this.ldapSearch.GetSearchResultEntries("CN=Enterprise Read-only Domain Controllers,CN=Users," + this.DistinguishedName, this.LdapFilter, this.Scope, this.returnAttributeList);
            foreach (SearchResultEntry entry in Entries)
            {
                this.SecurityIdentifierList.Add(entry.Attributes["objectSid"][0]);
            }

            Entries = this.ldapSearch.GetSearchResultEntries("CN=Read-only Domain Controllers,CN=Users," + this.DistinguishedName, this.LdapFilter, this.Scope, this.returnAttributeList);
            foreach (SearchResultEntry entry in Entries)
            {
                this.SecurityIdentifierList.Add(entry.Attributes["objectSid"][0]);
            }

            ArrayList ADRulesList = SearchMothed();
            if (ADRulesList != null)
            {
                Utils.FormatOutput(DistinguishedName, ADRulesList);
            }
        }
    }
}
