using System;
using System.Collections;

namespace SharpRODC.Modules.Objects
{
    internal class AllowedReplicationGroup : DACLSearch
    {
        public AllowedReplicationGroup(LdapSearch ldapSearch) : base(ldapSearch)
        {
            base.ldapSearch = ldapSearch;
            base.DistinguishedName = "CN=Allowed RODC Password Replication Group,CN=Users," + this.ldapSearch.RootDN;
        }

        public override void Run()
        {
            Console.WriteLine("\n[*] " + this.DistinguishedName);
            ArrayList ADRulesList = SearchMothed("user");
            if (ADRulesList != null)
            {
                Utils.FormatOutput(DistinguishedName, ADRulesList);
            }
        }
    }
}
