using System;
using System.Collections;

namespace SharpRODC.Modules.Objects
{
    internal class DeniedReplicationGroup : DACLSearch
    {
        public DeniedReplicationGroup(LdapSearch ldapSearch) : base(ldapSearch)
        {
            base.ldapSearch = ldapSearch;
            base.DistinguishedName = "CN=Denied RODC Password Replication Group,CN=Users," + this.ldapSearch.RootDN;
        }

        public override void Run()
        {
            Console.WriteLine("[*] " + this.DistinguishedName);
            ArrayList ADRulesList = SearchMothed("user");
            if (ADRulesList != null)
            {
                Utils.FormatOutput(DistinguishedName, ADRulesList);
            }
        }
    }
}
