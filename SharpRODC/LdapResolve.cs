/*
 Author:     WHOAMI
 Blog:       https://whoamianony.top/
 Twitter:    @wh0amitz
 Modules:    Resolve GUIDs to display name, such as SchemaObjectGUID, ExtendedRight, etc
*/
using System.Collections.Generic;
using System.Security.Principal;

namespace SharpRODC
{
    internal class LdapResolve
    {
        LdapSearch ldapSearch;
        public LdapResolve(LdapSearch ldapSearch)
        {
            this.ldapSearch = ldapSearch;
        }

        public string ResolveSchemaObjectGUID(string Guid)
        {
            Dictionary<string, string> SchemaObjectsList = new Dictionary<string, string>
            {
                { "00000000-0000-0000-0000-000000000000", "All" }
            };

            // Active Directory includes predefined property sets:
            // https://docs.microsoft.com/en-us/windows/desktop/adschema/property-sets
            Dictionary<string, string> PropertySetsList = new Dictionary<string, string>
            {
                {"72e39547-7b18-11d1-adef-00c04fd8d5cd", "DNS-Host-Name-Attributes"},
                {"b8119fd0-04f6-4762-ab7a-4986c76b3f9a", "Domain-Other-Parameters"},
                {"c7407360-20bf-11d0-a768-00aa006e0529", "Domain-Password"},
                {"e45795b2-9455-11d1-aebd-0000f80367c1", "Email-Information"},
                {"59ba2f42-79a2-11d0-9020-00c04fc2d3cf", "Email-Information"},
                {"bc0ac240-79a9-11d0-9020-00c04fc2d4cf", "Membership"},
                {"ffa6f046-ca4b-4feb-b40d-04dfee722543", "MS-TS-GatewayAccess"},
                {"77b5b886-944a-11d1-aebd-0000f80367c1", "Personal-Information"},
                {"91e647de-d96f-4b70-9557-d63ff4f3ccd8", "Private-Information"},
                {"e48d0154-bcf8-11d1-8702-00c04fb96050", "Public-Information"},
                {"5805bc62-bdc9-4428-a5e2-856a0f4c185e", "Terminal-Server-License-Server"},
                {"4c164200-20c0-11d0-a768-00aa006e0529", "User-Account-Restrictions"},
                {"5f202010-79a5-11d0-9020-00c04fc2d4cf", "User-Logon"},
                {"e45795b3-9455-11d1-aebd-0000f80367c1", "Web-Information"},
                {"9b026da6-0d3c-465c-8bee-5199d7165cba", "DS-Validated-Write-Computer"},
                {"037088f8-0ae1-11d2-b422-00a0c968f939", "RAS-Information"},
                {"1f298a89-de98-47b8-b5cd-572ad53d267e", "Exchange-Information"}
            };

            if (SchemaObjectsList.ContainsKey(Guid))
            {
                return SchemaObjectsList[Guid];
            }
            else if (PropertySetsList.ContainsKey(Guid))
            {
                return PropertySetsList[Guid];
            }
            else
            {
                return this.ldapSearch.GetNameBySchemaGUID(Guid);
            }
        }

        public string ResolveExtendedRightGUID(string Guid)
        {
            Dictionary<string, string> ExtendedRightsList = new Dictionary<string, string>
            {
                {"00000000-0000-0000-0000-000000000000", "All"}

            };

            if (ExtendedRightsList.ContainsKey(Guid))
            {
                return ExtendedRightsList[Guid];
            }
            else
            {
                return this.ldapSearch.GetExtendedRightByRightsGUID(Guid);
            }
        }

        public string ResolveSIDToName(string Sid)
        {
            Dictionary<string, string> UniversalWellKnownSIDs = new Dictionary<string, string>
            {
                {"S-1-1-0", "Everyone"},
                {"S-1-5-7", "Anonymous"},
                {"S-1-5-10", "Principal Self"},
                {"S-1-5-11", "Authenticated Users"},
                {"S-1-5-32-545", "Users"},
                {"S-1-5-32-546", "Guests"},
                {"S-1-5-32-580", "BUILTIN\\Remote Management Users"},
            };

            if (UniversalWellKnownSIDs.ContainsKey(Sid))
            {
                return UniversalWellKnownSIDs[Sid];
            }
            else
            {
                int rid = int.Parse(Sid.Substring(Sid.LastIndexOf('-') + 1));

                if (rid < 1000)
                {
                    return null;
                }

                try
                {
                    // https://stackoverflow.com/questions/499053/how-can-i-convert-from-a-sid-to-an-account-name-in-c-sharp
                    return new SecurityIdentifier(Sid).Translate(typeof(NTAccount)).ToString();
                }
                catch
                {
                    return (string)this.ldapSearch.GetSingleAttributeValue(this.ldapSearch.RootDN, $"(objectSid={Sid})", "name");
                }
            }
        }
    }
}
