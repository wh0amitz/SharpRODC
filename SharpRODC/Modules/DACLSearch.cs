/*
 Author:     WHOAMI
 Blog:       https://whoamianony.top/
 Twitter:    @wh0amitz
 Modules:    Search module, which will be inherited by other function modules
*/
using System;
using System.DirectoryServices;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace SharpRODC.Modules
{
    internal class DACLSearch
    {
        public LdapSearch ldapSearch;
        public string DistinguishedName;
        public string LdapFilter = "(objectClass=*)";
        public string[] returnAttributeList = new string[] { "distinguishedName", "nTSecurityDescriptor" };
        public ArrayList SecurityIdentifierList = null;
        public System.DirectoryServices.Protocols.SearchScope Scope = System.DirectoryServices.Protocols.SearchScope.Base;

        public DACLSearch(LdapSearch ldapSearch)
        {
            this.ldapSearch = ldapSearch;
        }

        public DACLSearch(LdapSearch ldapSearch, string DistinguishedName)
        {
            this.ldapSearch = ldapSearch;
            this.DistinguishedName = DistinguishedName;
        }

        public DACLSearch(LdapSearch ldapSearch, ArrayList SecurityIdentifierList)
        {
            this.ldapSearch = ldapSearch;
            this.SecurityIdentifierList = SecurityIdentifierList;
        }

        virtual public void Run()
        {
            ArrayList ADRulesList = SearchMothed();
            if (ADRulesList != null)
            {
                Utils.FormatOutput(DistinguishedName, ADRulesList);
            }
        }
        
        public ArrayList SearchMothed(string SearchType = "rodc")
        {
            LdapResolve ldapResolve = new LdapResolve(this.ldapSearch);
            SearchResultEntryCollection Entries = this.ldapSearch.GetSearchResultEntries(this.DistinguishedName, this.LdapFilter, this.Scope, this.returnAttributeList);
            ArrayList ADRulesList = new ArrayList();

            foreach (SearchResultEntry entry in Entries)
            {
                try
                {
                    ActiveDirectorySecurity ADSecurityDescriptor = new ActiveDirectorySecurity();
                    ADSecurityDescriptor.SetSecurityDescriptorBinaryForm((Byte[])entry.Attributes["nTSecurityDescriptor"][0]);
                    AuthorizationRuleCollection AccessRules = ADSecurityDescriptor.GetAccessRules(true, true, typeof(SecurityIdentifier));

                    foreach (ActiveDirectoryAccessRule ADRule in AccessRules)
                    {
                        string ObjectDN = entry.Attributes["distinguishedName"][0].ToString();
                        string AccessControlType = ADRule.AccessControlType.ToString();
                        string ActiveDirectoryRights = ADRule.ActiveDirectoryRights.ToString();
                        string IdentityReference = null;
                        string securityIdentifier = null;

                        if (
                            !Regex.IsMatch(ADRule.ActiveDirectoryRights.ToString(), @"(GenericAll)") &&
                            !Regex.IsMatch(ADRule.ActiveDirectoryRights.ToString(), @"(GenericWrite)") &&
                            !Regex.IsMatch(ADRule.ActiveDirectoryRights.ToString(), @"(WriteProperty)") &&
                            !Regex.IsMatch(ADRule.ActiveDirectoryRights.ToString(), @"(WriteDacl)") &&
                            !Regex.IsMatch(ADRule.ActiveDirectoryRights.ToString(), @"(WriteOwner)") &&
                            !Regex.IsMatch(ADRule.ActiveDirectoryRights.ToString(), @"(ExtendedRight)")
                        )
                        {
                            continue;
                        }

                        string ObjectType = "";

                        if (Regex.IsMatch(ADRule.ActiveDirectoryRights.ToString(), @"(ExtendedRight)"))
                        {
                            ObjectType = ldapResolve.ResolveExtendedRightGUID(ADRule.ObjectType.ToString());
                            if (string.IsNullOrEmpty(ObjectType))
                            {
                                continue;
                            }
                        }
                        else
                        {
                            ObjectType = ldapResolve.ResolveSchemaObjectGUID(ADRule.ObjectType.ToString());
                            if (string.IsNullOrEmpty(ObjectType))
                            {
                                continue;
                            }
                        }

                        string ObjectTypeGuid = ADRule.ObjectType.ToString();

                        if(SecurityIdentifierList != null)
                        {
                            foreach (byte[] s in SecurityIdentifierList)
                            {
                                SecurityIdentifier sid = new SecurityIdentifier((byte[])s, 0);

                                if (sid.Value.ToString() == ADRule.IdentityReference.ToString())
                                {
                                    IdentityReference = ldapResolve.ResolveSIDToName(ADRule.IdentityReference.ToString());
                                    securityIdentifier = ADRule.IdentityReference.ToString();
                                }
                            }
                        }
                        else
                        {
                            IdentityReference = ldapResolve.ResolveSIDToName(ADRule.IdentityReference.ToString());
                            securityIdentifier = ADRule.IdentityReference.ToString();
                        }
                        
                        if (string.IsNullOrEmpty(IdentityReference))
                        {
                            continue;
                        }

                        Dictionary<string, string> ADRulePropertiesDict = new Dictionary<string, string>();
                        ADRulePropertiesDict.Add("ObjectDN", ObjectDN);
                        ADRulePropertiesDict.Add("AccessControlType", AccessControlType);
                        ADRulePropertiesDict.Add("ActiveDirectoryRights", ActiveDirectoryRights);
                        ADRulePropertiesDict.Add("ObjectType", ObjectType);
                        ADRulePropertiesDict.Add("ObjectTypeGuid", ObjectTypeGuid);
                        ADRulePropertiesDict.Add("IdentityReference", IdentityReference);
                        ADRulePropertiesDict.Add("SecurityIdentifier", securityIdentifier);

                        ADRulesList.Add(ADRulePropertiesDict);
                    }
                }
                catch (Exception ex)
                {
                    // Do nothing here!
                    Console.WriteLine(ex.ToString());
                }
            }

            return ADRulesList;
        }
    }
}
