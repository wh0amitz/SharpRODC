/*
 Author:     WHOAMI
 Blog:       https://whoamianony.top/
 Twitter:    @wh0amitz
 Modules:    Connect to Active Directory, perform LDAP search operations, etc
*/
using System;
using System.Net;
using System.DirectoryServices;
using System.Text.RegularExpressions;
using System.DirectoryServices.Protocols;
using System.Security.Cryptography.X509Certificates;
using System.DirectoryServices.ActiveDirectory;

namespace SharpRODC
{
    internal class LdapSearch
    {
        public string DomainName;
        public string Server;
        public int PortNumber;
        public string Username;
        public string Password;

        public string RootDN;
        public string ConfigDN;
        public string SchemaDN;

        public LdapConnection connection;

        public LdapSearch(string DomainName, string Server, int PortNumber, string Username, string Password)
        {
            if (String.IsNullOrEmpty(DomainName))
            {
                System.DirectoryServices.ActiveDirectory.Domain domain = System.DirectoryServices.ActiveDirectory.Domain.GetComputerDomain();
                this.DomainName = domain.Name.ToLower();
                Console.WriteLine($"[*] Get the domain name: {this.DomainName}");
                this.Server = domain.PdcRoleOwner.Name;
                Console.WriteLine($"[*] Get the domain controller: {this.Server}");

                DirectoryEntry RootDSE = GetDirectoryEntry("RootDSE");
                this.RootDN = RootDSE.Properties["defaultNamingContext"].Value.ToString();
                this.ConfigDN = RootDSE.Properties["configurationNamingContext"].Value.ToString();
                this.SchemaDN = RootDSE.Properties["schemaNamingContext"].Value.ToString();
            }
            else
            {
                this.DomainName = DomainName;
                Console.WriteLine($"[*] Get the domain name: {this.DomainName}");
                
                if (String.IsNullOrEmpty(Server))
                {
                    Domain domain = System.DirectoryServices.ActiveDirectory.Domain.GetDomain(new DirectoryContext(DirectoryContextType.Domain, this.DomainName));
                    this.Server = domain.PdcRoleOwner.Name;
                }
                else
                {
                    this.Server = Server;
                }

                Console.WriteLine($"[*] Get the domain controller: {this.Server}");
                foreach (String DC in this.DomainName.Split('.'))
                {
                    this.RootDN += ",DC=" + DC;
                }
                this.RootDN = this.RootDN.TrimStart(',');
                this.ConfigDN = "CN=Configuration," + this.RootDN;
                this.SchemaDN = "CN=Schema,CN=Configuration," + this.RootDN;
            }

            this.PortNumber = PortNumber;
            this.Username = Username;
            this.Password = Password;

            ActiveDirectoryConnection(this.Server, this.PortNumber);
        }

        private void ActiveDirectoryConnection(string server, int PortNumber)
        {
            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(server, PortNumber);
            LdapConnection connection = new LdapConnection(identifier);

            if (!String.IsNullOrEmpty(this.Username) && !String.IsNullOrEmpty(this.Password))
            {
                NetworkCredential credentials = new NetworkCredential(this.Username, this.Password, this.DomainName);
                connection.Credential = credentials;
                connection.AuthType = AuthType.Negotiate;
            }
            else
            {
                connection.SessionOptions.Sealing = true;
                connection.SessionOptions.Signing = true;
                connection.Bind();
            }

            this.connection = connection;
        }

        private DirectoryEntry GetDirectoryEntry(string dn)
        {
            try
            {
                return new DirectoryEntry($"LDAP://{this.Server}:{this.PortNumber}/{dn}");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
                return null;
            }
        }

        public SearchResultEntryCollection GetSearchResultEntries(string distinguishedName, string ldapFilter, System.DirectoryServices.Protocols.SearchScope searchScope, string[] attributeList)
        {
            SearchRequest searchRequest = new SearchRequest(distinguishedName, ldapFilter, searchScope, attributeList);
            // The SecurityDescriptorFlagControl class is used to pass flags to the server to control various security descriptor behaviors.
            searchRequest.Controls.Add(new SecurityDescriptorFlagControl(System.DirectoryServices.Protocols.SecurityMasks.Dacl));
            SearchResponse searchResponse = (SearchResponse)this.connection.SendRequest(searchRequest);
            return searchResponse.Entries;
        }

        public object GetSingleAttributeValue(string distinguishedName, string ldapFilter, string attribute)
        {
            string[] returnAttributeList = new string[] { attribute };
            SearchResultEntryCollection Entries = GetSearchResultEntries(distinguishedName, ldapFilter, System.DirectoryServices.Protocols.SearchScope.Base, returnAttributeList);
            SearchResultEntry entry = Entries[0];
            return entry.Attributes[attribute][0];
        }

        public string GetNameBySchemaGUID(string Guid)
        {
            string encodeGuid = Regex.Replace(Guid.Replace("-", ""), "(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})", @"\$4\$3\$2\$1\$6\$5\$8\$7\$9\$10\$11\$12\$13\$14\$15\$16").Replace("\"", "");
            string[] returnAttributeList = new string[] { "lDAPDisplayName" };

            SearchResultEntryCollection Entries = GetSearchResultEntries(this.ConfigDN, $"(schemaIDGUID={encodeGuid})", System.DirectoryServices.Protocols.SearchScope.Subtree, returnAttributeList);
            foreach (SearchResultEntry entry in Entries)
            {
                try
                {
                    return entry.Attributes["lDAPDisplayName"][0].ToString();
                }
                catch
                {
                    // Do nothing here!
                }
            }
            return Guid;
        }

        public string GetExtendedRightByRightsGUID(string Guid)
        {
            string[] returnAttributeList = new string[] { "cn" };

            SearchResultEntryCollection Entries = GetSearchResultEntries($"CN=Extended-Rights,{this.ConfigDN}", $"(rightsGuid={Guid})", System.DirectoryServices.Protocols.SearchScope.Subtree, returnAttributeList);
            foreach (SearchResultEntry entry in Entries)
            {
                try
                {
                    return entry.Attributes["cn"][0].ToString();
                }
                catch (Exception e)
                {
                    return e.ToString();
                }
            }
            return Guid;
        }
    }
}
