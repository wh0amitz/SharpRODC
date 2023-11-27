/*
 Author:     WHOAMI
 Blog:       https://whoamianony.top/
 Twitter:    @wh0amitz
 Modules:    Utils used by the project, including result output, threat rating, etc
*/
using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace SharpRODC
{
    internal class Utils
    {
        static string Severity;
        static string ObjectDN;
        static string AccessControlType;
        static string ActiveDirectoryRights;
        static string ObjectType;
        static string ObjectTypeGuid;
        static string SecurityIdentifier;
        static string IdentityReference;

        static int SeverityLevel;
        static string SeverityLevelString;

        static ArrayList ADRulesList;
        public static void FormatOutput(string distinguishedName, ArrayList rulesList)
        {
            ADRulesList = rulesList;

            Console.WriteLine();

            //Console.WriteLine($"[*] Generate a raw report of the results.\n");

            foreach (Dictionary<string, string> ADRulePropertiesDict in ADRulesList)
            {
                ObjectDN = ADRulePropertiesDict["ObjectDN"];
                AccessControlType = ADRulePropertiesDict["AccessControlType"];
                ActiveDirectoryRights = ADRulePropertiesDict["ActiveDirectoryRights"];
                ObjectType = ADRulePropertiesDict["ObjectType"];
                ObjectTypeGuid = ADRulePropertiesDict["ObjectTypeGuid"];
                IdentityReference = ADRulePropertiesDict["IdentityReference"];
                SecurityIdentifier = ADRulePropertiesDict["SecurityIdentifier"];

                GetRightsSeverity();
                // Launch filter Severity
                if (!String.IsNullOrEmpty(Severity) && SeverityLevelString != Severity)
                {
                    RightsSeverityFree();
                    continue;
                }

                SelectOutputColor();

                string ObjectDNOutput = "    ObjectDN ".PadRight(26, ' ') + ": " + ObjectDN;
                Console.WriteLine(ObjectDNOutput.Length > 102 ? ObjectDNOutput.Insert(105, "\n                         ") : ObjectDNOutput);
                Console.WriteLine("    AccessControlType ".PadRight(26, ' ') + ": " + AccessControlType);
                string ActiveDirectoryRightsOutput = "    ActiveDirectoryRights ".PadRight(26, ' ') + ": " + ActiveDirectoryRights;
                Console.WriteLine(ActiveDirectoryRightsOutput.Length > 105 ? ActiveDirectoryRightsOutput.Insert(105, "\n                         ") : ActiveDirectoryRightsOutput);
                Console.WriteLine("    ObjectType ".PadRight(26, ' ') + ": " + ObjectType);
                Console.WriteLine("    Trustee ".PadRight(26, ' ') + ": " + IdentityReference);
                Console.WriteLine("    SecurityIdentifier ".PadRight(26, ' ') + ": " + SecurityIdentifier);

                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine();

                RightsSeverityFree();
            }
        }

        private static void GetRightsSeverity()
        {
            if (Regex.IsMatch(ActiveDirectoryRights, @"(GenericAll)|(GenericWrite)"))
            {
                if (AccessControlType == "Allow")
                {
                    SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;

                }
            }
            if (Regex.IsMatch(ActiveDirectoryRights, @"(WriteProperty)"))
            {
                if (AccessControlType == "Allow")
                {
                    switch (ObjectTypeGuid)
                    {
                        // public-information
                        case "e48d0154-bcf8-11d1-8702-00c04fb96050":
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        // email-information
                        case "e45795b2-9455-11d1-aebd-0000f80367c1":
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        // web-information
                        case "e45795b3-9455-11d1-aebd-0000f80367c1":
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        // personal-information
                        case "77b5b886-944a-11d1-aebd-0000f80367c1":
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        // group membership
                        case "bc0ac240-79a9-11d0-9020-00c04fc2d4cf":
                            SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                            break;
                        // domain-password
                        case "c7407360-20bf-11d0-a768-00aa006e0529":
                            SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                            break;
                        // User-Account-Restrictions
                        case "4c164200-20c0-11d0-a768-00aa006e0529":
                            SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                            break;
                        // ms-DS-Supported-Encryption-Types
                        case "20119867-1d04-4ab7-9371-cfc3d5df0afd":
                            SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                            break;
                        // User-Account-Control
                        case "bf967a68-0de6-11d0-a285-00aa003049e2":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // Service-Principal-Name
                        case "f3a64788-5306-11d1-a9c5-0000f80367c1":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // Alt-Security-Identities
                        case "00fbf30c-91fe-11d1-aebc-0000f80367c1":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // member
                        case "bf9679c0-0de6-11d0-a285-00aa003049e2":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        //  Is-Member-Of-DL
                        case "bf967991-0de6-11d0-a285-00aa003049e2":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // Primary-Group-ID
                        case "bf967a00-0de6-11d0-a285-00aa003049e2":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // SID-History
                        case "17eb4278-d167-11d0-b002-0000f80367c1":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity
                        case "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // ms-DS-Key-Credential-Link
                        case "5b47d60f-6090-40b2-9f37-2a4de88f3063":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // GPC-File-Sys-path
                        case "f30e3bc1-9ff0-11d1-b603-0000f80367c1":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // MS-DS-Machine-Account-Quota
                        case "d064fb68-1480-11d3-91c1-0000f87a57d4":
                            SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                            break;
                        // PKI-Extended-Key-Usage
                        case "18976af6-3b9e-11d2-90cc-00c04fd91ab1":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // ms-PKI-Enrollment-Flag
                        case "d15ef7d8-f226-46db-ae79-b34e560bd12c":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // ms-PKI-Certificate-Name-Flag
                        case "ea1dddc4-60ff-416e-8cc0-17cee534bce7":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // DNS-Host-Name
                        case "72e39547-7b18-11d1-adef-00c04fd8d5cd":
                            SeverityLevel = SeverityLevel < 2 ? 2 : SeverityLevel;
                            break;
                        default:
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                    }
                }
            }
            if (Regex.IsMatch(ActiveDirectoryRights, @"(WriteDacl)|(WriteOwner)"))
            {
                if (AccessControlType == "Allow")
                {
                    SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                }
            }
            if (Regex.IsMatch(ActiveDirectoryRights, @"(ExtendedRight)"))
            {
                if (AccessControlType == "Allow")
                {
                    switch (ObjectTypeGuid)
                    {
                        // domain administrator server =
                        case "ab721a52-1e2f-11d0-9819-00aa0040529b":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // reset password =
                        case "00299570-246d-11d0-a768-00aa006e0529":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // send as =
                        case "ab721a54-1e2f-11d0-9819-00aa0040529b":
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        // receive as =
                        case "ab721a56-1e2f-11d0-9819-00aa0040529b":
                            SeverityLevel = SeverityLevel < 1 ? 1: SeverityLevel;
                            break;
                        // send to =
                        case "ab721a55-1e2f-11d0-9819-00aa0040529b":
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        // open address list =
                        case "a1990816-4298-11d1-ade2-00c04fd8d5cd":
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        // replicating directory changes =
                        case "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2":
                            SeverityLevel = SeverityLevel < 2 ? 2 : SeverityLevel;
                            break;
                        // replication synchronization =
                        case "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // manage replication topology =
                        case "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // change schema master =
                        case "e12b56b6-0a95-11d1-adbb-00c04fd8d5cd":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // change rid master =
                        case "d58d5f36-0a98-11d1-adbb-00c04fd8d5cd":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // do garbage collection =
                        case "fec364e0-0a98-11d1-adbb-00c04fd8d5cd":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // recalculate hierarchy =
                        case "0bc1554e-0a99-11d1-adbb-00c04fd8d5cd":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // allocate rids =
                        case "1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // change pdc =
                        case "bae50096-4752-11d1-9052-00c04fc2d4cf":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // add guid =
                        case "440820ad-65b4-11d1-a3da-0000f875ae0d":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // change domain master =
                        case "014bf69c-7b3b-11d1-85f6-08002be74fab":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // receive dead letter =
                        case "4b6e08c0-df3c-11d1-9c86-006008764d0e":
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        // peek dead letter =
                        case "4b6e08c1-df3c-11d1-9c86-006008764d0e":
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        // receive computer journal =
                        case "4b6e08c2-df3c-11d1-9c86-006008764d0e":
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        // peek computer journal =
                        case "4b6e08c3-df3c-11d1-9c86-006008764d0e":
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        // receive message =
                        case "06bd3200-df3e-11d1-9c86-006008764d0e":
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        // peek message =
                        case "06bd3201-df3e-11d1-9c86-006008764d0e":
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        // send message =
                        case "06bd3202-df3e-11d1-9c86-006008764d0e":
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        // receive journal =
                        case "06bd3203-df3e-11d1-9c86-006008764d0e":
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        // open connector queue =
                        case "b4e60130-df3f-11d1-9c86-006008764d0e":
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        // apply group policy =
                        case "edacfd8f-ffb3-11d1-b41d-00a0c968f939":
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        // add/remove replica in domain =
                        case "9923a32a-3607-11d2-b9be-0000f87a36b2":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // change infrastructure master =
                        case "cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // update schema cache =
                        case "be2bb760-7f46-11d2-b9ad-00c04f79f805":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // recalculate security inheritance =
                        case "62dd28a8-7f46-11d2-b9ad-00c04f79f805":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // check stale phantoms =
                        case "69ae6200-7f46-11d2-b9ad-00c04f79f805":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // enroll =
                        case "0e10c968-78fb-11d2-90d4-00c04f79dc55":
                            SeverityLevel = SeverityLevel < 2 ? 2 : SeverityLevel;
                            break;
                        // generate resultant set of policy (planning) =
                        case "b7b1b3dd-ab09-4242-9e30-9980e5d322f7":
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        // refresh group cache for logons =
                        case "9432c620-033c-4db7-8b58-14ef6d0bf477":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // enumerate entire sam domain =
                        case "91d67418-0135-4acc-8d79-c08e857cfbec":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // generate resultant set of policy (logging) =
                        case "b7b1b3de-ab09-4242-9e30-9980e5d322f7":
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        // create inbound forest trust =
                        case "e2a36dc9-ae17-47c3-b58b-be34c55ba633":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // replicating directory changes all =
                        case "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // migrate sid history =
                        case "ba33815a-4f93-4c76-87f3-57574bff8109":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // reanimate tombstones =
                        case "45ec5156-db7e-47bb-b53f-dbeb2d03c40f":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // allowed to authenticate =
                        case "68b1d179-0d15-4d4f-ab71-46152e79a7bc":
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        // execute forest update script =
                        case "2f16c4a5-b98e-432c-952a-cb388ba33f2e":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // monitor active directory replication =
                        case "f98340fb-7c5b-4cdb-a00b-2ebdfa115a96":
                            SeverityLevel = SeverityLevel < 3 ? 3 : SeverityLevel;
                            break;
                        // update password not required bit =
                        case "280f369c-67c7-438e-ae98-1d46f3c6f541":
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        // unexpire password =
                        case "ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501":
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        // enable per user reversibly encrypted password =
                        case "05c74c5e-4deb-43b4-bd9f-86664c2a7fd5":
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        // query self quota =
                        case "4ecc03fe-ffc0-4947-b630-eb672a8a9dbc":
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        // read only replication secret synchronization =
                        case "1131f6ae-9c07-11d1-f79f-00c04fc2dcd2":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // reload ssl/tls certificate =
                        case "1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // replicating directory changes in filtered set =
                        case "89e95b76-444d-4c62-991a-0facbeda640c":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // run protect admin groups task =
                        case "7726b9d5-a4b4-4288-a6b2-dce952e80a7f":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // manage optional features for active directory =
                        case "7c0e2a7c-a419-48e4-a995-10180aad54dd":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // allow a dc to create a clone of itself =
                        case "3e0f7e18-2c7a-4c10-ba82-4d926db99a3e":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // autoenrollment =
                        case "a05b8cc2-17bc-4802-a710-e7c15ab866a2":
                            SeverityLevel = SeverityLevel < 2 ? 2 : SeverityLevel;
                            break;
                        // set owner of an object during creation. =
                        case "4125c71f-7fac-4ff0-bcb7-f09a41325286":
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                        // bypass the quota restrictions during creation. =
                        case "88a9933e-e5c8-4f2a-9dd7-2527416b8092":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // read secret attributes of objects in a partition. =
                        case "084c93a2-620d-4879-a836-f0ae47de0e89":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        // write secret attributes of objects in a partition. =
                        case "94825a8d-b171-4116-8146-1e34d8f54401":
                            SeverityLevel = SeverityLevel < 4 ? 4 : SeverityLevel;
                            break;
                        default:
                            SeverityLevel = SeverityLevel < 1 ? 1 : SeverityLevel;
                            break;
                    }
                }
            }

            switch (SeverityLevel)
            {
                case 1:
                    SeverityLevelString = "Low";
                    break;
                case 2:
                    SeverityLevelString = "Warning";
                    break;
                case 3:
                    SeverityLevelString = "High";
                    break;
                case 4:
                    SeverityLevelString = "Critical";
                    break;
                default:
                    SeverityLevelString = "Useless";
                    break;
            }
        }

        private static void RightsSeverityFree()
        {
            SeverityLevel = 0;
            SeverityLevelString = "Useless";
        }

        private static void SelectOutputColor()
        {
            switch (SeverityLevelString)
            {
                case "Low":
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    break;
                case "Warning":
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    break;
                case "High":
                    Console.ForegroundColor = ConsoleColor.DarkYellow;
                    break;
                case "Critical":
                    Console.ForegroundColor = ConsoleColor.Red;
                    break;
                default:
                    Console.ForegroundColor = ConsoleColor.White;
                    break;
            }
        }
    }
}
