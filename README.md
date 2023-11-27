# SharpRODC

To audit the security of read-only domain controllers, I created the [SharpRODC](https://github.com/wh0amitz/SharpRODC) project, a simple .NET tool for RODC-related misconfiguration. For more details on attacking RODC please read my blog: [“*Revisiting a Abuse of Read-Only Domain Controllers (RODCs)*”](https://whoamianony.top/posts/revisiting-a-abuse-of-read-only-domain-controllers/)

The tool enumerates the following from Active Directory:

- DACL of the RODC object
- RODC's Krbtgt account
- DACL of the "Allowed RODC Password Replication Group" object
- DACL of the "Denied RODC Password Replication Group" object
- "managedBy" attribute value of RODC object
- DACL of the user or group to whom RODC administrative rights are delegated
- "msDS-RevealOnDemandGroup" attribute value of the RODC object
- "msDS-NeverRevealGroup" attribute value of the RODC object
- "msDS-RevealedList attribute" value of the RODC object
- RODC-related DACL on the domain partition object