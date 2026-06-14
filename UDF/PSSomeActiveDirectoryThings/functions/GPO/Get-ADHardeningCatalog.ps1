function Get-ADHardeningCatalog {
    <#
    .SYNOPSIS
        Returns the static catalog of hardening settings recognised by the
        AD CMMC exporter.

    .DESCRIPTION
        The catalog is the lookup table the GPO scanner uses to label every
        entry it pulls out of registry.pol / GptTmpl.inf / audit.csv with a
        canonical name, a hardening category, and (when applicable) the
        matching CMMC control. Entries the catalog does not know are left
        out of the per-GPO hardening view; the catalog is the curated
        scope of what we audit.

        Three sub-catalogs are returned:

        - Registry      : registry-value entries, keyed by lowercase
                          "<key>\<value>" (no hive). Matches both
                          Machine\registry.pol (Key + Value) and the
                          GptTmpl.inf [Registry Values] Setting after the
                          MACHINE\ prefix is stripped. GPP Preferences
                          Registry items also resolve here once the hive
                          (HKLM\) prefix is stripped.
        - INI           : GptTmpl.inf entries that live outside
                          [Registry Values] (System Access, Event Audit,
                          per-log retention sections, ...). Keyed by
                          "<section>|<setting>" (case insensitive).
        - AuditSub      : audit.csv subcategory GUID → canonical name +
                          category + CMMC. Subcategory GUIDs are the
                          stable identifier; their English display name
                          can drift between OS versions, so we key on
                          the GUID.

        Categories used:
            Auth      - credential protection, anonymous restrictions
            Network   - DNS / SMB / TLS / RDP / WinRM / LDAP transport
            Logging   - PowerShell logs, event log sizing, audit policy
            System    - subsystems, symlinks, telemetry, MS accounts
            GPO       - Group Policy processing & refresh
            PKI       - root / intermediate certificate trust
            WSUS      - Windows Update settings

        Catalog scope was bootstrapped from the 26 hardening GPOs
        exported in C:\Temp\hardening; extending it is a matter of adding
        an entry here. The exporter does not need a code change.

    .OUTPUTS
        Hashtable with keys: Registry, INI, AuditSub.

    .EXAMPLE
        $oCat = Get-ADHardeningCatalog
        $oCat.Registry['software\policies\microsoft\windows nt\dnsclient\enablemulticast']

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0

        1.0.0 (2026-05-26) - Initial version. Coverage:
            - Network: LLMNR, SSL/TLS protocol toggles, SMB1
              server/client + signing, NetCease, LDAP signing /
              channel binding / diagnostics, RDP NLA + Security
              Layer + EncryptionLevel + secure RPC + clipboard /
              printer redirection + session time limits, WinRM
              auth + unencrypted, Kerberos encryption types,
              Netlogon DnsAvoidRegisterRecords, CredSSP Encryption
              Oracle Remediation (CVE-2018-0886), Windows Firewall
              per-profile state + logging (Domain/Private/Public),
              OneDrive corporate-only sync. (Wi-Fi / 802.1X
              profiles are parsed by the exporter via
              Get-ADGroupPolicyNetworkProfile from AD-stored
              msieee80211-Data XML, not via this catalog.)
            - Auth: NoLMHash, cached logon count, NTLM audit +
              outgoing restriction + LM auth level + session
              security, machine password age + sign-or-seal +
              strong key, anonymous restrictions (5 keys),
              NoConnectedUser, BitLocker (FVE + TPM AD backup),
              sleep-require-password (AC/DC), NTFS EFS block,
              Convenience PIN disable, Smart Card service
              startup, password / lockout primitives, RDP
              client password-saving block, blank-password
              limit, SAM password-length ceiling raise, Office
              corporate-only sign-in, 40 [Privilege Rights]
              entries (URA logon quartet + powerful privileges
              - Tcb, Debug, EnableDelegation, Backup, Restore,
              TakeOwnership, ...).
            - Logging: PowerShell module + script-block +
              transcription, audit-process-creation cmdline,
              event log sizing + retention per channel, audit
              policy general flags + 50 advanced-audit
              subcategory GUIDs, WEF SubscriptionManager
              (3 slots), Firewall per-profile logging.
            - System: subsystems + symlinks, telemetry / cloud
              blocks, MS account auth block, Point-and-Print
              driver restriction (PrintNightmare), IE outdated
              ActiveX blocking, SmartScreen (IE + Windows +
              Edge variants), Defender PUA protection.
            - GPO: registry policy processing + refresh
              interval, SyncForegroundPolicy, AlwaysInstall-
              Elevated.
            - PKI: Certificate Path Validation (auto-root
              update + timeouts + cross-cert download).
            - WSUS: full pivot (WUServer, TargetGroup, schedule,
              AU options, ...).
    #>
    [CmdletBinding()]
    Param()

    Process {
        # CMMC shortcuts — keeps the catalog readable. Match the labels
        # used by Get-CMMCControl in Export-ADSecurityReport.ps1 so the
        # CMMC column renders consistently with the existing rows.
        $sAC315 = 'AC.L2-3.1.5 - LEAST PRIVILEGE'
        $sAC316 = 'AC.L2-3.1.6 - NON-PRIVILEGED ACCOUNT USE'
        $sAC317 = 'AC.L2-3.1.7 - PRIVILEGED FUNCTIONS'
        $sAC318 = 'AC.L2-3.1.8 - UNSUCCESSFUL LOGON ATTEMPTS'
        $sAC3110 = 'AC.L2-3.1.10 - SESSION LOCK'
        $sAC3111 = 'AC.L2-3.1.11 - SESSION TERMINATION'
        $sAC3113 = 'AC.L2-3.1.3 - CONTROL CUI FLOW'
        $sAU331 = 'AU.L2-3.3.1 - SYSTEM AUDITING'
        $sAU338 = 'AU.L2-3.3.8 - AUDIT PROTECTION'
        $sIA353 = 'IA.L2-3.5.3 - MULTIFACTOR AUTHENTICATION'
        $sIA3510 = 'IA.L2-3.5.10 - CRYPTOGRAPHICALLY-PROTECTED PASSWORDS'
        $sMP381 = 'MP.L2-3.8.1 - MEDIA PROTECTION'
        $sSC3131 = 'SC.L2-3.13.1 - BOUNDARY PROTECTION'
        $sSC3138 = 'SC.L2-3.13.8 - ENCRYPTION OF CUI IN TRANSIT'
        $sSC31315 = 'SC.L2-3.13.15 - COMMUNICATIONS AUTHENTICITY'
        $sSC31311 = 'SC.L2-3.13.11 - CRYPTOGRAPHIC PROTECTION'
        $sSC31316 = 'SC.L2-3.13.16 - PROTECTION OF CUI AT REST'
        $sSI3141 = 'SI.L2-3.14.1 - FLAW REMEDIATION'
        $sSI3142 = 'SI.L2-3.14.2 - MALICIOUS CODE PROTECTION'

        # ---- Registry catalog ------------------------------------------
        # Key format: lowercase "<registry path no hive>\<value name>".
        # Matched against registry.pol Key+Value AND GptTmpl [Registry
        # Values] Setting (MACHINE\ stripped). Names mirror the GPMC
        # display label when available; otherwise the raw registry name.
        $hReg = @{
            # --- Network / DNS ---------------------------------------
            'software\policies\microsoft\windows nt\dnsclient\enablemulticast' = @{
                Name = 'LLMNR Disabled (EnableMulticast=0)'; Category = 'Network'; CMMC = $sSC3138
            }

            # --- Network / TLS-SSL (per-protocol/role Enabled flag) --
            'system\currentcontrolset\control\securityproviders\schannel\protocols\ssl 2.0\server\enabled' = @{
                Name = 'SCHANNEL - SSL 2.0 Server'; Category = 'Network'; CMMC = $sSC3138
            }
            'system\currentcontrolset\control\securityproviders\schannel\protocols\ssl 2.0\client\enabled' = @{
                Name = 'SCHANNEL - SSL 2.0 Client'; Category = 'Network'; CMMC = $sSC3138
            }
            'system\currentcontrolset\control\securityproviders\schannel\protocols\ssl 3.0\server\enabled' = @{
                Name = 'SCHANNEL - SSL 3.0 Server'; Category = 'Network'; CMMC = $sSC3138
            }
            'system\currentcontrolset\control\securityproviders\schannel\protocols\ssl 3.0\client\enabled' = @{
                Name = 'SCHANNEL - SSL 3.0 Client'; Category = 'Network'; CMMC = $sSC3138
            }
            'system\currentcontrolset\control\securityproviders\schannel\protocols\tls 1.0\server\enabled' = @{
                Name = 'SCHANNEL - TLS 1.0 Server'; Category = 'Network'; CMMC = $sSC3138
            }
            'system\currentcontrolset\control\securityproviders\schannel\protocols\tls 1.0\client\enabled' = @{
                Name = 'SCHANNEL - TLS 1.0 Client'; Category = 'Network'; CMMC = $sSC3138
            }
            'system\currentcontrolset\control\securityproviders\schannel\protocols\tls 1.1\server\enabled' = @{
                Name = 'SCHANNEL - TLS 1.1 Server'; Category = 'Network'; CMMC = $sSC3138
            }
            'system\currentcontrolset\control\securityproviders\schannel\protocols\tls 1.1\client\enabled' = @{
                Name = 'SCHANNEL - TLS 1.1 Client'; Category = 'Network'; CMMC = $sSC3138
            }
            'system\currentcontrolset\control\securityproviders\schannel\protocols\tls 1.2\server\enabled' = @{
                Name = 'SCHANNEL - TLS 1.2 Server'; Category = 'Network'; CMMC = $sSC3138
            }
            'system\currentcontrolset\control\securityproviders\schannel\protocols\tls 1.2\client\enabled' = @{
                Name = 'SCHANNEL - TLS 1.2 Client'; Category = 'Network'; CMMC = $sSC3138
            }
            'system\currentcontrolset\control\securityproviders\schannel\protocols\tls 1.3\server\enabled' = @{
                Name = 'SCHANNEL - TLS 1.3 Server'; Category = 'Network'; CMMC = $sSC3138
            }
            'system\currentcontrolset\control\securityproviders\schannel\protocols\tls 1.3\client\enabled' = @{
                Name = 'SCHANNEL - TLS 1.3 Client'; Category = 'Network'; CMMC = $sSC3138
            }

            # --- Network / SMB --------------------------------------
            # SMB1 server-side toggle (0=disable, 1=enable, 2=audit on
            # Windows 10/Server 2019+).
            'system\currentcontrolset\services\lanmanserver\parameters\smb1' = @{
                Name = 'SMB1 Server (0=off, 2=audit)'; Category = 'Network'; CMMC = $sSC3138
            }
            # SMB1 client driver (Start=4 means disabled).
            'system\currentcontrolset\services\mrxsmb10\start' = @{
                Name = 'SMB1 Client Driver (Start=4=disabled)'; Category = 'Network'; CMMC = $sSC3138
            }
            # SMB signing
            'system\currentcontrolset\services\lanmanserver\parameters\requiresecuritysignature' = @{
                Name = 'SMB Server - Require Security Signature'; Category = 'Network'; CMMC = $sSC3138
            }
            'system\currentcontrolset\services\lanmanworkstation\parameters\requiresecuritysignature' = @{
                Name = 'SMB Client - Require Security Signature'; Category = 'Network'; CMMC = $sSC3138
            }

            # --- Network / NetCease (BloodHound mitigation) ----------
            'system\currentcontrolset\services\lanmanserver\defaultsecurity\srvsvcsessioninfo' = @{
                Name = 'NetCease - Restrict NetSession Enumeration'; Category = 'Network'; CMMC = $sAC315
            }

            # --- Network / LDAP -------------------------------------
            'system\currentcontrolset\services\ntds\parameters\ldapserverintegrity' = @{
                Name = 'LDAP Server - Require Signing'; Category = 'Network'; CMMC = $sSC3138
            }
            'system\currentcontrolset\services\ntds\parameters\ldapenforcechannelbinding' = @{
                Name = 'LDAP Server - Channel Binding'; Category = 'Network'; CMMC = $sSC3138
            }
            'system\currentcontrolset\services\ntds\diagnostics\16 ldap interface events' = @{
                Name = 'NTDS - LDAP Interface Events Diagnostic Level'; Category = 'Logging'; CMMC = $sAU331
            }
            'system\currentcontrolset\services\eventlog\directory service\maxsize' = @{
                Name = 'Event Log - Directory Service MaxSize'; Category = 'Logging'; CMMC = $sAU338
            }

            # --- Network / RDP NLA -----------------------------------
            'software\policies\microsoft\windows nt\terminal services\userauthentication' = @{
                Name = 'RDP - Require Network Level Authentication'; Category = 'Network'; CMMC = $sSC31315
            }
            'software\policies\microsoft\windows nt\terminal services\securitylayer' = @{
                Name = 'RDP - Security Layer'; Category = 'Network'; CMMC = $sSC31315
            }
            'software\policies\microsoft\windows nt\terminal services\minencryptionlevel' = @{
                Name = 'RDP - Minimum Encryption Level'; Category = 'Network'; CMMC = $sSC3138
            }

            # --- Network / WinRM -------------------------------------
            'software\policies\microsoft\windows\winrm\client\allowbasic' = @{
                Name = 'WinRM Client - Allow Basic Authentication'; Category = 'Network'; CMMC = $sSC31315
            }
            'software\policies\microsoft\windows\winrm\client\allowdigest' = @{
                Name = 'WinRM Client - Allow Digest Authentication'; Category = 'Network'; CMMC = $sSC31315
            }
            'software\policies\microsoft\windows\winrm\client\allowunencryptedtraffic' = @{
                Name = 'WinRM Client - Allow Unencrypted Traffic'; Category = 'Network'; CMMC = $sSC3138
            }
            'software\policies\microsoft\windows\winrm\service\allowbasic' = @{
                Name = 'WinRM Service - Allow Basic Authentication'; Category = 'Network'; CMMC = $sSC31315
            }
            'software\policies\microsoft\windows\winrm\service\allowunencryptedtraffic' = @{
                Name = 'WinRM Service - Allow Unencrypted Traffic'; Category = 'Network'; CMMC = $sSC3138
            }

            # --- Auth / LM hash & cached creds -----------------------
            'system\currentcontrolset\control\lsa\nolmhash' = @{
                Name = 'No LM Hash on Password Change'; Category = 'Auth'; CMMC = $sIA3510
            }
            'software\microsoft\windows nt\currentversion\winlogon\cachedlogonscount' = @{
                Name = 'Cached Logons Count'; Category = 'Auth'; CMMC = $sAC315
            }

            # --- Auth / NTLM audit and restriction -------------------
            'system\currentcontrolset\control\lsa\msv1_0\auditreceivingntlmtraffic' = @{
                Name = 'NTLM - Audit Incoming Traffic'; Category = 'Logging'; CMMC = $sAU331
            }
            'system\currentcontrolset\control\lsa\msv1_0\restrictsendingntlmtraffic' = @{
                Name = 'NTLM - Restrict Outgoing Traffic'; Category = 'Auth'; CMMC = $sSC31315
            }
            'system\currentcontrolset\services\netlogon\parameters\auditntlmindomain' = @{
                Name = 'NTLM - Audit Authentication in Domain'; Category = 'Logging'; CMMC = $sAU331
            }

            # --- Auth / Machine account & Netlogon channel -----------
            'system\currentcontrolset\services\netlogon\parameters\maximumpasswordage' = @{
                Name = 'Domain Member - Maximum Machine Password Age'; Category = 'Auth'; CMMC = $sIA3510
            }
            'system\currentcontrolset\services\netlogon\parameters\disablepasswordchange' = @{
                Name = 'Domain Member - Disable Machine Password Change'; Category = 'Auth'; CMMC = $sIA3510
            }
            'system\currentcontrolset\services\netlogon\parameters\requiresignorseal' = @{
                Name = 'Domain Member - Require Sign or Seal'; Category = 'Auth'; CMMC = $sSC31315
            }
            'system\currentcontrolset\services\netlogon\parameters\requirestrongkey' = @{
                Name = 'Domain Member - Require Strong Session Key'; Category = 'Auth'; CMMC = $sSC31315
            }

            # --- Auth / Anonymous restrictions -----------------------
            'system\currentcontrolset\control\lsa\restrictanonymous' = @{
                Name = 'Restrict Anonymous Access to SAM and Shares'; Category = 'Auth'; CMMC = $sAC315
            }
            'system\currentcontrolset\control\lsa\restrictanonymoussam' = @{
                Name = 'Restrict Anonymous SAM Enumeration'; Category = 'Auth'; CMMC = $sAC315
            }
            'system\currentcontrolset\control\lsa\everyoneincludesanonymous' = @{
                Name = 'Everyone Includes Anonymous'; Category = 'Auth'; CMMC = $sAC315
            }
            'system\currentcontrolset\services\lanmanserver\parameters\restrictnullsessaccess' = @{
                Name = 'Restrict Null Session Access'; Category = 'Auth'; CMMC = $sAC315
            }
            'system\currentcontrolset\services\lanmanserver\parameters\nullsessionpipes' = @{
                Name = 'Null Session Pipes'; Category = 'Auth'; CMMC = $sAC315
            }
            'system\currentcontrolset\services\lanmanserver\parameters\nullsessionshares' = @{
                Name = 'Null Session Shares'; Category = 'Auth'; CMMC = $sAC315
            }
            'system\currentcontrolset\control\lsa\restrictremotesam' = @{
                Name = 'Restrict Remote SAM (SDDL ACL)'; Category = 'Auth'; CMMC = $sAC315
            }
            'system\currentcontrolset\control\lsa\forceguest' = @{
                Name = 'Force Guest - Sharing/Security Model for Local Accounts'; Category = 'Auth'; CMMC = $sAC315
            }
            'system\currentcontrolset\control\lsa\disabledomaincreds' = @{
                Name = 'Disable Storage of Network Credentials'; Category = 'Auth'; CMMC = $sAC315
            }

            # --- Auth / Microsoft account block ----------------------
            'software\microsoft\windows\currentversion\policies\system\noconnecteduser' = @{
                Name = 'Block Microsoft Account Logon'; Category = 'Auth'; CMMC = $sAC315
            }
            # Machine inactivity limit (idle seconds before screen lock).
            # 0 = disabled; 600 = 10 min. AC-3.1.10 SESSION LOCK evidence.
            'software\microsoft\windows\currentversion\policies\system\inactivitytimeoutsecs' = @{
                Name = 'Interactive Logon - Machine Inactivity Limit (seconds)'; Category = 'Auth'; CMMC = $sAC3110
            }

            # --- Logging / PowerShell --------------------------------
            'software\policies\microsoft\windows\powershell\modulelogging\enablemodulelogging' = @{
                Name = 'PowerShell - Module Logging'; Category = 'Logging'; CMMC = $sAU331
            }
            'software\policies\microsoft\windows\powershell\scriptblocklogging\enablescriptblocklogging' = @{
                Name = 'PowerShell - Script Block Logging'; Category = 'Logging'; CMMC = $sAU331
            }
            'software\policies\microsoft\windows\powershell\scriptblocklogging\enablescriptblockinvocationlogging' = @{
                Name = 'PowerShell - Script Block Invocation Logging'; Category = 'Logging'; CMMC = $sAU331
            }
            'software\policies\microsoft\windows\powershell\transcription\enabletranscripting' = @{
                Name = 'PowerShell - Transcription'; Category = 'Logging'; CMMC = $sAU331
            }
            'software\policies\microsoft\windows\powershell\transcription\outputdirectory' = @{
                Name = 'PowerShell - Transcription Output Directory'; Category = 'Logging'; CMMC = $sAU338
            }
            'software\policies\microsoft\windows\powershell\transcription\enableinvocationheader' = @{
                Name = 'PowerShell - Transcription Invocation Header'; Category = 'Logging'; CMMC = $sAU331
            }
            'software\policies\microsoft\windows\powershell\enablescripts' = @{
                Name = 'PowerShell - Enable Script Execution'; Category = 'System'; CMMC = $null
            }
            'software\policies\microsoft\windows\powershell\executionpolicy' = @{
                Name = 'PowerShell - Execution Policy'; Category = 'System'; CMMC = $null
            }

            # --- Logging / Audit Process Creation cmdline ------------
            'software\policies\microsoft\windows\audit\processcreationincludecmdline_enabled' = @{
                Name = 'Audit Process Creation - Include Command Line'; Category = 'Logging'; CMMC = $sAU331
            }

            # --- Logging / Event Log channels (size + retention) ----
            'software\policies\microsoft\windows\eventlog\application\maxsize' = @{
                Name = 'Event Log - Application MaxSize (KB)'; Category = 'Logging'; CMMC = $sAU338
            }
            'software\policies\microsoft\windows\eventlog\application\retention' = @{
                Name = 'Event Log - Application Retention Behavior'; Category = 'Logging'; CMMC = $sAU338
            }
            'software\policies\microsoft\windows\eventlog\security\maxsize' = @{
                Name = 'Event Log - Security MaxSize (KB)'; Category = 'Logging'; CMMC = $sAU338
            }
            'software\policies\microsoft\windows\eventlog\security\retention' = @{
                Name = 'Event Log - Security Retention Behavior'; Category = 'Logging'; CMMC = $sAU338
            }
            'software\policies\microsoft\windows\eventlog\system\maxsize' = @{
                Name = 'Event Log - System MaxSize (KB)'; Category = 'Logging'; CMMC = $sAU338
            }
            'software\policies\microsoft\windows\eventlog\system\retention' = @{
                Name = 'Event Log - System Retention Behavior'; Category = 'Logging'; CMMC = $sAU338
            }
            'software\policies\microsoft\windows\eventlog\setup\maxsize' = @{
                Name = 'Event Log - Setup MaxSize (KB)'; Category = 'Logging'; CMMC = $sAU338
            }
            'software\policies\microsoft\windows\eventlog\setup\retention' = @{
                Name = 'Event Log - Setup Retention Behavior'; Category = 'Logging'; CMMC = $sAU338
            }

            # --- Logging / Audit policy general flags ----------------
            'system\currentcontrolset\control\lsa\scenoapplylegacyauditpolicy' = @{
                Name = 'Audit - Force Subcategory Policy (block legacy)'; Category = 'Logging'; CMMC = $sAU331
            }
            'system\currentcontrolset\control\lsa\crashonauditfail' = @{
                Name = 'Audit - Shut Down on Audit Failure'; Category = 'Logging'; CMMC = $sAU338
            }
            'system\currentcontrolset\control\lsa\auditbaseobjects' = @{
                Name = 'Audit - Access of Global System Objects'; Category = 'Logging'; CMMC = $sAU331
            }

            # --- System / Subsystems & symlinks ----------------------
            'system\currentcontrolset\control\session manager\subsystems\optional' = @{
                Name = 'Optional Subsystems (e.g. POSIX)'; Category = 'System'; CMMC = $null
            }
            'system\currentcontrolset\control\session manager\kernel\obcaseinsensitive' = @{
                Name = 'Case Insensitivity for Non-Windows Subsystems'; Category = 'System'; CMMC = $null
            }
            'system\currentcontrolset\control\session manager\protectionmode' = @{
                Name = 'Strengthen Default Permissions on System Objects'; Category = 'System'; CMMC = $null
            }
            'system\currentcontrolset\control\filesystem\symlinklocaltolocalevaluation' = @{
                Name = 'Symlink - Local-to-Local Evaluation'; Category = 'System'; CMMC = $null
            }
            'system\currentcontrolset\control\filesystem\symlinklocaltoremoteevaluation' = @{
                Name = 'Symlink - Local-to-Remote Evaluation'; Category = 'System'; CMMC = $null
            }
            'system\currentcontrolset\control\filesystem\symlinkremotetolocalevaluation' = @{
                Name = 'Symlink - Remote-to-Local Evaluation'; Category = 'System'; CMMC = $null
            }
            'system\currentcontrolset\control\filesystem\symlinkremotetoremoteevaluation' = @{
                Name = 'Symlink - Remote-to-Remote Evaluation'; Category = 'System'; CMMC = $null
            }

            # --- System / Telemetry & cloud blocks -------------------
            'software\policies\microsoft\windows\datacollection\allowtelemetry' = @{
                Name = 'Allow Diagnostic Data (Telemetry)'; Category = 'System'; CMMC = $null
            }
            'software\policies\microsoft\windows\cloudcontent\disablewindowsconsumerfeatures' = @{
                Name = 'Disable Microsoft Consumer Experiences'; Category = 'System'; CMMC = $null
            }
            'software\policies\microsoft\windows\cloudcontent\disablecloudoptimizedcontent' = @{
                Name = 'Disable Cloud Optimized Content'; Category = 'System'; CMMC = $null
            }
            'software\policies\microsoft\windows\windowssearch\allowcortana' = @{
                Name = 'Allow Cortana'; Category = 'System'; CMMC = $null
            }
            'software\policies\microsoft\windows\windowssearch\allowcortanaabovelock' = @{
                Name = 'Allow Cortana Above Lock Screen'; Category = 'System'; CMMC = $null
            }
            'software\policies\microsoft\windows\windowssearch\allowcloudsearch' = @{
                Name = 'Allow Cloud Search'; Category = 'System'; CMMC = $null
            }
            'software\policies\microsoft\windows\windowssearch\allowindexingencryptedstoresoritems' = @{
                Name = 'Allow Indexing of Encrypted Files'; Category = 'System'; CMMC = $null
            }
            'software\policies\microsoft\windows\windowssearch\allowsearchtousecortana' = @{
                Name = 'Allow Search and Cortana to Use Location'; Category = 'System'; CMMC = $null
            }
            'software\policies\microsoft\windows\locationandsensors\disablelocation' = @{
                Name = 'Disable Location Service'; Category = 'System'; CMMC = $null
            }
            'software\policies\microsoft\windows\advertisinginfo\disabledbygrouppolicy' = @{
                Name = 'Disable Advertising ID'; Category = 'System'; CMMC = $null
            }
            'software\policies\microsoft\messenger\client\cloudmessagingallowed' = @{
                Name = 'Allow Message Service Cloud Sync'; Category = 'System'; CMMC = $null
            }
            'software\policies\microsoft\microsoftaccount\disableuserauth' = @{
                Name = 'Block Consumer Microsoft Account Authentication'; Category = 'System'; CMMC = $sAC315
            }
            'software\policies\microsoft\internet explorer\feeds\disableenclosuredownload' = @{
                Name = 'Prevent RSS Enclosure Download'; Category = 'System'; CMMC = $null
            }
            'software\policies\microsoft\windows\windowsupdate\settoknowsettings' = @{
                Name = 'Toggle User Control over Insider Builds'; Category = 'System'; CMMC = $null
            }
            'software\policies\microsoft\windows\datacollection\donotshowfeedbacknotifications' = @{
                Name = 'Do Not Show Feedback Notifications'; Category = 'System'; CMMC = $null
            }
            'software\policies\microsoft\assistance\client\1.0\nosolicit' = @{
                Name = 'Block Solicited Remote Assistance'; Category = 'System'; CMMC = $sAC315
            }
            'software\policies\microsoft\windows nt\terminal services\fallowunsolicited' = @{
                Name = 'Block Offer Remote Assistance'; Category = 'System'; CMMC = $sAC315
            }
            'software\policies\microsoft\windows\system\enableactivityfeed' = @{
                Name = 'Allow Upload of User Activities'; Category = 'System'; CMMC = $null
            }
            'software\policies\microsoft\windows\system\enablecdp' = @{
                Name = 'Continue Experiences on this Device'; Category = 'System'; CMMC = $null
            }
            'software\policies\microsoft\windows\dataconsentservice\enabledatacollection' = @{
                Name = 'Device Health Attestation Monitoring'; Category = 'System'; CMMC = $null
            }
            'software\policies\microsoft\windows\defender\spynet\spynetreporting' = @{
                Name = 'Defender - Join Microsoft MAPS'; Category = 'System'; CMMC = $null
            }
            'software\policies\microsoft\windows defender\reporting\disablegenericreports' = @{
                Name = 'Defender - Watson Events Reporting'; Category = 'System'; CMMC = $null
            }
            'software\policies\microsoft\sqmclient\windows\disablewindowserrorreporting' = @{
                Name = 'PerfTrack - Enable/Disable'; Category = 'System'; CMMC = $null
            }
            'software\policies\microsoft\windows\scripted diagnostics\enablequeryremoteserver' = @{
                Name = 'MSDT Interactive Communication with Support'; Category = 'System'; CMMC = $null
            }

            # --- Kerberos / AD-side hardening (added in 1.6.0) -------
            # Bitmask: 0x1 DES_CBC_CRC, 0x2 DES_CBC_MD5, 0x4 RC4_HMAC_MD5,
            # 0x8 AES128_HMAC_SHA1, 0x10 AES256_HMAC_SHA1, 0x20 future.
            # 0x18 (= 24) = AES128 + AES256 only, the modern baseline.
            'system\currentcontrolset\control\lsa\kerberos\parameters\supportedencryptiontypes' = @{
                Name = 'Kerberos - Supported Encryption Types (bitmask)'; Category = 'Auth'; CMMC = $sSC3138
            }
            # DC Locator DNS records the DC must NOT register. Used on
            # specific DCs to scope which records they advertise (split
            # DNS, perimeter DCs, etc.).
            'system\currentcontrolset\services\netlogon\parameters\dnsavoidregisterrecords' = @{
                Name = 'Netlogon - DC Locator DNS Records To Avoid'; Category = 'Network'; CMMC = $null
            }

            # --- Windows Event Forwarding (WEF) to a SIEM ------------
            # The Group Policy editor renders multiple subscription URLs
            # under value names "1", "2", ... so we register the first
            # three slots explicitly. Add more if the deployment uses
            # additional collectors.
            'software\policies\microsoft\windows\eventlog\eventforwarding\subscriptionmanager\1' = @{
                Name = 'WEF - Subscription Manager (slot 1)'; Category = 'Logging'; CMMC = $sAU331
            }
            'software\policies\microsoft\windows\eventlog\eventforwarding\subscriptionmanager\2' = @{
                Name = 'WEF - Subscription Manager (slot 2)'; Category = 'Logging'; CMMC = $sAU331
            }
            'software\policies\microsoft\windows\eventlog\eventforwarding\subscriptionmanager\3' = @{
                Name = 'WEF - Subscription Manager (slot 3)'; Category = 'Logging'; CMMC = $sAU331
            }

            # --- Certificate path validation -------------------------
            # Auto-update of trusted roots from Microsoft (turning this
            # off pins the org's CA trust). Path validation timeouts +
            # cross-cert download interval shape the CRL/OCSP behaviour.
            'software\policies\microsoft\systemcertificates\authroot\disablerootautoupdate' = @{
                Name = 'Disable Automatic Root Certificates Update'; Category = 'PKI'; CMMC = $sSC31311
            }
            'software\policies\microsoft\systemcertificates\chainengineconfig\chainurlretrievaltimeoutmilliseconds' = @{
                Name = 'Cert Path - URL Retrieval Timeout (ms)'; Category = 'PKI'; CMMC = $sSC31311
            }
            'software\policies\microsoft\systemcertificates\chainengineconfig\chainrevaccumulativeurlretrievaltimeoutmilliseconds' = @{
                Name = 'Cert Path - Cumulative Retrieval Timeout (ms)'; Category = 'PKI'; CMMC = $sSC31311
            }
            'software\policies\microsoft\systemcertificates\chainengineconfig\chaindisableaiaurlretrieval' = @{
                Name = 'Cert Path - Disable AIA URL Retrieval'; Category = 'PKI'; CMMC = $sSC31311
            }
            'software\policies\microsoft\systemcertificates\chainengineconfig\crosscertdownloadintervalhours' = @{
                Name = 'Cert Path - Cross-Cert Download Interval (hours)'; Category = 'PKI'; CMMC = $sSC31311
            }

            # --- Installer / Logon hardening -------------------------
            # AlwaysInstallElevated=1 is dangerous (any user can install
            # any MSI as SYSTEM). Surfaced explicitly because it shows
            # up in the Qualys agent deployment GPO and an auditor will
            # want to see it flagged.
            'software\policies\microsoft\windows\installer\alwaysinstallelevated' = @{
                Name = 'Windows Installer - Always Install with Elevated Privileges'; Category = 'Auth'; CMMC = $sAC317
            }
            # "Always wait for the network at computer startup and logon"
            # - guarantees GPO + roaming-profile + assigned-software gets
            # the network before the user signs in.
            'software\policies\microsoft\windows nt\currentversion\winlogon\syncforegroundpolicy' = @{
                Name = 'Logon - Always Wait For Network At Startup'; Category = 'GPO'; CMMC = $null
            }

            # --- User-side Screen Saver lock (HKCU - User\registry.pol)
            # Same hive layout as legacy `User Policy - Screen Saver`,
            # but matched via the catalog path now so any GPO that sets
            # these surfaces with the canonical "Hardening - Auth" label
            # in addition to the legacy section.
            'software\policies\microsoft\windows\control panel\desktop\screensaveactive' = @{
                Name = 'Screen Saver - Enabled'; Category = 'Auth'; CMMC = $sAC3110
            }
            'software\policies\microsoft\windows\control panel\desktop\screensaverissecure' = @{
                Name = 'Screen Saver - Password Protected'; Category = 'Auth'; CMMC = $sAC3110
            }
            'software\policies\microsoft\windows\control panel\desktop\screensavetimeout' = @{
                Name = 'Screen Saver - Timeout (seconds)'; Category = 'Auth'; CMMC = $sAC3110
            }

            # --- GPO Processing --------------------------------------
            'software\policies\microsoft\windows\group policy\{35378eac-683f-11d2-a89a-00c04fbbcfa2}\nobackgroundpolicy' = @{
                Name = 'GPO - Registry Policy Processing: No Background'; Category = 'GPO'; CMMC = $null
            }
            'software\policies\microsoft\windows\group policy\{35378eac-683f-11d2-a89a-00c04fbbcfa2}\nogpolistchanges' = @{
                Name = 'GPO - Process Even If GPOs Unchanged'; Category = 'GPO'; CMMC = $null
            }
            'software\policies\microsoft\windows\system\grouppolicyrefreshtime' = @{
                Name = 'GPO - Refresh Interval for Computers (minutes)'; Category = 'GPO'; CMMC = $null
            }
            'software\policies\microsoft\windows\system\grouppolicyrefreshtimeoffset' = @{
                Name = 'GPO - Refresh Interval Random Offset (minutes)'; Category = 'GPO'; CMMC = $null
            }

            # --- WSUS (also surfaced in the WSUS pivot section) ------
            'software\policies\microsoft\windows\windowsupdate\wuserver' = @{
                Name = 'WSUS - Intranet Update Service URL'; Category = 'WSUS'; CMMC = $sSI3141
            }
            'software\policies\microsoft\windows\windowsupdate\wustatusserver' = @{
                Name = 'WSUS - Intranet Statistics Server URL'; Category = 'WSUS'; CMMC = $sSI3141
            }
            'software\policies\microsoft\windows\windowsupdate\targetgroup' = @{
                Name = 'WSUS - Target Group Name'; Category = 'WSUS'; CMMC = $sSI3141
            }
            'software\policies\microsoft\windows\windowsupdate\targetgroupenabled' = @{
                Name = 'WSUS - Target Group Enabled'; Category = 'WSUS'; CMMC = $sSI3141
            }
            'software\policies\microsoft\windows\windowsupdate\disablewindowsupdateaccess' = @{
                Name = 'WSUS - Disable Windows Update Access'; Category = 'WSUS'; CMMC = $sSI3141
            }
            'software\policies\microsoft\windows\windowsupdate\au\usewuserver' = @{
                Name = 'WSUS - Use Intranet Update Server'; Category = 'WSUS'; CMMC = $sSI3141
            }
            'software\policies\microsoft\windows\windowsupdate\au\noautoupdate' = @{
                Name = 'WSUS - No Auto Update'; Category = 'WSUS'; CMMC = $sSI3141
            }
            'software\policies\microsoft\windows\windowsupdate\au\auoptions' = @{
                Name = 'WSUS - Auto Update Options'; Category = 'WSUS'; CMMC = $sSI3141
            }
            'software\policies\microsoft\windows\windowsupdate\au\scheduledinstallday' = @{
                Name = 'WSUS - Scheduled Install Day'; Category = 'WSUS'; CMMC = $sSI3141
            }
            'software\policies\microsoft\windows\windowsupdate\au\scheduledinstalltime' = @{
                Name = 'WSUS - Scheduled Install Time'; Category = 'WSUS'; CMMC = $sSI3141
            }
            'software\policies\microsoft\windows\windowsupdate\au\elevatenonadmins' = @{
                Name = 'WSUS - Non-Admins Receive Update Notifications'; Category = 'WSUS'; CMMC = $sSI3141
            }
            'software\policies\microsoft\windows\windowsupdate\au\autoinstallminorupdates' = @{
                Name = 'WSUS - Auto Install Minor Updates'; Category = 'WSUS'; CMMC = $sSI3141
            }
            'software\policies\microsoft\windows\windowsupdate\au\alwaysautorebootatscheduledtime' = @{
                Name = 'WSUS - Always Auto Reboot at Scheduled Time'; Category = 'WSUS'; CMMC = $sSI3141
            }
            'software\policies\microsoft\windows\windowsupdate\au\alwaysautorebootatscheduledtimeminutes' = @{
                Name = 'WSUS - Auto Reboot Timer (minutes)'; Category = 'WSUS'; CMMC = $sSI3141
            }
            'software\policies\microsoft\windows\windowsupdate\au\detectionfrequency' = @{
                Name = 'WSUS - Detection Frequency (hours)'; Category = 'WSUS'; CMMC = $sSI3141
            }
            'software\policies\microsoft\windows\windowsupdate\au\detectionfrequencyenabled' = @{
                Name = 'WSUS - Detection Frequency Enabled'; Category = 'WSUS'; CMMC = $sSI3141
            }
            'software\policies\microsoft\windows\windowsupdate\au\scheduledinstalleveryweek' = @{
                Name = 'WSUS - Schedule: Every Week'; Category = 'WSUS'; CMMC = $sSI3141
            }
            'software\policies\microsoft\windows\windowsupdate\au\scheduledinstallfirstweek' = @{
                Name = 'WSUS - Schedule: First Week'; Category = 'WSUS'; CMMC = $sSI3141
            }
            'software\policies\microsoft\windows\windowsupdate\au\scheduledinstallsecondweek' = @{
                Name = 'WSUS - Schedule: Second Week'; Category = 'WSUS'; CMMC = $sSI3141
            }
            'software\policies\microsoft\windows\windowsupdate\au\scheduledinstallthirdweek' = @{
                Name = 'WSUS - Schedule: Third Week'; Category = 'WSUS'; CMMC = $sSI3141
            }
            'software\policies\microsoft\windows\windowsupdate\au\scheduledinstallfourthweek' = @{
                Name = 'WSUS - Schedule: Fourth Week'; Category = 'WSUS'; CMMC = $sSI3141
            }
            'software\policies\microsoft\windows\windowsupdate\au\noautorebootwithloggedonusers' = @{
                Name = 'WSUS - No Auto Reboot With Logged On Users'; Category = 'WSUS'; CMMC = $sSI3141
            }
            'software\policies\microsoft\windows\windowsupdate\setdisablefillempty' = @{
                Name = 'WSUS - Disable Fill Empty Content URLs'; Category = 'WSUS'; CMMC = $sSI3141
            }

            # ====================================================
            # Lot 3 additions (CMMC-scoped subset of generic GPOs)
            # ====================================================
            # Anti-evidence note: several entries below detect
            # security-WEAKENING configurations (firewall off,
            # WindowsUpdate disabled, CredSSP=Vulnerable, NLA off,
            # NTFS encryption blocked). The catalog still matches
            # them so the auditor sees the configuration; the
            # interpretation (compliant vs not) is left to the human.

            # --- BitLocker (Drive Encryption) ----------------------
            # Standard FVE policy paths. EncryptionMethod / WithXts
            # variants cover Win7/8.x vs Win10+ encryption mode
            # selection. The AD-backup chain (OSActiveDirectoryBackup
            # + OSRequireActiveDirectoryBackup) is the SC-3.13.16
            # CUI-at-rest recovery story; without it the org cannot
            # decrypt drives after user departure.
            'software\policies\microsoft\fve\encryptionmethod' = @{
                Name = 'BitLocker - Encryption Method (legacy)'; Category = 'Auth'; CMMC = $sSC31316
            }
            'software\policies\microsoft\fve\encryptionmethodwithxtsos' = @{
                Name = 'BitLocker - Encryption Method (OS Drive, XTS)'; Category = 'Auth'; CMMC = $sSC31316
            }
            'software\policies\microsoft\fve\encryptionmethodwithxtsfdv' = @{
                Name = 'BitLocker - Encryption Method (Fixed Data, XTS)'; Category = 'Auth'; CMMC = $sSC31316
            }
            'software\policies\microsoft\fve\encryptionmethodwithxtsrdv' = @{
                Name = 'BitLocker - Encryption Method (Removable Data, XTS)'; Category = 'Auth'; CMMC = $sSC31316
            }
            'software\policies\microsoft\fve\osactivedirectorybackup' = @{
                Name = 'BitLocker - OS Drive Store Recovery in AD'; Category = 'Auth'; CMMC = $sSC31316
            }
            'software\policies\microsoft\fve\osactivedirectoryinfotostore' = @{
                Name = 'BitLocker - OS Drive Recovery Info Stored in AD'; Category = 'Auth'; CMMC = $sSC31316
            }
            'software\policies\microsoft\fve\osrequireactivedirectorybackup' = @{
                Name = 'BitLocker - OS Drive Require AD Backup Before Enabling'; Category = 'Auth'; CMMC = $sSC31316
            }
            'software\policies\microsoft\fve\osrecovery' = @{
                Name = 'BitLocker - OS Drive Recovery Options Configured'; Category = 'Auth'; CMMC = $sSC31316
            }
            'software\policies\microsoft\fve\osallowdra' = @{
                Name = 'BitLocker - OS Drive Allow Data Recovery Agent'; Category = 'Auth'; CMMC = $sSC31316
            }
            'software\policies\microsoft\fve\osrecoverypassword' = @{
                Name = 'BitLocker - OS Drive Allow 48-digit Recovery Password'; Category = 'Auth'; CMMC = $sSC31316
            }
            'software\policies\microsoft\fve\osrecoverykey' = @{
                Name = 'BitLocker - OS Drive Allow 256-bit Recovery Key'; Category = 'Auth'; CMMC = $sSC31316
            }
            'software\policies\microsoft\fve\oshiderecoverypage' = @{
                Name = 'BitLocker - OS Drive Hide Recovery Options From Wizard'; Category = 'Auth'; CMMC = $sSC31316
            }
            'software\policies\microsoft\fve\rdvconfigurebde' = @{
                Name = 'BitLocker - Control Use on Removable Drives'; Category = 'Auth'; CMMC = $sMP381
            }
            'software\policies\microsoft\fve\rdvallowbde' = @{
                Name = 'BitLocker - Allow Users to Apply on Removable Drives'; Category = 'Auth'; CMMC = $sMP381
            }
            'software\policies\microsoft\fve\rdvdisablebde' = @{
                Name = 'BitLocker - Allow Users to Suspend/Decrypt Removable Drives'; Category = 'Auth'; CMMC = $sMP381
            }
            # TPM AD backup (companion to BitLocker, separate
            # GPO scope). Also written via GptTmpl [Extra Registry
            # Settings] - matched via INI catalog as well.
            'software\policies\microsoft\tpm\activedirectorybackup' = @{
                Name = 'TPM - Save Owner Info in AD'; Category = 'Auth'; CMMC = $sSC31316
            }
            'software\policies\microsoft\tpm\requireactivedirectorybackup' = @{
                Name = 'TPM - Require AD Backup Before Provisioning'; Category = 'Auth'; CMMC = $sSC31316
            }

            # --- CredSSP Encryption Oracle Remediation -------------
            # CVE-2018-0886. Value 0=Force Updated Clients, 1=
            # Mitigated, 2=Vulnerable. Lot 3's GPO sets =2 (anti-
            # evidence). Catalogued so the row surfaces.
            'software\microsoft\windows\currentversion\policies\system\credssp\parameters\allowencryptionoracle' = @{
                Name = 'CredSSP - Encryption Oracle Remediation (CVE-2018-0886)'; Category = 'Network'; CMMC = $sSC3138
            }

            # --- Windows Firewall (per-profile) --------------------
            # Three profiles (Domain / Standard=Private / Public)
            # with parallel value sets. EnableFirewall=0 = firewall
            # off (anti-evidence). Lot 3 Firewall GPO disables all 3.
            'software\policies\microsoft\windowsfirewall\domainprofile\enablefirewall' = @{
                Name = 'Firewall (Domain) - Enabled'; Category = 'Network'; CMMC = $sSC3131
            }
            'software\policies\microsoft\windowsfirewall\domainprofile\defaultinboundaction' = @{
                Name = 'Firewall (Domain) - Default Inbound Action'; Category = 'Network'; CMMC = $sSC3131
            }
            'software\policies\microsoft\windowsfirewall\domainprofile\defaultoutboundaction' = @{
                Name = 'Firewall (Domain) - Default Outbound Action'; Category = 'Network'; CMMC = $sSC3131
            }
            'software\policies\microsoft\windowsfirewall\domainprofile\disablenotifications' = @{
                Name = 'Firewall (Domain) - Disable Notifications'; Category = 'Network'; CMMC = $sSC3131
            }
            'software\policies\microsoft\windowsfirewall\domainprofile\logging\logdroppedpackets' = @{
                Name = 'Firewall (Domain) - Log Dropped Packets'; Category = 'Logging'; CMMC = $sAU331
            }
            'software\policies\microsoft\windowsfirewall\domainprofile\logging\logsuccessfulconnections' = @{
                Name = 'Firewall (Domain) - Log Successful Connections'; Category = 'Logging'; CMMC = $sAU331
            }
            'software\policies\microsoft\windowsfirewall\domainprofile\logging\logfilepath' = @{
                Name = 'Firewall (Domain) - Log File Path'; Category = 'Logging'; CMMC = $sAU338
            }
            'software\policies\microsoft\windowsfirewall\domainprofile\logging\logfilesize' = @{
                Name = 'Firewall (Domain) - Log File Max Size (KB)'; Category = 'Logging'; CMMC = $sAU338
            }
            'software\policies\microsoft\windowsfirewall\standardprofile\enablefirewall' = @{
                Name = 'Firewall (Private) - Enabled'; Category = 'Network'; CMMC = $sSC3131
            }
            'software\policies\microsoft\windowsfirewall\standardprofile\defaultinboundaction' = @{
                Name = 'Firewall (Private) - Default Inbound Action'; Category = 'Network'; CMMC = $sSC3131
            }
            'software\policies\microsoft\windowsfirewall\standardprofile\defaultoutboundaction' = @{
                Name = 'Firewall (Private) - Default Outbound Action'; Category = 'Network'; CMMC = $sSC3131
            }
            'software\policies\microsoft\windowsfirewall\standardprofile\disablenotifications' = @{
                Name = 'Firewall (Private) - Disable Notifications'; Category = 'Network'; CMMC = $sSC3131
            }
            'software\policies\microsoft\windowsfirewall\standardprofile\logging\logdroppedpackets' = @{
                Name = 'Firewall (Private) - Log Dropped Packets'; Category = 'Logging'; CMMC = $sAU331
            }
            'software\policies\microsoft\windowsfirewall\standardprofile\logging\logsuccessfulconnections' = @{
                Name = 'Firewall (Private) - Log Successful Connections'; Category = 'Logging'; CMMC = $sAU331
            }
            'software\policies\microsoft\windowsfirewall\standardprofile\logging\logfilepath' = @{
                Name = 'Firewall (Private) - Log File Path'; Category = 'Logging'; CMMC = $sAU338
            }
            'software\policies\microsoft\windowsfirewall\standardprofile\logging\logfilesize' = @{
                Name = 'Firewall (Private) - Log File Max Size (KB)'; Category = 'Logging'; CMMC = $sAU338
            }
            'software\policies\microsoft\windowsfirewall\publicprofile\enablefirewall' = @{
                Name = 'Firewall (Public) - Enabled'; Category = 'Network'; CMMC = $sSC3131
            }
            'software\policies\microsoft\windowsfirewall\publicprofile\defaultinboundaction' = @{
                Name = 'Firewall (Public) - Default Inbound Action'; Category = 'Network'; CMMC = $sSC3131
            }
            'software\policies\microsoft\windowsfirewall\publicprofile\defaultoutboundaction' = @{
                Name = 'Firewall (Public) - Default Outbound Action'; Category = 'Network'; CMMC = $sSC3131
            }
            'software\policies\microsoft\windowsfirewall\publicprofile\disablenotifications' = @{
                Name = 'Firewall (Public) - Disable Notifications'; Category = 'Network'; CMMC = $sSC3131
            }
            'software\policies\microsoft\windowsfirewall\publicprofile\logging\logdroppedpackets' = @{
                Name = 'Firewall (Public) - Log Dropped Packets'; Category = 'Logging'; CMMC = $sAU331
            }
            'software\policies\microsoft\windowsfirewall\publicprofile\logging\logsuccessfulconnections' = @{
                Name = 'Firewall (Public) - Log Successful Connections'; Category = 'Logging'; CMMC = $sAU331
            }
            'software\policies\microsoft\windowsfirewall\publicprofile\logging\logfilepath' = @{
                Name = 'Firewall (Public) - Log File Path'; Category = 'Logging'; CMMC = $sAU338
            }
            'software\policies\microsoft\windowsfirewall\publicprofile\logging\logfilesize' = @{
                Name = 'Firewall (Public) - Log File Max Size (KB)'; Category = 'Logging'; CMMC = $sAU338
            }

            # --- Windows Update Disable family ---------------------
            # Anti-evidence: when these are 1, Windows Update is
            # blocked entirely on the target. SI-3.14.1 (flaw
            # remediation) is then compromised.
            # (DisableWindowsUpdateAccess is already in the catalog
            # in the WSUS block above as a Lot 1 entry.)
            'software\policies\microsoft\windows\windowsupdate\disableosupgrade' = @{
                Name = 'WU - Disable OS Upgrade'; Category = 'WSUS'; CMMC = $sSI3141
            }
            'software\policies\microsoft\windows\windowsupdate\excludewudriversinqualityupdate' = @{
                Name = 'WU - Exclude Drivers in Quality Updates'; Category = 'WSUS'; CMMC = $sSI3141
            }

            # --- NTLM auth level & session security ----------------
            # LmCompatibilityLevel: 5 = NTLMv2 only, refuse LM & NTLM
            # (target hardening). NtlmMinClientSec / NtlmMinServerSec:
            # bitmask requiring 128-bit + NTLMv2 session security.
            'system\currentcontrolset\control\lsa\lmcompatibilitylevel' = @{
                Name = 'LAN Manager Authentication Level'; Category = 'Auth'; CMMC = $sSC3138
            }
            'system\currentcontrolset\control\lsa\msv1_0\ntlmminclientsec' = @{
                Name = 'NTLM - Minimum Session Security (Clients)'; Category = 'Auth'; CMMC = $sSC3138
            }
            'system\currentcontrolset\control\lsa\msv1_0\ntlmminserversec' = @{
                Name = 'NTLM - Minimum Session Security (Servers)'; Category = 'Auth'; CMMC = $sSC3138
            }

            # --- Sleep / Wake password (AC + DC) -------------------
            # The wake-from-sleep "Require a password" toggle lives
            # under the power-scheme GUID 0e796bdb...51 with two
            # parallel values (ACSettingIndex = plugged in,
            # DCSettingIndex = on battery). 1 = required.
            'software\policies\microsoft\power\powersettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\acsettingindex' = @{
                Name = 'Require Password on Wake (Plugged In)'; Category = 'Auth'; CMMC = $sAC3110
            }
            'software\policies\microsoft\power\powersettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\dcsettingindex' = @{
                Name = 'Require Password on Wake (On Battery)'; Category = 'Auth'; CMMC = $sAC3110
            }

            # --- Point and Print driver restriction ----------------
            # PrintNightmare (CVE-2021-34527) mitigation. Value 1 =
            # only admins can install printer drivers.
            'software\policies\microsoft\windows nt\printers\pointandprint\restrictdriverinstallationtoadministrators' = @{
                Name = 'Point and Print - Restrict Driver Install to Admins (PrintNightmare)'; Category = 'System'; CMMC = $sSI3141
            }

            # --- RDP session controls ------------------------------
            # Time limits + privacy redirection toggles on the
            # Terminal Services policy hive. Time values in ms.
            # fDisable* booleans: 1=disable redirection, 0=allow.
            # fPromptForPassword=1 forces re-prompt; fEncryptRPC=1
            # requires secure-RPC even for compatible clients.
            'software\policies\microsoft\windows nt\terminal services\maxidletime' = @{
                Name = 'RDP - Max Idle Time (ms)'; Category = 'Auth'; CMMC = $sAC3110
            }
            'software\policies\microsoft\windows nt\terminal services\maxdisconnectiontime' = @{
                Name = 'RDP - Max Disconnection Time (ms)'; Category = 'Auth'; CMMC = $sAC3111
            }
            'software\policies\microsoft\windows nt\terminal services\maxconnectiontime' = @{
                Name = 'RDP - Max Active Session Time (ms)'; Category = 'Auth'; CMMC = $sAC3111
            }
            'software\policies\microsoft\windows nt\terminal services\fpromptforpassword' = @{
                Name = 'RDP - Always Prompt for Password'; Category = 'Auth'; CMMC = $sSC31315
            }
            'software\policies\microsoft\windows nt\terminal services\fencryptrpctraffic' = @{
                Name = 'RDP - Require Secure RPC Communication'; Category = 'Network'; CMMC = $sSC3138
            }
            'software\policies\microsoft\windows nt\terminal services\fdisablecdm' = @{
                Name = 'RDP - Disable Drive (Clipboard/Drive) Redirection'; Category = 'Network'; CMMC = $sAC3113
            }
            'software\policies\microsoft\windows nt\terminal services\fdisablecpm' = @{
                Name = 'RDP - Disable Client Printer Redirection'; Category = 'Network'; CMMC = $sAC3113
            }

            # --- NTFS encryption (EFS) gate ------------------------
            # NtfsDisableEncryption=1 blocks EFS on all NTFS volumes.
            # Anti-evidence vs MP-3.8.1 if CUI relies on EFS.
            'system\currentcontrolset\policies\ntfsdisableencryption' = @{
                Name = 'NTFS - Block EFS Encryption on All Volumes'; Category = 'Auth'; CMMC = $sMP381
            }

            # --- Convenience PIN sign-in ---------------------------
            # AllowDomainPINLogon=0 forbids PIN as a domain logon
            # factor (favours stronger creds / smart card).
            'software\policies\microsoft\windows\system\allowdomainpinlogon' = @{
                Name = 'Convenience PIN Domain Sign-in Allowed'; Category = 'Auth'; CMMC = $sIA353
            }

            # --- OneDrive corporate-only sync ----------------------
            # DisablePersonalSync=1 blocks consumer OneDrive (forces
            # business/CUI traffic through corporate tenant).
            # KFM* policies govern Known Folder Move into the
            # corporate tenant. AllowTenantList itself is a subkey
            # of REG_SZ values (one per allowed tenant) - awkward
            # to flat-catalogue; the presence of DisablePersonalSync
            # is the audit-significant signal.
            'software\policies\microsoft\onedrive\disablepersonalsync' = @{
                Name = 'OneDrive - Block Personal Account Sync'; Category = 'Network'; CMMC = $sAC3113
            }
            'software\policies\microsoft\onedrive\kfmblockoptin' = @{
                Name = 'OneDrive - Block Move of Known Folders to OneDrive'; Category = 'Network'; CMMC = $sAC3113
            }
            'software\policies\microsoft\onedrive\kfmsilentoptin' = @{
                Name = 'OneDrive - Silently Move Known Folders (tenant ID)'; Category = 'Network'; CMMC = $sAC3113
            }

            # --- IE outdated ActiveX blocking ----------------------
            # ADMX target. DownloadVersionList=1 = blocking
            # disabled (anti-pattern). Surfaced for completeness;
            # IE is deprecated on modern Windows, so signal may be
            # rare in current environments.
            'software\policies\microsoft\internet explorer\versionmanager\downloadversionlist' = @{
                Name = 'IE - Disable Blocking of Outdated ActiveX'; Category = 'System'; CMMC = $sSI3141
            }

            # ====================================================
            # Lot 4 additions (User-side hardening + workstation
            # baseline observed in 54 GPMC reports parsed via
            # Read-ADGroupPolicyReportHtml)
            # ====================================================

            # --- Auth / Password handling ------------------------
            # DisablePasswordSaving=1 prevents RDP Connection Client
            # from caching credentials. IA-3.5.7 / AC-3.1.5.
            'software\policies\microsoft\windows nt\terminal services\disablepasswordsaving' = @{
                Name = 'RDP Client - Do Not Allow Passwords to Be Saved'; Category = 'Auth'; CMMC = $sAC315
            }
            # LimitBlankPasswordUse=1 blocks blank-password local
            # accounts from network logon; only console logon
            # allowed. Standard MS hardening baseline.
            'system\currentcontrolset\control\lsa\limitblankpassworduse' = @{
                Name = 'Limit Blank Password Use to Console Logon'; Category = 'Auth'; CMMC = $sAC315
            }
            # RelaxMinimumPasswordLengthLimits=1 raises the policy
            # ceiling from 14 to 128 chars - enables Min Password
            # Length values > 14 to actually take effect. Relevant
            # only paired with a corresponding length policy.
            'system\currentcontrolset\control\sam\relaxminimumpasswordlengthlimits' = @{
                Name = 'SAM - Allow Password Length Above 14 Chars'; Category = 'Auth'; CMMC = 'IA.L2-3.5.7 - PASSWORD COMPLEXITY'
            }

            # --- Office / Cloud account block --------------------
            # SignInOptions: 0 = both, 1 = MS account only, 2 = org
            # account only (corp-only), 3 = no sign-in. >=2 keeps
            # CUI out of personal MS accounts via Office.
            'software\policies\microsoft\office\common\signin\signinoptions' = @{
                Name = 'Office - Block Sign-in Options (corp-only or none)'; Category = 'Auth'; CMMC = $sAC3113
            }
            # SignIn block via versioned key (Office 2016+).
            'software\policies\microsoft\office\16.0\common\signin\signinoptions' = @{
                Name = 'Office 16 - Block Sign-in Options'; Category = 'Auth'; CMMC = $sAC3113
            }

            # --- SmartScreen (IE + Windows + Edge) ---------------
            # IE SmartScreen / phishing filter.
            'software\policies\microsoft\internet explorer\phishingfilter\enabledv9' = @{
                Name = 'IE SmartScreen - Enabled'; Category = 'System'; CMMC = $sSI3142
            }
            'software\policies\microsoft\internet explorer\phishingfilter\preventoverride' = @{
                Name = 'IE SmartScreen - Prevent Override'; Category = 'System'; CMMC = $sSI3142
            }
            'software\policies\microsoft\internet explorer\phishingfilter\preventoverrideappreputationunknownfiles' = @{
                Name = 'IE SmartScreen - Prevent Override for Unknown Files'; Category = 'System'; CMMC = $sSI3142
            }
            # Windows SmartScreen (shell-level for downloaded apps).
            'software\policies\microsoft\windows\system\enablesmartscreen' = @{
                Name = 'Windows SmartScreen - Enabled'; Category = 'System'; CMMC = $sSI3142
            }
            'software\policies\microsoft\windows\system\shellsmartscreenlevel' = @{
                Name = 'Windows SmartScreen - Block vs Warn Level'; Category = 'System'; CMMC = $sSI3142
            }
            # Edge (Chromium) SmartScreen + PUA detection.
            'software\policies\microsoft\edge\smartscreenenabled' = @{
                Name = 'Edge SmartScreen - Enabled'; Category = 'System'; CMMC = $sSI3142
            }
            'software\policies\microsoft\edge\smartscreenpuaenabled' = @{
                Name = 'Edge SmartScreen - PUA Detection Enabled'; Category = 'System'; CMMC = $sSI3142
            }
            # Defender PUA protection (covers downloads outside Edge).
            'software\policies\microsoft\windows defender\puaprotection' = @{
                Name = 'Defender - PUA Protection Enabled'; Category = 'System'; CMMC = $sSI3142
            }
        }

        # ---- INI catalog (GptTmpl.inf sections outside Registry Values)
        # Section header captured as written in the .inf, case-insensitive
        # match handled by the lookup helper. [System Access] keys cover
        # the password / lockout primitives; per-log sections cover legacy
        # event log sizing on pre-Vista templates.
        $hINI = @{
            # System Access (password + lockout primitives)
            'system access|minimumpasswordlength'      = @{ Name = 'Min Password Length';         Category = 'Auth';    CMMC = 'IA.L2-3.5.7 - PASSWORD COMPLEXITY' }
            'system access|passwordcomplexity'         = @{ Name = 'Password Complexity';         Category = 'Auth';    CMMC = 'IA.L2-3.5.7 - PASSWORD COMPLEXITY' }
            'system access|passwordhistorysize'        = @{ Name = 'Password History Size';       Category = 'Auth';    CMMC = 'IA.L2-3.5.8 - PASSWORD REUSE' }
            'system access|maximumpasswordage'         = @{ Name = 'Max Password Age';            Category = 'Auth';    CMMC = 'IA.L2-3.5.8 - PASSWORD REUSE' }
            'system access|minimumpasswordage'         = @{ Name = 'Min Password Age';            Category = 'Auth';    CMMC = 'IA.L2-3.5.8 - PASSWORD REUSE' }
            'system access|lockoutbadcount'            = @{ Name = 'Lockout Bad Count';           Category = 'Auth';    CMMC = $sAC318 }
            'system access|resetlockoutcount'          = @{ Name = 'Reset Lockout Count';         Category = 'Auth';    CMMC = $sAC318 }
            'system access|lockoutduration'            = @{ Name = 'Lockout Duration';            Category = 'Auth';    CMMC = $sAC318 }
            'system access|clearpasswordswhilelogged'  = @{ Name = 'Clear Passwords While Logged'; Category = 'Auth';   CMMC = $null }
            'system access|lsaanonymousnamelookup'     = @{ Name = 'Allow Anonymous SID/Name Translation'; Category = 'Auth'; CMMC = $sAC315 }
            'system access|enableadminaccount'         = @{ Name = 'Local Administrator Enabled'; Category = 'Auth';    CMMC = $sAC315 }
            'system access|enableguestaccount'         = @{ Name = 'Local Guest Account Enabled'; Category = 'Auth';    CMMC = $sAC315 }
            'system access|newadministratorname'       = @{ Name = 'Local Administrator Renamed To'; Category = 'Auth'; CMMC = $sAC315 }
            'system access|newguestname'               = @{ Name = 'Local Guest Renamed To';      Category = 'Auth';    CMMC = $sAC315 }
            'system access|forcelogoffwhenhourexpire'  = @{ Name = 'Force Logoff When Hour Expire'; Category = 'Auth';  CMMC = $sAC315 }

            # [Privilege Rights] - User Rights Assignment (URA).
            # The GptTmpl.inf privilege constants and their display
            # equivalents in the Local Security Policy UI. Values are
            # comma-separated principal lists, usually "*<SID>" entries
            # (SDDL-style) - resolved to NT-account names by the export
            # layer when possible. CMMC scope: the logon-grant/deny
            # quartet is least-privilege evidence; the powerful
            # privilege rights (Tcb, Debug, EnableDelegation, ...) are
            # privileged-functions evidence (AC.L2-3.1.7).
            'privilege rights|senetworklogonright'              = @{ Name = 'Access this computer from the network';     Category = 'Auth'; CMMC = $sAC315 }
            'privilege rights|sedenynetworklogonright'          = @{ Name = 'Deny access to this computer from the network'; Category = 'Auth'; CMMC = $sAC315 }
            'privilege rights|seinteractivelogonright'          = @{ Name = 'Allow log on locally';                       Category = 'Auth'; CMMC = $sAC315 }
            'privilege rights|sedenyinteractivelogonright'      = @{ Name = 'Deny log on locally';                        Category = 'Auth'; CMMC = $sAC315 }
            'privilege rights|seremoteinteractivelogonright'    = @{ Name = 'Allow log on through Terminal Services';     Category = 'Auth'; CMMC = $sAC315 }
            'privilege rights|sedenyremoteinteractivelogonright'= @{ Name = 'Deny log on through Terminal Services';      Category = 'Auth'; CMMC = $sAC315 }
            'privilege rights|sebatchlogonright'                = @{ Name = 'Log on as a batch job';                      Category = 'Auth'; CMMC = $sAC315 }
            'privilege rights|sedenybatchlogonright'            = @{ Name = 'Deny log on as a batch job';                 Category = 'Auth'; CMMC = $sAC315 }
            'privilege rights|seservicelogonright'              = @{ Name = 'Log on as a service';                        Category = 'Auth'; CMMC = $sAC315 }
            'privilege rights|sedenyservicelogonright'          = @{ Name = 'Deny log on as a service';                   Category = 'Auth'; CMMC = $sAC315 }
            'privilege rights|setcbprivilege'                   = @{ Name = 'Act as part of the operating system';        Category = 'Auth'; CMMC = $sAC317 }
            'privilege rights|sedebugprivilege'                 = @{ Name = 'Debug programs';                             Category = 'Auth'; CMMC = $sAC317 }
            'privilege rights|seenabledelegationprivilege'      = @{ Name = 'Enable computer / user accounts for delegation'; Category = 'Auth'; CMMC = $sAC317 }
            'privilege rights|seauditprivilege'                 = @{ Name = 'Generate security audits';                   Category = 'Auth'; CMMC = $sAC317 }
            'privilege rights|sesecurityprivilege'              = @{ Name = 'Manage auditing and security log';           Category = 'Auth'; CMMC = $sAC317 }
            'privilege rights|setrustedcredmanaccessprivilege'  = @{ Name = 'Access Credential Manager as a trusted caller'; Category = 'Auth'; CMMC = $sAC317 }
            'privilege rights|sebackupprivilege'                = @{ Name = 'Back up files and directories';              Category = 'Auth'; CMMC = $sAC316 }
            'privilege rights|serestoreprivilege'               = @{ Name = 'Restore files and directories';              Category = 'Auth'; CMMC = $sAC316 }
            'privilege rights|setakeownershipprivilege'         = @{ Name = 'Take ownership of files or other objects';   Category = 'Auth'; CMMC = $sAC316 }
            'privilege rights|seloaddriverprivilege'            = @{ Name = 'Load and unload device drivers';             Category = 'Auth'; CMMC = $sAC317 }
            'privilege rights|seshutdownprivilege'              = @{ Name = 'Shut down the system';                       Category = 'Auth'; CMMC = $sAC315 }
            'privilege rights|seremoteshutdownprivilege'        = @{ Name = 'Force shutdown from a remote system';        Category = 'Auth'; CMMC = $sAC315 }
            'privilege rights|seimpersonateprivilege'           = @{ Name = 'Impersonate a client after authentication';  Category = 'Auth'; CMMC = $sAC317 }
            'privilege rights|seassignprimarytokenprivilege'    = @{ Name = 'Replace a process level token';              Category = 'Auth'; CMMC = $sAC317 }
            'privilege rights|secreatetokenprivilege'           = @{ Name = 'Create a token object';                      Category = 'Auth'; CMMC = $sAC317 }
            'privilege rights|sesystemenvironmentprivilege'     = @{ Name = 'Modify firmware environment values';         Category = 'Auth'; CMMC = $sAC317 }
            'privilege rights|seincreasequotaprivilege'         = @{ Name = 'Adjust memory quotas for a process';         Category = 'Auth'; CMMC = $null }
            'privilege rights|seincreasebasepriorityprivilege'  = @{ Name = 'Increase scheduling priority';               Category = 'Auth'; CMMC = $null }
            'privilege rights|sesystemtimeprivilege'            = @{ Name = 'Change the system time';                     Category = 'Auth'; CMMC = $sAC315 }
            'privilege rights|setimezoneprivilege'              = @{ Name = 'Change the time zone';                       Category = 'Auth'; CMMC = $null }
            'privilege rights|seprofilesingleprocessprivilege'  = @{ Name = 'Profile single process';                     Category = 'Auth'; CMMC = $null }
            'privilege rights|sesystemprofileprivilege'         = @{ Name = 'Profile system performance';                 Category = 'Auth'; CMMC = $null }
            'privilege rights|seundockprivilege'                = @{ Name = 'Remove computer from docking station';       Category = 'Auth'; CMMC = $null }
            'privilege rights|semanagevolumeprivilege'          = @{ Name = 'Perform volume maintenance tasks';           Category = 'Auth'; CMMC = $sAC317 }
            'privilege rights|secreateglobalprivilege'          = @{ Name = 'Create global objects';                      Category = 'Auth'; CMMC = $null }
            'privilege rights|secreatepagefileprivilege'        = @{ Name = 'Create a pagefile';                          Category = 'Auth'; CMMC = $null }
            'privilege rights|secreatesymboliclinkprivilege'    = @{ Name = 'Create symbolic links';                      Category = 'Auth'; CMMC = $null }
            'privilege rights|sechangenotifyprivilege'          = @{ Name = 'Bypass traverse checking';                   Category = 'Auth'; CMMC = $null }
            'privilege rights|semachineaccountprivilege'        = @{ Name = 'Add workstations to domain';                 Category = 'Auth'; CMMC = $sAC315 }
            'privilege rights|selockmemoryprivilege'            = @{ Name = 'Lock pages in memory';                       Category = 'Auth'; CMMC = $null }

            # Event Log per-log retention (legacy [Application Log] /
            # [Security Log] / [System Log] sections - present on
            # templates predating the EventLog ADMX). MaximumLogSize is
            # in KB; AuditLogRetentionPeriod is the retention mode.
            'application log|maximumlogsize'         = @{ Name = 'Event Log - Application MaxSize (KB)'; Category = 'Logging'; CMMC = $sAU338 }
            'application log|auditlogretentionperiod' = @{ Name = 'Event Log - Application Retention Period'; Category = 'Logging'; CMMC = $sAU338 }
            'application log|restrictguestaccess'    = @{ Name = 'Event Log - Application Restrict Guest Access'; Category = 'Logging'; CMMC = $sAU338 }
            'security log|maximumlogsize'            = @{ Name = 'Event Log - Security MaxSize (KB)';    Category = 'Logging'; CMMC = $sAU338 }
            'security log|auditlogretentionperiod'   = @{ Name = 'Event Log - Security Retention Period'; Category = 'Logging'; CMMC = $sAU338 }
            'security log|restrictguestaccess'       = @{ Name = 'Event Log - Security Restrict Guest Access'; Category = 'Logging'; CMMC = $sAU338 }
            'system log|maximumlogsize'              = @{ Name = 'Event Log - System MaxSize (KB)';      Category = 'Logging'; CMMC = $sAU338 }
            'system log|auditlogretentionperiod'     = @{ Name = 'Event Log - System Retention Period'; Category = 'Logging'; CMMC = $sAU338 }
            'system log|restrictguestaccess'         = @{ Name = 'Event Log - System Restrict Guest Access'; Category = 'Logging'; CMMC = $sAU338 }

            # Legacy 9-category audit policy ([Event Audit]) - mostly
            # superseded by audit.csv when SCENoApplyLegacyAuditPolicy=1.
            # Captured here for the corner case of templates that still
            # set them. Value semantics: 0=No, 1=Success, 2=Failure, 3=Both.
            'event audit|auditsystemevents'        = @{ Name = 'Audit System Events (legacy)';      Category = 'Logging'; CMMC = $sAU331 }
            'event audit|auditlogonevents'         = @{ Name = 'Audit Logon Events (legacy)';       Category = 'Logging'; CMMC = $sAU331 }
            'event audit|auditobjectaccess'        = @{ Name = 'Audit Object Access (legacy)';      Category = 'Logging'; CMMC = $sAU331 }
            'event audit|auditprivilegeuse'        = @{ Name = 'Audit Privilege Use (legacy)';      Category = 'Logging'; CMMC = $sAU331 }
            'event audit|auditpolicychange'        = @{ Name = 'Audit Policy Change (legacy)';      Category = 'Logging'; CMMC = $sAU331 }
            'event audit|auditaccountmanage'       = @{ Name = 'Audit Account Management (legacy)'; Category = 'Logging'; CMMC = $sAU331 }
            'event audit|auditprocesstracking'     = @{ Name = 'Audit Process Tracking (legacy)';   Category = 'Logging'; CMMC = $sAU331 }
            'event audit|auditdsaccess'            = @{ Name = 'Audit DS Access (legacy)';          Category = 'Logging'; CMMC = $sAU331 }
            'event audit|auditaccountlogon'        = @{ Name = 'Audit Account Logon (legacy)';      Category = 'Logging'; CMMC = $sAU331 }

            # [Service General Setting] - System Services startup
            # mode + ACL. Setting key = service short name; value
            # encodes startup-mode int + SDDL. Smart Card service
            # set to Automatic is MFA-readiness evidence.
            'service general setting|scardsvr'         = @{ Name = 'Smart Card Service Startup';      Category = 'Auth'; CMMC = $sIA353 }

            # [Extra Registry Settings] - SCE-template registry
            # entries. The Setting key in GptTmpl.inf is the full
            # registry path (no MACHINE\ prefix in the section's
            # entries despite living machine-side). Catalogued
            # only for the items we already match registry-side,
            # so a GPO that uses either delivery mechanism shows.
            'extra registry settings|software\policies\microsoft\tpm\activedirectorybackup' = @{
                Name = 'TPM - Save Owner Info in AD (via Extra Reg)'; Category = 'Auth'; CMMC = $sSC31316
            }
            'extra registry settings|software\policies\microsoft\tpm\requireactivedirectorybackup' = @{
                Name = 'TPM - Require AD Backup Before Provisioning (via Extra Reg)'; Category = 'Auth'; CMMC = $sSC31316
            }
        }

        # ---- Advanced Audit subcategories (audit.csv) ------------------
        # Keyed on the subcategory GUID since the display name has drifted
        # between OS versions ("Audit Policy Change" / "Authorization
        # Policy Change" are the obvious examples). Setting Value column
        # of audit.csv: 0=No, 1=Success, 2=Failure, 3=Both.
        $hAudit = @{
            # System
            '{0CCE9210-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Security State Change';                Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9211-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Security System Extension';            Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9212-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit System Integrity';                     Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9213-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit IPsec Driver';                         Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9214-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Other System Events';                  Category = 'Logging'; CMMC = $sAU331 }
            # Logon/Logoff
            '{0CCE9215-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Logon';                                Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9216-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Logoff';                               Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9217-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Account Lockout';                      Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9218-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit IPsec Main Mode';                      Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9219-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit IPsec Quick Mode';                     Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE921A-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit IPsec Extended Mode';                  Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE921B-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Special Logon';                        Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE921C-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Other Logon/Logoff Events';            Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE921D-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Network Policy Server';                Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE921E-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit User / Device Claims';                 Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE921F-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Group Membership';                     Category = 'Logging'; CMMC = $sAU331 }
            # Object Access
            '{0CCE9220-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit File System';                          Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9221-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Registry';                             Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9222-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Kernel Object';                        Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9223-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit SAM';                                  Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9224-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Certification Services';               Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9225-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Application Generated';                Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9226-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Handle Manipulation';                  Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9227-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit File Share';                           Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9228-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Filtering Platform Packet Drop';       Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9229-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Filtering Platform Connection';        Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE922A-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Other Object Access Events';           Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE922B-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Detailed File Share';                  Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE922C-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Removable Storage';                    Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE922D-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Central Access Policy Staging';        Category = 'Logging'; CMMC = $sAU331 }
            # Privilege Use
            '{0CCE922E-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Sensitive Privilege Use';              Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE922F-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Non Sensitive Privilege Use';          Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9230-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Other Privilege Use Events';           Category = 'Logging'; CMMC = $sAU331 }
            # Detailed Tracking
            '{0CCE9231-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Process Creation';                     Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9232-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Process Termination';                  Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9233-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit DPAPI Activity';                       Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9234-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit RPC Events';                           Category = 'Logging'; CMMC = $sAU331 }
            # Policy Change
            '{0CCE9235-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Audit Policy Change';                  Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9236-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Authentication Policy Change';         Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9237-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Authorization Policy Change';          Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9238-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit MPSSVC Rule-Level Policy Change';      Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9239-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Filtering Platform Policy Change';     Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE923A-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Other Policy Change Events';           Category = 'Logging'; CMMC = $sAU331 }
            # Account Management
            '{0CCE923B-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit User Account Management';              Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE923C-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Computer Account Management';          Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE923D-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Security Group Management';            Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE923E-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Distribution Group Management';        Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE923F-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Application Group Management';         Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9240-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Other Account Management Events';      Category = 'Logging'; CMMC = $sAU331 }
            # DS Access
            '{0CCE9241-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Directory Service Access';             Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9242-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Directory Service Changes';            Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9243-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Directory Service Replication';        Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9244-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Detailed Directory Service Replication'; Category = 'Logging'; CMMC = $sAU331 }
            # Account Logon
            '{0CCE9245-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Credential Validation';                Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9246-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Kerberos Service Ticket Operations';   Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9247-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Other Account Logon Events';           Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE9248-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Kerberos Authentication Service';      Category = 'Logging'; CMMC = $sAU331 }
            # Detailed Tracking (additions)
            '{0CCE9249-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Plug and Play Events';                 Category = 'Logging'; CMMC = $sAU331 }
            '{0CCE924A-69AE-11D9-BED3-505054503030}' = @{ Name = 'Audit Token Right Adjusted Events';          Category = 'Logging'; CMMC = $sAU331 }
        }

        return [PSCustomObject]@{
            Registry = $hReg
            INI      = $hINI
            AuditSub = $hAudit
        }
    }
}
