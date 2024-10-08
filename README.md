# AnimaSSH: An Xbox SSH/SFTP Server

## Overview

AnimaSSH installs a background OpenSSH SSH/SFTP server on a retail Xbox that has been compromised via [Collateral Damage](https://github.com/exploits-forsale/collateral-damage) & [Solstice](https://github.com/exploits-forsale/solstice).  It leverages [Silverton](https://github.com/kwsimons/Silverton) to bypass Xbox code signing requirements, allowing for arbitrary code execution in an SSH (power) shell.

## Why

When Collateral Damage was first released, all we had was a reverse shell, which was not ideal for rapid development.  `lander` greatly expanded Solstice by finding out how to open up the firewall and even created a [`solstice_daemon`](https://github.com/exploits-forsale/solstice/tree/main/crates/solstice_daemon) that utilizes the Rust `russh` library to create a custom SSH & SFTP server.  As of today, this is the [default payload](https://github.com/exploits-forsale/collateral-damage/blob/main/collat_payload/post_exploit.c) used by Collateral Damage.

AnimaSSH is an alternative SSH/SFTP implementation, relying solely on OpenSSH binaries.  This allows for multiple sessions, multi-user support, standardized configuration, high performance, etc.  Through the use of scheduled tasks, OpenSSH is launched in a background process detached from the entry point app (GameScript), maintaining an open connection after the app is closed and even while the Xbox is in hibernation.  More importantly, through the use of Silverton the SSH shells that are spawned at login are able to execute unsigned code.  The goal of AnimaSSH + Silverton is to allow for rapid development & testing of unsigned code on the Xbox, with the hope that it can help speed up research.

## Preparation

### From Release

The [AnimaSSH releases](https://github.com/kwsimons/AnimaSSH/releases) page hosts a fully assembled `xbox` directory that contains everything needed, this folder simply needs to be copied to the root of your USB drive.  It contains .NET SDK 8.0.402, Powershell 7.3.12, Silverton 0.2+ and AnimaSSH.  It is configured to use the built in OpenSSH server on the Xbox as well as launch Powershell for SSH shells *by default*.

### Manually

The follow steps allow you to configure your USB drive manually if you do not want to use the precreated releases.

1. Download and install [Silverton 0.2+](https://github.com/kwsimons/Silverton) so that you have an `xbox\payloads` directory per the installation instructions
1. Payload preparation (`xbox\payloads\ssh`)
	1. Copy the files in this repositories `payloads` directory to the `xbox\payloads\ssh` directory
	1. Package this repository and copy the output (`AnimaSSH.exe`, etc) to the `xbox\payloads\ssh` directory
1. SSH binary preparation (`xbox\ssh`)
	1. Download the OpenSSH binaries ([`OpenSSH-Win64.zip`](https://github.com/PowerShell/Win32-OpenSSH/releases)) and extract the contents of the `OpenSSH-Win64` directory to the `xbox\ssh` directory
1. Connect your USB drive to the Xbox and boot into a shell via [Collateral Damage](https://github.com/exploits-forsale/collateral-damage) and [Solstice](https://github.com/exploits-forsale/solstice)

## Usage

### Install & Start OpenSSH Server

You will first need to leverage [Collateral Damage](https://github.com/exploits-forsale/collateral-damage) & [Solstice](https://github.com/exploits-forsale/solstice) to gain shell access on the Xbox, then you can issue the commands outlined below.  You will need to run this command after each full Xbox reboot.

The following command will initialize, configure, and start the SSH/SFTP server on port 22:
```
D:\xbox\payloads\ssh\install_ssh.bat
```

**NOTE:** By default, the SSH shell is `cmd.exe`, if you have installed Powershell (see Silvertons installation instructions) and would prefer to use that, read the "Configuration" section.

### SSH/SFTP Client Login

By default an administrative user named `xbox` will be created with the password `xbox`, this account will have all account [rights](https://learn.microsoft.com/en-us/windows/win32/secauthz/account-rights-constants) & [privileges](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants) enabled.

## Compatibility

Devices tested:
* Xbox One X
* Xbox Series X

Versions tested:
* `10.0.25398.4909`
* `10.0.25398.4478`

Binaries tested:
* Silverton 0.2 with .NET SDK 8.0+
* Powershell 7.3.12
* OpenSSH v9.5.0.0p1-Beta
* Built-in Xbox OpenSSH server on versions `10.0.25398.4909` & `10.0.25398.4478`

## Configuration

`config.bat`:
* `SSH_INSTALL_DIR`: Absolute path to the directory containing the OpenSSH binaries
* `SSH_CONFIG_DIR`: Absolute path to the directory that will contain the SSH config, RSA key, Scheduled Task XML.  This cannot be a removable drive.
* `SSH_PAYLOADS_DIR`: Absolute path to the `payloads/ssh` directory
* `SHELL`: Absolute path to the batch/executable that launches the custom shell to use during SSH sessions
* `SSHD_LOG_FILE`: Absolute path to the file OpenSSH & Silverton will log to

`{SSH_CONFIG_DIR}\sshd_config.txt`:
* Contains the [sshd server configuration](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration#windows-configurations-in-sshd_config)

**NOTE:** The `SSH_CONFIG_DIR` cannot be on the USB drive, as permissions must be set on the RSA key within this directory.

## Logging

Silverton & OpenSSH logs will be written to `SSHD_LOG_FILE` configuration values location.  Silverton logging can be adjusted via it's [configuration](https://github.com/kwsimons/Silverton).  OpenSSH logging can be adjusted via the `LogLevel` property within `sshd_config.txt`.

## FAQ

### How does it work?

The AnimaSSH installer configures the Xbox so that it has a properly configured user (`xbox-ssh`) which can impersonate other users, and schedules a background task to launch the OpenSSH server.  As OpenSSH is unsigned, [Silverton](https://github.com/kwsimons/Silverton) is needed to invoke arbitrary unsigned code.  As Silverton hooks new processes launched by a program, it is capable of handling the multiple processes created by OpenSSH.

This installation script performs the following:
1. Attempts to shut down any existing OpenSSH server instance
1. Enables port 22 through the Firewall
1. Creates user `xbox` (with password `xbox`) with administrative permissions and all account rights/privileges enabled
1. Creates user `xbox-sshd` (with password `xbox-sshd`) with administrative permissions and necessary account rights/privileges enabled
1. If not already present, generates an RSA key named `xbox_ssh_rsa_key` in the OpenSSH directory and restricts file permissions
1. If not already present, generates an `sshd_config.txt` in the OpenSSH directory
1. If a custom shell is requested (eg Powershell), updates the OpenSSH registry entries
1. Generates a `ssh_task.xml` Scheduled Task definition and places it in the OpenSSH directory
1. Create a Scheduled Task using `ssh_task.xml`
1. Start the Scheduled Task (as `xbox-sshd`)

### Can I execute unsigned binaries from within the SSH shell?

Yes, the shell that OpenSSH eventually creates (via `conhost.exe`) will be launched by [Silverton](https://github.com/kwsimons/Silverton), ensuring that there is a process creation interceptor that will allow for new processes with unsigned code.

### Do I have to run the installer after each reboot?

Yes, this is necessary as the registry and scheduled tasks do not persist after a reboot.

### Will the server persist after closing the GameScript app?

Yes

### Can I connect while the Xbox is in hibernation?

Yes, the server remains up during hibernation.  Existing connections remain and new connections can be made.

### Can I create multiple SSH/SFTP sessions?

Yes

### Can I log in to multiple accounts?

Yes

### Can I utilize my own OpenSSH binaries?

Yes, simply change the `SSH_INSTALL_DIR` configuration variable.  [`v9.8.1.0p1-Preview Latest`](https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.8.1.0p1-Preview/OpenSSH-Win64.zip) has been tested and confirmed working through this technique.

### Why not run as a traditional Windows Service?

The `NT Service` accounts are problematic when using Silverton, as the .NET SDK has requirements for the user it is running under and necessary environment variables.  There is an opportunity to revisit this in the future, if required.

### Why not run as a the built-in `sshd` account?

This is due to the fact that the built-in `sshd` account is part of the `NT Service` domain, which is problematic when using Silverton (see "Why not run as a traditional Windows Service?").

### Why the name?

The Animas River runs through Silverton and Durango in Colorado, USA.  Durango is the code name for the Xbox OS, and Silverton is the tool that allows unsigned code to run within Durango - AnimaSSH attempts to connect those two together in an way that improves developer work*streams*.

## How to build

Using .NET SDK 8.0+, invoke the following command:
```
dotnet publish /p:PublishProfile=FolderProfile
```

## Resources

* https://github.com/exploits-forsale/collateral-damage
* https://github.com/exploits-forsale/solstice
* https://github.com/kwsimons/Silverton

## Debugging commands

Check on the scheduled task:
```
schtasks /query /tn SSH /FO LIST /V
```

Last Run Result:
* `267011`: The task has not yet run
* `267009`: The task is currently running
* `267014`: The last run of the task was terminated by the user
* `-2147020576`: The operator or administrator refused the request (`0x800710E0`)

Stop the running task:
```
schtasks /end /tn SSH
```

Force run the scheduled task:
```
schtasks /run /tn SSH
```

Delete a scheduled task:
```
schtasks /delete /F /tn SSH
```

(Powershell) Kill all the processes for user `xbox-ssd`:
```
Get-Process -IncludeUserName | Where UserName -match "\\xbox-sshd$" | Stop-Process -Force
```

(Powershell) Kill all the processes for user `xbox`:
```
Get-Process -IncludeUserName | Where UserName -match "^\\xbox$" | Stop-Process -Force
```
## Example usage

```
D:\xbox\payloads\ssh\install_ssh.bat

OpenSSH Install Directory: D:\xbox\ssh
OpenSSH Config Directory: S:\ssh
SSH Payloads Directory: D:\xbox\payloads\launcher\..\ssh
Shell: cmd.exe
Configuring firewall ...
[ INFO] FWPUClnt.dll is not loaded, natively loading...
Configured firewall
Creating user 'xbox' ...
User 'xbox' created
User 'XBOX\xbox' added to administrators group
Adding account right 'SeBatchLogonRight' ...
Added right/privilege 'SeBatchLogonRight' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account right 'SeInteractiveLogonRight' ...
Added right/privilege 'SeInteractiveLogonRight' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account right 'SeNetworkLogonRight' ...
Added right/privilege 'SeNetworkLogonRight' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account right 'SeRemoteInteractiveLogonRight' ...
Added right/privilege 'SeRemoteInteractiveLogonRight' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account right 'SeServiceLogonRight' ...
Added right/privilege 'SeServiceLogonRight' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account right 'SeBatchLogonRight' ...
Added right/privilege 'SeBatchLogonRight' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account right 'SeBatchLogonRight' ...
Added right/privilege 'SeBatchLogonRight' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account right 'SeBatchLogonRight' ...
Added right/privilege 'SeBatchLogonRight' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account right 'SeBatchLogonRight' ...
Added right/privilege 'SeBatchLogonRight' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account right 'SeBatchLogonRight' ...
Added right/privilege 'SeBatchLogonRight' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account right 'SeBatchLogonRight' ...
Added right/privilege 'SeBatchLogonRight' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeAssignPrimaryTokenPrivilege' ...
Added right/privilege 'SeAssignPrimaryTokenPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeAuditPrivilege' ...
Added right/privilege 'SeAuditPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeBackupPrivilege' ...
Added right/privilege 'SeBackupPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeChangeNotifyPrivilege' ...
Added right/privilege 'SeChangeNotifyPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeCreateGlobalPrivilege' ...
Added right/privilege 'SeCreateGlobalPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeCreatePagefilePrivilege' ...
Added right/privilege 'SeCreatePagefilePrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeCreatePermanentPrivilege' ...
Added right/privilege 'SeCreatePermanentPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeCreateSymbolicLinkPrivilege' ...
Added right/privilege 'SeCreateSymbolicLinkPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeCreateTokenPrivilege' ...
Added right/privilege 'SeCreateTokenPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeDebugPrivilege' ...
Added right/privilege 'SeDebugPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeDelegateSessionUserImpersonatePrivilege' ...
Added right/privilege 'SeDelegateSessionUserImpersonatePrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeEnableDelegationPrivilege' ...
Added right/privilege 'SeEnableDelegationPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeImpersonatePrivilege' ...
Added right/privilege 'SeImpersonatePrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeIncreaseBasePriorityPrivilege' ...
Added right/privilege 'SeIncreaseBasePriorityPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeIncreaseQuotaPrivilege' ...
Added right/privilege 'SeIncreaseQuotaPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeIncreaseWorkingSetPrivilege' ...
Added right/privilege 'SeIncreaseWorkingSetPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeLoadDriverPrivilege' ...
Added right/privilege 'SeLoadDriverPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeLockMemoryPrivilege' ...
Added right/privilege 'SeLockMemoryPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeMachineAccountPrivilege' ...
Added right/privilege 'SeMachineAccountPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeManageVolumePrivilege' ...
Added right/privilege 'SeManageVolumePrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeProfileSingleProcessPrivilege' ...
Added right/privilege 'SeProfileSingleProcessPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeRelabelPrivilege' ...
Added right/privilege 'SeRelabelPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeRemoteShutdownPrivilege' ...
Added right/privilege 'SeRemoteShutdownPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeRestorePrivilege' ...
Added right/privilege 'SeRestorePrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeSecurityPrivilege' ...
Added right/privilege 'SeSecurityPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeShutdownPrivilege' ...
Added right/privilege 'SeShutdownPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeSyncAgentPrivilege' ...
Added right/privilege 'SeSyncAgentPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeSystemEnvironmentPrivilege' ...
Added right/privilege 'SeSystemEnvironmentPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeSystemProfilePrivilege' ...
Added right/privilege 'SeSystemProfilePrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeSystemtimePrivilege' ...
Added right/privilege 'SeSystemtimePrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeTakeOwnershipPrivilege' ...
Added right/privilege 'SeTakeOwnershipPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeTcbPrivilege' ...
Added right/privilege 'SeTcbPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeTimeZonePrivilege' ...
Added right/privilege 'SeTimeZonePrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeTrustedCredManAccessPrivilege' ...
Added right/privilege 'SeTrustedCredManAccessPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeUndockPrivilege' ...
Added right/privilege 'SeUndockPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1021
Adding account privilege 'SeUnsolicitedInputPrivilege' ...
Right/privilege 'SeUnsolicitedInputPrivilege' does not exist
Created user profile Q:\Users\xbox
Created user 'xbox'
Creating user 'xbox-sshd' ...
User 'xbox-sshd' created
User 'XBOX\xbox-sshd' added to administrators group
Adding account privilege 'SeAssignPrimaryTokenPrivilege' ...
Added right/privilege 'SeAssignPrimaryTokenPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1022
Adding account privilege 'SeTcbPrivilege' ...
Added right/privilege 'SeTcbPrivilege' to SID S-1-5-21-2702878673-795188819-444038987-1022
Created user profile Q:\Users\xbox-sshd
Created user 'xbox-sshd'
Generating SSH RSA key 'S:\ssh\xbox_ssh_rsa_key' ...
Executing D:\xbox\ssh\ssh-keygen.exe -t rsa -b 2048 -N "" -f "S:\ssh\xbox_ssh_rsa_key" (ProcessId: 3548)
Generating public/private rsa key pair.
Your identification has been saved in S:\ssh\xbox_ssh_rsa_key
Your public key has been saved in S:\ssh\xbox_ssh_rsa_key.pub
The key fingerprint is:
SHA256:IFILp2FAAliye4o4mMJgntmYz03Kwa5jA0YRPWD6d5Q system@XBOX
The key's randomart image is:
+---[RSA 2048]----+
|OBO o            |
|== O . .         |
|o + + E          |
| + . o .         |
|+.o . . S        |
|X=B. .           |
|@B + .           |
|.== =            |
|..+* .           |
+----[SHA256]-----+
Process completed sucessfully
Generated SSH RSA key 'S:\ssh\xbox_ssh_rsa_key'
Restricting SSH RSA key file permissions ...
[ INFO] Ownership & full control set to user 'xbox-sshd' for file S:\ssh\xbox_ssh_rsa_key
Restricted SSH RSA key file permissions
Creating SSH config 'S:\ssh\sshd_config.txt' ...
Created SSH config 'S:\ssh\sshd_config.txt'
Utilizing default cmd.exe shell
Creating scheduled task XML 'S:\ssh\ssh_task.xml' ...
Created scheduled task XML 'S:\ssh\ssh_task.xml'
Scheduling task 'S:\ssh\ssh_task.xml'
Executing C:\Windows\system32\schtasks.exe /create /f /tn SSH /xml S:\ssh\ssh_task.xml /ru xbox-sshd /rp xbox-sshd (ProcessId: 4040)
SUCCESS: The scheduled task "SSH" has successfully been created.
Process completed sucessfully
Scheduled task 'S:\ssh\ssh_task.xml'

Installation complete and SSH server online!
```