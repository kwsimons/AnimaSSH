using Microsoft.Win32;
using Silverton.Core.Interop;
using Silverton.Core.Managers;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;
using static Silverton.Core.Interop.NativeBridge;

namespace AnimaSSH {

    // Responsible for installing the SSH server, must be executed after each reboot
    public class Launcher {

        private static readonly string SSH_RSA_KEY_FILENAME = "xbox_ssh_rsa_key";
        private static readonly string SSH_CONFIG_FILENAME = "sshd_config.txt";
        private static readonly string SSH_TASK_XML_FILENAME = @"ssh_task.xml";
        private static readonly string SSH_PID_FILENAME = @"sshd.pid";
        private static readonly string XBOX_USER = "xbox";
        private static readonly string XBOX_PASS = "xbox";
        private static readonly string SSHD_USER = "xbox-sshd";
        private static readonly string SSHD_PASS = "xbox-sshd";
        private static readonly string ADMINISTRATORS_GROUP = "Administrators";
        private static readonly string OPENSSH_REGISTRY_HIVE = @"HKEY_LOCAL_MACHINE";
        private static readonly string OPENSSH_REGISTRY_ROOT = @"SOFTWARE\OpenSSH";
        private static readonly string OPENSSH_REGISTRY_PATH = $"{OPENSSH_REGISTRY_HIVE}\\{OPENSSH_REGISTRY_ROOT}";
        private static readonly string OPENSSH_DEFAULTSHELL_REGISTRY_KEY = "DefaultShell";
        private static readonly string OPENSSH_DEFAULTSHELLARGUMENTS_REGISTRY_KEY = "DefaultShellArguments";

        public static void Main(string[] args) {

            try {
                var command = args.Length > 0 ? args[0] : "<empty>";
                var arguments = ParseArguments(args);
                switch (args[0]) {
                    case "install":
                        Install(arguments);
                        break;
                    case "uninstall":
                        Uninstall(arguments);
                        break;
                    case "stop":
                        Stop(arguments);
                        break;
                    default:
                        throw new Exception($"Unknown command '{command}'");
                }

            }
            catch (Exception ex) {
                Console.WriteLine(ex.ToString());
                Environment.ExitCode = ex.HResult;
            }
            finally {
                Console.Out.Flush();
                Console.Error.Flush();
            }
        }

        // Stop the existing OpenSSH server
        private static void Stop(Arguments arguments) {
            Console.WriteLine($"OpenSSH Config Directory: {arguments.SSHConfigDirectory}");

            var filePath = Path.Combine(arguments.SSHConfigDirectory, SSH_PID_FILENAME);
            if (File.Exists(filePath)) {
                Console.WriteLine($"PID file found: {filePath}");
                var lines = File.ReadAllLines(filePath);
                if (lines.Length > 0) {
                    var pid = lines[0];
                    Console.WriteLine($"Found PID {pid}");
                    try {
                        var process = Process.GetProcessById(int.Parse(pid));
                        Console.WriteLine($"Killing PID {pid} ... ");
                        process.Kill(true);
                        Console.WriteLine($"Killed PID {pid}");
                    } catch (ArgumentException) {
                        Console.WriteLine($"PID {pid} not running");
                    }
                }
            }
        }

        // Install & start the OpenSSH server
        private static void Install(Arguments arguments) {
            Console.WriteLine($"OpenSSH Install Directory: {arguments.OpenSSHInstallDirectory}");
            Console.WriteLine($"OpenSSH Config Directory: {arguments.SSHConfigDirectory}");
            Console.WriteLine($"SSH Payloads Directory: {arguments.SSHPayloadsDirectory}");
            Console.WriteLine($"Shell: {arguments.CustomShellLauncher}");

            // Stop the server if it is already running
            try {
                Stop(arguments);
            } catch (Exception e) {
                // Best effort
            }

            // Firewall
            {
                Console.WriteLine("Configuring firewall ... ");

                // Disable the firewall
                FirewallManager.DisableFirewalls();

                // Open up the debugger and SSH port
                FirewallManager.AllowPortThroughFirewall("SSH", 22);

                Console.WriteLine("Configured firewall");
            }

            // xbox user
            {
                // Create our sshd account if it doesn't exist
                if (!AccountManager.ListLocalUsers().ContainsKey(XBOX_USER)) {
                    Console.WriteLine($"Creating user '{XBOX_USER}' ... ");

                    AccountManager.CreateAccount(XBOX_USER, XBOX_PASS);
                    var domainAndAccount = Environment.GetEnvironmentVariable("USERDOMAIN") + @"\" + XBOX_USER;

                    // Add them to the administrators group
                    AccountManager.AddAccountToGroup(domainAndAccount, ADMINISTRATORS_GROUP);

                    // Add all the rights & privileges possible to the account
                    SecurityIdentifier account = (SecurityIdentifier)new NTAccount(domainAndAccount).Translate(typeof(SecurityIdentifier));
                    AccountManager.AddRightToAccount(account, AccountRightsConstants.SeBatchLogonRight);
                    AccountManager.AddRightToAccount(account, AccountRightsConstants.SeInteractiveLogonRight);
                    AccountManager.AddRightToAccount(account, AccountRightsConstants.SeNetworkLogonRight);
                    AccountManager.AddRightToAccount(account, AccountRightsConstants.SeRemoteInteractiveLogonRight);
                    AccountManager.AddRightToAccount(account, AccountRightsConstants.SeServiceLogonRight);
                    AccountManager.AddRightToAccount(account, AccountRightsConstants.SeBatchLogonRight);
                    AccountManager.AddRightToAccount(account, AccountRightsConstants.SeBatchLogonRight);
                    AccountManager.AddRightToAccount(account, AccountRightsConstants.SeBatchLogonRight);
                    AccountManager.AddRightToAccount(account, AccountRightsConstants.SeBatchLogonRight);
                    AccountManager.AddRightToAccount(account, AccountRightsConstants.SeBatchLogonRight);
                    AccountManager.AddRightToAccount(account, AccountRightsConstants.SeBatchLogonRight);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeAssignPrimaryTokenPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeAuditPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeBackupPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeChangeNotifyPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeCreateGlobalPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeCreatePagefilePrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeCreatePermanentPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeCreateSymbolicLinkPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeCreateTokenPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeDebugPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeDelegateSessionUserImpersonatePrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeEnableDelegationPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeImpersonatePrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeIncreaseBasePriorityPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeIncreaseQuotaPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeIncreaseWorkingSetPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeLoadDriverPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeLockMemoryPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeMachineAccountPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeManageVolumePrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeProfileSingleProcessPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeRelabelPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeRemoteShutdownPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeRestorePrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeSecurityPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeShutdownPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeSyncAgentPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeSystemEnvironmentPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeSystemProfilePrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeSystemtimePrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeTakeOwnershipPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeTcbPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeTimeZonePrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeTrustedCredManAccessPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeUndockPrivilege);
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeUnsolicitedInputPrivilege);

                    // Create the user profile premptively
                    AccountManager.CreateProfile(account, XBOX_USER);

                    Console.WriteLine($"Created user '{XBOX_USER}'");
                }
            }

            // xbox-sshd user
            {
                // Create our sshd account if it doesn't exist
                if (!AccountManager.ListLocalUsers().ContainsKey(SSHD_USER)) {
                    Console.WriteLine($"Creating user '{SSHD_USER}' ... ");

                    AccountManager.CreateAccount(SSHD_USER, SSHD_PASS);
                    var domainAndAccount = Environment.GetEnvironmentVariable("USERDOMAIN") + @"\" + SSHD_USER;

                    // Add them to the administrators group
                    AccountManager.AddAccountToGroup(domainAndAccount, ADMINISTRATORS_GROUP);

                    // Add privileges so that the user can impersonate users and set tokens (used for SSHD)
                    SecurityIdentifier account = (SecurityIdentifier)new NTAccount(domainAndAccount).Translate(typeof(SecurityIdentifier));
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeAssignPrimaryTokenPrivilege); // Needed to set tokens when spawning processes as different users
                    AccountManager.AddPrivilegeToAccount(account, AccountPrivilegeConstants.SeTcbPrivilege); // Allows user to assume the identity of any user

                    // Create the user profile premptively
                    AccountManager.CreateProfile(account, SSHD_USER);

                    Console.WriteLine($"Created user '{SSHD_USER}'");
                }
            }

            // SSH install directory
            {
                // Ensure the ssh directory exists
                if (!Directory.Exists(arguments.OpenSSHInstallDirectory)) {
                    throw new Exception($"Folder '{arguments.OpenSSHInstallDirectory}' does not exist");
                }
            }

            // SSH config directory
            {
                // Ensure the ssh directory exists
                if (!Directory.Exists(arguments.SSHConfigDirectory)) {
                    Directory.CreateDirectory(arguments.SSHConfigDirectory);
                }
            }

            // SSH RSA key
            {
                var rsaKeyPath = Path.Combine(arguments.SSHConfigDirectory, SSH_RSA_KEY_FILENAME);

                // Create the RSA key if it does not exist
                if (!File.Exists(rsaKeyPath)) {
                    Console.WriteLine($"Generating SSH RSA key '{rsaKeyPath}' ... ");
                    LaunchProcess(arguments.OpenSSHInstallDirectory, "ssh-keygen.exe", $"-t rsa -b 2048 -N \"\" -f \"{rsaKeyPath}\"");
                    if (!File.Exists(rsaKeyPath)) {
                        throw new Exception($"Error creating SSH RSA key '{rsaKeyPath}'");
                    }
                    Console.WriteLine($"Generated SSH RSA key '{rsaKeyPath}'");
                }

                // Restrict permissions on the RSA key to only the sshd account
                Console.WriteLine($"Restricting SSH RSA key file permissions ... ");
                FileManager.RestrictFileAccess(rsaKeyPath, SSHD_USER);
                Console.WriteLine($"Restricted SSH RSA key file permissions");
            }

            // SSH config file
            {
                var configPath = Path.Combine(arguments.SSHConfigDirectory, SSH_CONFIG_FILENAME);

                // Create the config file if it does not exist
                if (!File.Exists(configPath)) {
                    Console.WriteLine($"Creating SSH config '{configPath}' ... ");

                    File.WriteAllText(configPath, @"
HostKey {SSH_CONFIG_DIR}\xbox_ssh_rsa_key
PidFile {SSH_CONFIG_DIR}\sshd.pid

Port 22
ListenAddress 0.0.0.0
AddressFamily any

Subsystem	sftp	{SSH_INSTALL_DIR}\sftp-server.exe
".Replace("{SSH_INSTALL_DIR}", arguments.OpenSSHInstallDirectory)
.Replace("{SSH_CONFIG_DIR}", arguments.SSHConfigDirectory));

                    Console.WriteLine($"Created SSH config '{configPath}'");
                }
            }

            // Default shell
            {
                if (!string.IsNullOrEmpty(arguments.CustomShellLauncher) && arguments.CustomShellLauncher != "cmd.exe") {
                    Console.WriteLine($"Overriding shell: {arguments.CustomShellLauncher}");
                    Registry.SetValue(OPENSSH_REGISTRY_PATH, OPENSSH_DEFAULTSHELL_REGISTRY_KEY, @"C:\Windows\system32\cmd.exe");
                    Registry.SetValue(OPENSSH_REGISTRY_PATH, OPENSSH_DEFAULTSHELLARGUMENTS_REGISTRY_KEY, $"/C \"{arguments.CustomShellLauncher}\"");
                }
                else {
                    Console.WriteLine($"Utilizing default cmd.exe shell");
                    using (var reg = Registry.LocalMachine.OpenSubKey(OPENSSH_REGISTRY_ROOT, true)) {
                        reg.DeleteValue(OPENSSH_DEFAULTSHELL_REGISTRY_KEY, false);
                        reg.DeleteValue(OPENSSH_DEFAULTSHELLARGUMENTS_REGISTRY_KEY, false);
                    }
                }
            }

            // Scheduled task definition
            var xmlPath = Path.Combine(arguments.SSHConfigDirectory, SSH_TASK_XML_FILENAME);
            {
                Console.WriteLine($"Creating scheduled task XML '{xmlPath}' ... ");

                File.WriteAllText(xmlPath, @"<?xml version=""1.0"" encoding=""UTF-16""?>
<Task version=""1.2"" xmlns=""http://schemas.microsoft.com/windows/2004/02/mit/task"">
<RegistrationInfo>
<Author>NT AUTHORITY\SYSTEM</Author>
<Description>OpenSSH Server</Description>
<URI>SSH</URI>
</RegistrationInfo>
<Principals>
<Principal>
	<UserId>XboxOne\xbox-sshd</UserId>
    <RunLevel>HighestAvailable</RunLevel>
</Principal>
</Principals>
<Settings>
<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
<AllowStartOnDemand>true</AllowStartOnDemand>
<AllowHardTerminate>true</AllowHardTerminate>
<StartWhenAvailable>true</StartWhenAvailable>
<Priority>8</Priority>
<RestartOnFailure>
	<Count>100</Count>
	<Interval>P31D</Interval>
</RestartOnFailure>
<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
</Settings>
<Triggers>
<BootTrigger>
    <Enabled>true</Enabled>
</BootTrigger>
<RegistrationTrigger>
    <Enabled>true</Enabled>
	<Repetition>
	<Interval>PT1M</Interval>
	</Repetition>
</RegistrationTrigger>
</Triggers>
<Actions Context=""Author"">
<Exec>
    <Command>{PAYLOADS_DIR}\sshd_task.bat</Command>
</Exec>
</Actions>
</Task>
".Replace("{PAYLOADS_DIR}", arguments.SSHPayloadsDirectory));

                Console.WriteLine($"Created scheduled task XML '{xmlPath}'");
            }

            // Schedule task to launch sshd server in the background
            {
                Console.WriteLine($"Scheduling task '{xmlPath}'");
                LaunchProcess(@"C:\Windows\system32", "schtasks.exe", $"/create /f /tn SSH /xml {xmlPath} /ru {SSHD_USER} /rp {SSHD_USER}");
                Console.WriteLine($"Scheduled task '{xmlPath}'");
            }

            Console.WriteLine("\nInstallation complete and SSH server online!");
        }

        // Shutdown and uninstall the OpenSSH server
        private static void Uninstall(Arguments arguments) {
            Console.WriteLine($"OpenSSH Config Directory: {arguments.SSHConfigDirectory}");

            // Stop the server
            try {
                Stop(arguments);
            }catch(Exception e) {
                Console.WriteLine($"ERROR: {e.ToString()}");
            }

            // Delete the scheduled task
            try {
                Console.WriteLine($"Deleting scheduled task");
                LaunchProcess(@"C:\Windows\system32", "schtasks.exe", $"/delete /F /tn SSH");
                Console.WriteLine($"Deleting scheduled");
            }catch(Exception e) {
                Console.WriteLine($"ERROR: {e.ToString()}");
            }

            // Delete the scheduled task XML
            var xmlPath = Path.Combine(arguments.SSHConfigDirectory, SSH_TASK_XML_FILENAME);
            try {
                Console.WriteLine($"Deleting file '{xmlPath}' ...");
                File.Delete(xmlPath);
                Console.WriteLine($"Deleted file '{xmlPath}'");
            }catch(Exception e) {
                Console.WriteLine($"ERROR: {e.ToString()}");
            }

            // Delete the SSH config file
            try{
                var configPath = Path.Combine(arguments.SSHConfigDirectory, SSH_CONFIG_FILENAME);
                Console.WriteLine($"Deleting file '{configPath}' ...");
                File.Delete(configPath);
                Console.WriteLine($"Deleted file '{configPath}'");
            }catch(Exception e) {
                Console.WriteLine($"ERROR: {e.ToString()}");
            }

            // Delete the RSA key
            try{
                var rsaKeyPath = Path.Combine(arguments.SSHConfigDirectory, SSH_RSA_KEY_FILENAME);
                Console.WriteLine($"Deleting file '{rsaKeyPath}' ...");
                File.Delete(rsaKeyPath);
                Console.WriteLine($"Deleted file '{rsaKeyPath}'");
            }catch(Exception e) {
                Console.WriteLine($"ERROR: {e.ToString()}");
            }

            // Clear the registry
            try{
                Console.WriteLine($"Deleting registry entries ...");
                using (var reg = Registry.LocalMachine.OpenSubKey(OPENSSH_REGISTRY_ROOT, true)) {
                    reg.DeleteValue(OPENSSH_DEFAULTSHELL_REGISTRY_KEY, false);
                    reg.DeleteValue(OPENSSH_DEFAULTSHELLARGUMENTS_REGISTRY_KEY, false);
                }
                Console.WriteLine($"Deleted registry entries");
            }catch(Exception e) {
                Console.WriteLine($"ERROR: {e.ToString()}");
            }

            // Delete the xbox-sshd user profile
            try {
                Console.WriteLine($"Deleting user '{SSHD_USER}' profile ...");
                SecurityIdentifier account = (SecurityIdentifier)new NTAccount(SSHD_USER).Translate(typeof(SecurityIdentifier));
                AccountManager.DeleteProfile(account);
                Console.WriteLine($"Deleted user '{SSHD_USER}' profile");
            } catch (Exception e) {
                Console.WriteLine($"ERROR: {e.ToString()}");
            }

            // Delete the xbox-sshd user
            try {
                Console.WriteLine($"Deleting user '{SSHD_USER}' ...");
                AccountManager.DeleteAccount(SSHD_USER, SSHD_PASS);
                Console.WriteLine($"Deleted user '{SSHD_USER}'");
            }catch(Exception e) {
                Console.WriteLine($"ERROR: {e.ToString()}");
            }

            // Delete the xbox-sshd user directory
            try {
                var homeDirectory = Path.Combine(Environment.GetEnvironmentVariable("ProfileDrive"), "Users", SSHD_USER);
                Console.WriteLine($"Deleting folder '{homeDirectory}' ...");
                Directory.Delete(homeDirectory, true);
                Console.WriteLine($"Deleted user '{homeDirectory}'");
            }catch (Exception e) {
                Console.WriteLine($"ERROR: {e.ToString()}");
            }

            // Delete the xbox user profile
            try {
                Console.WriteLine($"Deleting user '{XBOX_USER}' profile ...");
                SecurityIdentifier account = (SecurityIdentifier)new NTAccount(XBOX_USER).Translate(typeof(SecurityIdentifier));
                AccountManager.DeleteProfile(account);
                Console.WriteLine($"Deleted user '{XBOX_USER}' profile");
            }catch (Exception e) {
                Console.WriteLine($"ERROR: {e.ToString()}");
            }

            // Delete the xbox user
            try {
                Console.WriteLine($"Deleting user '{XBOX_USER}' ...");
                AccountManager.DeleteAccount(XBOX_USER, SSHD_PASS);
                Console.WriteLine($"Deleted user '{XBOX_USER}'");
            }catch(Exception e) {
                Console.WriteLine($"ERROR: {e.ToString()}");
            }

            // Delete the xbox user directory
            try {
                var homeDirectory = Path.Combine(Environment.GetEnvironmentVariable("ProfileDrive"), "Users", XBOX_USER);
                Console.WriteLine($"Deleting folder '{homeDirectory}' ...");
                Directory.Delete(homeDirectory, true);
                Console.WriteLine($"Deleted user '{homeDirectory}'");
            } catch (Exception e) {
                Console.WriteLine($"ERROR: {e.ToString()}");
            }

            Console.WriteLine("\nUninstall Complete!");
        }

        private struct Arguments {
            public string OpenSSHInstallDirectory;
            public string SSHConfigDirectory;
            public string SSHPayloadsDirectory;
            public string CustomShellLauncher;
        }

        private static Arguments ParseArguments(string[] args) {
            var arguments = new Arguments() {
                OpenSSHInstallDirectory = @"S:\ssh",
                SSHConfigDirectory = @"S:\ssh",
                SSHPayloadsDirectory = @"D:\xbox\payloads\ssh",
                CustomShellLauncher = ""
            };
            // Skip the first argument as it is the command
            for (int i = 1; i<args.Length; i+=2) {
                if ((i + 1) == args.Length) {
                    throw new Exception($"Must be an even number of arguments ({args.Length}): {string.Join(",", args)}");
                }
                switch (args[i]) {
                    case "--ssh_dir":
                        arguments.OpenSSHInstallDirectory = args[i + 1];
                        break;
                    case "--config_dir":
                        arguments.SSHConfigDirectory = args[i + 1];
                        break;
                    case "--payloads_dir":
                        arguments.SSHPayloadsDirectory = args[i + 1];
                        break;
                    case "--custom_shell":
                        arguments.CustomShellLauncher = args[i + 1];
                        break;
                }
            }
            return arguments;
        }

        private static void LaunchProcess(string workingDirectory, string fileName, string command) {

            var processInformation = new NativeBridge.PROCESS_INFORMATION();
            var startupInfo = new NativeBridge.STARTUPINFO();
            uint dwCreationFlags = 0;
            string applicationName = null;
            string cmd = $"{workingDirectory}\\{fileName} {command}";

            if (!NativeBridge.CreateProcessW(applicationName, cmd,
                0, 0, true, dwCreationFlags, 0, null, ref startupInfo, out processInformation)) {
                Console.WriteLine($"Unable to create process: 0x{NativeBridge.GetLastError():X}");
                return;
            }
            Console.WriteLine($"Executing {cmd} (ProcessId: {processInformation.dwProcessId})");
            WaitForSingleObject(processInformation.hProcess, 0xFFFFFFFF);

            uint exitCode = 0x666;
            GetExitCodeProcess(processInformation.hProcess, out exitCode);

            if (exitCode != 0) {
                //Console.WriteLine($"ERROR: {fileName} returned exit code 0x{exitCode:X}");
                throw new Win32Exception((int)exitCode, $"ERROR: {fileName} returned exit code 0x{exitCode:X}");
            }

            Console.WriteLine($"Process completed sucessfully");
        }
    }
}
