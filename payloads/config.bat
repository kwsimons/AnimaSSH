rem Configuration script, sets environment variables used by SSH scripts

rem The location of the OpenSSH executables
set SSH_INSTALL_DIR=C:\Windows\System32\OpenSSH
rem set SSH_INSTALL_DIR=D:\xbox\ssh

rem SSH config directory
set SSH_CONFIG_DIR=S:\ssh

rem SSH payload directory
set SSH_PAYLOADS_DIR=%LAUNCHER_DIRECTORY%\..\ssh

rem Path to custom shell to use for SSH sessions
set SHELL=cmd.exe
rem set SHELL=%LAUNCHER_DIRECTORY%\..\powershell.bat

rem Log file
set SSHD_LOG_FILE=%SSH_CONFIG_DIR%\log.txt