@echo off
rem Launches sshd.exe via our custom launcher, to be called by a scheduled task created by install_ssh.bat
rem This file must sit in a directory whose parent directory contains the Silverton init.bat

rem Perform initialization
call %~dp0\..\init.bat

rem Load our configuration
call %~dp0\config.bat

rem Kill the existing SSH server (via our custom launcher)
set COMMAND=%SSH_PAYLOADS_DIR%\AnimaSSH.exe stop --config_dir "%SSH_CONFIG_DIR%"
%DOTNET_PATH% msbuild /nologo "%MSBUILD_XML_PATH%" ^
		-property:LauncherDirectory="%LAUNCHER_DIRECTORY%" ^
		-property:LogLevel="%LOG_LEVEL%" ^
		-property:WorkingDirectory="%SSH_PAYLOADS_DIR%" ^
		-property:Command="%COMMAND%"

rem The command we want to run
set COMMAND=sshd.exe -e -f %SSH_CONFIG_DIR%\sshd_config.txt

rem Clear the log file
set > %SSHD_LOG_FILE%

echo %DATE% %TIME% - Launching as %USERDOMAIN%\%USERNAME% >> %SSHD_LOG_FILE%
echo ##################### >> %SSHD_LOG_FILE%

rem Execute the command (via our custom launcher)
"%DOTNET_PATH%" msbuild /nologo "%MSBUILD_XML_PATH%" ^
		-property:LauncherDirectory="%LAUNCHER_DIRECTORY%" ^
		-property:LogLevel="%LOG_LEVEL%" ^
		-property:WorkingDirectory="%SSH_INSTALL_DIR%" ^
		-property:Command="%COMMAND%" ^
	>> %SSHD_LOG_FILE% 2>&1

echo ##################### >> %SSHD_LOG_FILE%
echo sshd exited with code %errorlevel%  >> %SSHD_LOG_FILE%