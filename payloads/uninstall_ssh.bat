@echo off
rem Installs & starts SSH via our custom launcher
rem This file must sit in a directory whose parent directory contains the Silverton init.bat

rem Perform initialization
call %~dp0\..\init.bat

rem Load our configuration
call %~dp0\config.bat

rem The current working directory to use when invoking the command
set CWD=C:\\

rem The command we want to run
set COMMAND=%SSH_PAYLOADS_DIR%\AnimaSSH.exe uninstall --config_dir "%SSH_CONFIG_DIR%"

rem Execute the command (via our custom launcher)
%DOTNET_PATH% msbuild /nologo "%MSBUILD_XML_PATH%" ^
		-property:LauncherDirectory="%LAUNCHER_DIRECTORY%" ^
		-property:LogLevel="%LOG_LEVEL%" ^
		-property:WorkingDirectory="%CWD%" ^
		-property:Command="%COMMAND%"