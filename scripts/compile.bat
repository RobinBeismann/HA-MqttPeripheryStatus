REM Enable Extensions and jump into current directory
@setlocal enableextensions
@cd /d "%~dp0"

REM Clone PS2Exe
IF exist "../helper/ps2exe/" ( rmdir "../helper/ps2exe/" /S /Q )
git clone https://github.com/MScholtes/PS2EXE.git ..\helper\ps2exe

REM Compile our powershell script
powershell.exe -ExecutionPolicy Unrestricted -NoProfile -Command "Import-Module -Name '..\helper\ps2exe\Module\ps2exe.psm1'; Invoke-ps2exe -inputFile '..\bin\Mqtt_Periphery_Usage.ps1' -outputFile '..\bin\Mqtt_Periphery_Usage.exe'"

pause