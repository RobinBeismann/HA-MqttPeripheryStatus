Import-Module -Name ".\MQTTnet.dll"

#region Static Definitions
# Device and Binary Definition
[array]$global:devices = "microphone", "webcam"
[array]$global:ignoresBinaries = "rundll32.exe"
$global:mqttTopic = "DeviceStatus"

# Registry BasePath
$RegHive = "HKEY_USERS"
$RegKeyPath = "{0}\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\{1}\NonPackaged"
$global:RegPath = "$RegHive\$RegKeyPath"

$RegSettingsPath = "HKEY_CURRENT_USER\SOFTWARE\RobinBeismann\DeviceStatus"

$SourceIdentifier = "DeviceStatusChange"
#endregion

#region Functions
function Get-DeviceStatus(){    
    $result = @{}

    $global:devices | ForEach-Object {
        $device = $_    
        $devicePath = $global:RegPath -f $global:UserSID,$device
        if(Test-Path -Path "Registry::$devicePath" -ErrorAction SilentlyContinue){
            $inUse = $false
            $inUseBy = "-"
            Get-ChildItem -Path "Registry::$devicePath" | ForEach-Object {
                $name = $_.PSChildName
                $lastHashtag = $name.LastIndexOf("#")
                $binaryName = $name.Substring($lastHashTag+1,$name.Length-$lastHashTag-1)
                
                if($binaryName -in $global:ignoresBinaries){
                    return;
                }

                if(!$result.$device){
                    $result.$device = @{}
                }
                if(!$result.$device.apps){
                    $result.$device.apps = @{}
                }
            
                $Start = 0
                if("LastUsedTimeStart" -in $_.Property){
                    $Start = $_.GetValue("LastUsedTimeStart")
                    if(
                        !($result.$device.LastUsedTimeStartFileTime) -or
                        ($result.$device.LastUsedTimeStartFileTime -lt $Start)
                    ){
                        $result.$device.LastUsedTimeStartFileTime = $Start
                        $result.$device.LastUsedTimeStartDateTime = (Get-Date -Format "yyyyMMddHHmmss" -Date ([datetime]::FromFileTime($Start)) )
                        $result.$device.LastUsedTimeStartApp = $binaryName 
                    }
                }
                $Stop = 0
                if("LastUsedTimeStop" -in $_.Property){
                    $Stop = $_.GetValue("LastUsedTimeStop")
                    if(
                        !($result.$device.LastUsedTimeStopFileTime) -or
                        ($result.$device.LastUsedTimeStopFileTime -lt $Stop)
                    ){
                        $result.$device.LastUsedTimeStopFileTime = $Stop
                        $result.$device.LastUsedTimeStopDateTime = (Get-Date -Format "yyyyMMddHHmmss" -Date ([datetime]::FromFileTime($Stop)) )
                        $result.$device.LastUsedTimeStopApp = $binaryName 
                    }
                    if($Stop -eq 0){
                        $inUse = $true
                        $inUseBy = $binaryName
                    }
                }

                $result.$device.apps.$binaryName = @{
                    StartFileTime = $Start
                    StartDateTime = (Get-Date -Format "yyyyMMddHHmmss" -Date ([datetime]::FromFileTime($Start)) )
                    StopFileTime = $Stop
                    StopDateTime = (Get-Date -Format "yyyyMMddHHmmss" -Date ([datetime]::FromFileTime($Stop)) )
                }
            }
            $result.$device.InUse = $inUse
            $result.$device.InUseBy = $inUseBy
        }
    }

    return $result
}

function Send-Notification(){
    $status = Get-DeviceStatus
    $status.GetEnumerator() | ForEach-Object {
        $device = $_.Name
        $_.Value.Apps.GetEnumerator() | ForEach-Object {
            $app = $_.Name
            $_.Value.GetEnumerator() | Foreach-Object {
                $ValName = $_.Name
                $Val = $_.Value
                
                Send-MqttMessage -Topic "$global:mqttTopic/$env:COMPUTERNAME/$device/$app/$valName" -Payload $Val
            }
        }

        $_.Value.GetEnumerator() | Where-Object { $_.Name -ne "apps" } | ForEach-Object {            
            $ValName = $_.Name
            $Val = $_.Value
            
            Send-MqttMessage -Topic "$global:mqttTopic/$env:COMPUTERNAME/$device/$valName" -Payload $Val
        }

        # Send Home Assistant Binary sensors        
        Send-MqttMessage -Topic "homeassistant/binary_sensor/$env:COMPUTERNAME/$device/config" -Payload (ConvertTo-Json -Depth 10 -InputObject @{
            payload_off = "False"
            payload_on = "True"
            name = "$env:COMPUTERNAME $device in-use"
            state_topic = "$global:mqttTopic/$env:COMPUTERNAME/$device/InUse"
            enabled_by_default = $true
        })
    }
}
$global:mqttOptions = $null
$global:mqttFactory = $null
$global:mqttClient = $null
function Send-MqttMessage([string]$Topic,[string]$Payload){
    #region Connection
    $cancellationToken = [System.Threading.CancellationToken]::None
    if(!$global:mqttFactory){
        $global:mqttFactory = [MQTTnet.MqttFactory]::new()
    }
    if(!$global:mqttClient){
        $global:mqttClient = $mqttFactory.CreateMqttClient()
    }
    if(!$global:mqttOptions){
        $global:mqttOptions = [MQTTnet.Client.MqttClientOptionsBuilder]::new()
        Write-Host("[$(Get-Date)] Initializing MQTT to `"$($global:mqttServerName)`"..")
        switch($global:mqttServerOption){
            websocket {              
                Write-Host("[$(Get-Date)] Initializing MQTT via Websocket..")
                $null = $global:mqttOptions.WithWebSocketServer($global:mqttServerName)
            }
            tcp {
                Write-Host("[$(Get-Date)] Initializing MQTT via TCP..")
                $null = $global:mqttOptions.WithTcpServer($global:mqttServerName)
            }
        }
        if($global:mqttServerTls){
            Write-Host("[$(Get-Date)] Enabling TLS..")
            $null = $global:mqttOptions.WithTls()
        }
        if($global:mqttServerCredentials -eq "true"){      
            Write-Host("[$(Get-Date)] Enabling Authentication (User: `"$($global:mqttServerCreds.UserName)`")..")      
            $null = $global:mqttOptions.WithCredentials($global:mqttServerCreds.UserName, $global:mqttServerCreds.GetNetworkCredential().Password)
        }
        $null = $global:mqttOptions.WithCleanSession()
        $null = $global:mqttOptions.WithClientId($env:COMPUTERNAME)
    }

    if(
        $global:mqttClient -and
        !$Global:mqttClient.IsConnected
    ){
        Write-Host("[$(Get-Date)] Connecting async..")
        $null = $global:mqttClient.ConnectAsync($global:mqttOptions.Build(),$cancellationToken)
        $maxTries = 30
        $counter = 0
        while(
            !$Global:mqttClient.IsConnected -and
            $counter -le $maxTries
        ){
            Start-Sleep -Milliseconds 100
            Write-Verbose("[$(Get-Date)] Try $Counter/$maxTries")
            $counter++
        }
        Write-Host("[$(Get-Date)] Connection Status: $($Global:mqttClient.IsConnected)")
    }
    
    #endregion

    $message = [MQTTnet.MqttApplicationMessageBuilder]::new()
    $null = $message.WithTopic($Topic)
    $null = $message.WithPayload($Payload)
    if($Global:mqttClient.IsConnected){
        $null = $global:mqttClient.PublishAsync($message.Build(),$cancellationToken)
        Write-Verbose("[$(Get-Date)] Sent `"$Payload`" to `"$Topic`".")
    }
}

# .NET methods for hiding/showing the console in the background
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();

[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
'

function Show-Console
{
    $consolePtr = [Console.Window]::GetConsoleWindow()

    # Hide = 0,
    # ShowNormal = 1,
    # ShowMinimized = 2,
    # ShowMaximized = 3,
    # Maximize = 3,
    # ShowNormalNoActivate = 4,
    # Show = 5,
    # Minimize = 6,
    # ShowMinNoActivate = 7,
    # ShowNoActivate = 8,
    # Restore = 9,
    # ShowDefault = 10,
    # ForceMinimized = 11

    [Console.Window]::ShowWindow($consolePtr, 4)
    $global:WindowHidden = $false
}

function Hide-Console
{
    $consolePtr = [Console.Window]::GetConsoleWindow()
    [Console.Window]::ShowWindow($consolePtr, 0)
    $global:WindowHidden = $true
}
$global:WindowHidden = $false
function Get-ConsoleHiddenState
{
    return $global:WindowHidden
}

# Load Functions into global store so we can use them in runspaces later on
$functionNames = "Get-DeviceStatus", "Send-Notification", "Send-MqttMessage", "Hide-Console", "Show-Console"
$global:scriptFunctions = Get-ChildItem -Path 'function:' | Where-Object { $_.Name -in $functionNames } | Foreach-Object {
    [PSCustomObject]@{
        FunctionName = $_.Name
        FunctionCode = (Get-Item -Path "Function:\$($_.Name)").Definition
    }
}
#endregion

#region Configuration
if(!(Test-Path -Path "Registry::$RegSettingsPath")){
    $null = New-Item -Path "Registry::$RegSettingsPath" -Force
}
[array]$ConfigKeys = (Get-Item -Path "Registry::$RegSettingsPath").Property

$ConfigItems = [ordered]@{
    "mqttServerName" = @{
        Description = "MQTT Server Name"
    }
    "mqttServerOption" = @{
        Description = "MQTT Connection Protocol"
        ValidOptions = "websocket", "tcp"
    }
    "mqttServerTls" = @{
        Description = "Enable TLS for MQTT"
        ValidOptions = "true", "false"
    }
    "mqttServerCredentials" = @{
        Description = "Enable Authentication for MQTT"
        ValidOptions = "true", "false"
    }
}

# Get Configuration from Registry or ask for Configuration
$ConfigItems.GetEnumerator() | Foreach-Object {
    $option = $_.Name
    $description = $_.Value.Description
    $validOptions = $_.Value.ValidOptions

    if(
        ($option -notin $ConfigKeys) -or
        (
            ($savedOption = (Get-ItemProperty -Path "Registry::$RegSettingsPath" -Name $option).$option) -and
            (
                $validOptions -and
                ($savedOption -notin $validOptions)
            )
        )
    ){
        Do{ 
            if($validOptions){
                $savedOption = Read-host "$description (Valid Options: $($validOptions -join ", "))"
            }else{
                $savedOption = Read-host $description
            }
        }while(
            $validOptions -and
            ($savedOption -notin $validOptions)
        )
        Set-ItemProperty -Path "Registry::$RegSettingsPath" -Name $option -Value $savedOption
    }
    Set-Variable -Name $option -Scope 'Global' -Value $savedOption   
}

# Check if Credential Usage is enabled and read credentials if needed
$option = "mqttServerCreds"
$cred = $null
if(
    $global:mqttServerCredentials -eq "true"
){
    # Try finding and parsing existing credentials, if not, ask for new ones
    try{
        if($option -in $ConfigKeys){
            $serializedObject = (Get-ItemProperty -Path "Registry::$RegSettingsPath" -Name $option).$option
            $cred = [System.Management.Automation.PSSerializer]::Deserialize($serializedObject)
        }
    }catch{
        Write-Host("[$(Get-Date)] Unable to parse existing credentials..")
    }
    if(
        !$cred
    ){
        Write-Host("[$(Get-Date)] Unable to read or find existing credentials, asking for new ones..")
        $cred = Get-Credential -Message "Please enter MQTT Credentials."
        Set-ItemProperty -Path "Registry::$RegSettingsPath" -Name $option -Value ([System.Management.Automation.PSSerializer]::Serialize($cred))
    }
    Set-Variable -Name $option -Scope 'Global' -Value $cred
}
#endregion

#region Build Registry Paths
# Get User SID (we can only subscribe registries under HKU and not HKCU)
$global:UserSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
# Build our subscribing root paths
$RootPathFilter = ($devices | ForEach-Object {
    "RootPath='$($RegKeyPath.Replace("\","\\"))'" -f $UserSID,$_
}) -join " OR "
#endregion

#region Initialize GUI and pass functions
$syncHash = [hashtable]::Synchronized(@{})
$syncHash.Add('scriptFunctions', $global:scriptFunctions)
$syncHash.Add('WindowHidden', $global:WindowHidden)
$newRunspace =[runspacefactory]::CreateRunspace()
$newRunspace.ApartmentState = "STA"
$newRunspace.ThreadOptions = "ReuseThread"         
$newRunspace.Open()
$newRunspace.SessionStateProxy.SetVariable("syncHash",$syncHash)          
$psCmd = [PowerShell]::Create().AddScript({   
    # Add assemblies for WPF and Mahapps
    [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')    | out-null
    [System.Reflection.Assembly]::LoadWithPartialName('presentationframework')   | out-null
    [System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')    | out-null
    [System.Reflection.Assembly]::LoadWithPartialName('WindowsFormsIntegration') | out-null

    # Choose an icon to display in the systray
    $icon = [System.Drawing.Icon]::ExtractAssociatedIcon("C:\Windows\HelpPane.exe") 
    
    # Add the systray icon 
    $Main_Tool_Icon = New-Object System.Windows.Forms.NotifyIcon
    $Main_Tool_Icon.Text = "MQTT Periphery Usage"
    $Main_Tool_Icon.Icon = $icon
    $Main_Tool_Icon.Visible = $true
    $syncHash.scriptFunctions.GetEnumerator() | ForEach-Object {
        Set-Item -Path "Function:\$($_.FunctionName)" -Value $_.FunctionCode
    }
    
    # Add Show Console
    
    $Menu_Show = New-Object System.Windows.Forms.MenuItem
    $Menu_Show.Checked = $syncHash.WindowHidden
    $Menu_Show.Text = "Hide"
    $Menu_Show.Checked = $false
    # Action after clicking on the Exit context menu
    $Menu_Show.Add_Click({
        switch($Menu_Show.Checked){
            $false {
                Hide-Console
                $Menu_Show.Checked = $true
            }
            $true {
                Show-Console
                $Menu_Show.Checked = $false
            }
        }
    })

    # Add menu exit
    $Menu_Exit = New-Object System.Windows.Forms.MenuItem
    $Menu_Exit.Text = "Exit"
    # Action after clicking on the Exit context menu
    $Menu_Exit.add_Click({
        $Main_Tool_Icon.Visible = $false
        #[void][System.Windows.Forms.Application]::Exit() 
        exit;
    })

    $contextmenu = New-Object System.Windows.Forms.ContextMenu
    $Main_Tool_Icon.ContextMenu = $contextmenu
    $Main_Tool_Icon.contextMenu.MenuItems.AddRange($Menu_Show)
    $Main_Tool_Icon.contextMenu.MenuItems.AddRange($Menu_Exit)

    Hide-Console
    $Menu_Show.Checked = $true

    # Use a Garbage colection to reduce Memory RAM
    # https://dmitrysotnikov.wordpress.com/2012/02/24/freeing-up-memory-in-powershell-using-garbage-collector/
    # https://docs.microsoft.com/fr-fr/dotnet/api/system.gc.collect?view=netframework-4.7.2
    [System.GC]::Collect()
    
    # Create an application context for it to all run within - Thanks Chrissy
    # This helps with responsiveness, especially when clicking Exit - Thanks Chrissy
    $appContext = New-Object System.Windows.Forms.ApplicationContext
    [void][System.Windows.Forms.Application]::Run($appContext)
})
$psCmd.Runspace = $newRunspace
$data = $psCmd.BeginInvoke()
#endregion

#region WMI Subscriber
# Set up splatting for the WMI Event Subscriber
$WMI = @{
    Query ="Select * from RegistryTreeChangeEvent where Hive='$RegHive' AND ($RootPathFilter)"
    Action = {
        Write-Host("[$(Get-Date)] Event detected!")
        try{
            # Load Functions into Runspace
            $global:scriptFunctions.GetEnumerator() | ForEach-Object {
                Set-Item -Path "Function:\$($_.FunctionName)" -Value $_.FunctionCode
            }
            # Send Notification
            Send-Notification
        }catch{
            Write-Host("[$(Get-Date)] Failed to invoke notification, error: $_")
        }
    }
    SourceIdentifier = $SourceIdentifier
}

# Register WMI Event Subscriber
Get-EventSubscriber | Where-Object {
    $_.SourceIdentifier -eq $SourceIdentifier
} | ForEach-Object {
    $_ | Unregister-Event
}
$Null = Register-WMIEvent @WMI

# Loop all 60 seconds, send heartbeat and wait again for 60 seconds
while(1){
    Write-Host("[$(Get-Date)] Waiting for Event..")
    $null = Send-Notification
    Send-MqttMessage -Topic "$global:mqttTopic/$env:COMPUTERNAME/LastStatus" -Payload (Get-Date -Format "yyyyMMddHHmmss")
    Wait-Event -SourceIdentifier 'DeviceStatusChange' -Timeout 60
}
#endregion