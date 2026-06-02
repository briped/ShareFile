param(
    [Parameter()]
    [System.IO.DirectoryInfo]
    $Destination = 'C:\ShareFileDownload'
    ,
    [Parameter()]
    [Alias('Subdomain')]
    [string]
    $Account
    ,
    [Parameter()]
    [ValidateSet('US', 'EU')]
    [string]
    $Region = 'EU'
)
Start-Transcript -Path (Join-Path -Path $PSScriptRoot -ChildPath "Transcript-$(Get-Date -Format FileDateTime)")
##### BEGIN: Initial configuration, variables and setup.
switch ($PSVersionTable.PSVersion.Major) {
    5 { $ModuleName = 'ShareFile'; break }
    7 { $ModuleName = 'ShareFile-Core'; break }
    default { throw "The ShareFile PowerShell module only supports version 5.x and 7.x" }
}
if (!($SfModule = Get-Module -Name $ModuleName)) {
    try {
        Write-Host "Importing module: ${ModuleName}"
        $SfModule = Import-Module -PassThru -Name $ModuleName
    }
    catch {
        throw "Make sure the ShareFile PowerShell module is installed. https://github.com/sharefile-org/ShareFile-PowerShell-Module"
    }
}
switch ($Region) {
       'EU' { $Domain = "sf-api.eu"; break }
    default { $Domain = "sf-api.com" }
}

$DestinationChildren = @{
    Employees = @{
        Name = 'Employees'
        Path = $null
    }
    Shared    = @{
        Name = 'Shared'
        Path = $null
    }
}
foreach ($DestinationChild in $DestinationChildren.Keys) {
    $DestinationChildren.${DestinationChild}.Path = Join-Path -Path $Destination -ChildPath $DestinationChildren.${DestinationChild}.Name
    if (!(Test-Path -PathType Container -Path $DestinationChildren.${DestinationChild}.Path)) {
        try {
            New-Item -Force -ItemType Directory -Path $DestinationChildren.${DestinationChild}.Path
        }
        catch { $_ }
    }
}
##### END: Initial configuration, variables and setup.


##### BEGIN: Connect to ShareFile.
Write-Host "Authenticating to ShareFile ..."
$SfAuthFile = Join-Path -Path $env:USERPROFILE -ChildPath "${Account}.${Domain}.sfps"
if (!(Test-Path -PathType Leaf -Path $SfAuthFile)) {
    $Attributes = @{
        Account    = $Account
        Domain     = $Domain
        Name       = $SfAuthFile
    }
    Write-Verbose -Message "New-SfClient $($Attributes|ConvertTo-Json -Compress)"
    try {
    $SfClient = New-SfClient @Attributes
    } catch { throw $_ }
}
if (!$SfClient) {
    Write-Host '... using stored credentials: ' -NoNewline
    Write-Host $SfAuthFile -ForegroundColor Cyan
    Write-Verbose -Message "Get-SfClient -Name $SfAuthFile"
    try {
        $SfClient = Get-SfClient -Name $SfAuthFile
    } catch { throw $_ }
}
##### END: Connect to ShareFile.


##### BEGIN: Connect ShareFile PSDrive.
$SfDrive = (Get-PSDrive -PSProvider ShareFile).Name
if (!$SfDrive) {
    $SfDrive = 'ShareFile'
    $Attributes = @{
        PSProvider = 'ShareFile'
        Name       = $SfDrive
        Client     = $SfClient
        Root       = '/'
    }
    Write-Host "Connecting ShareFile drive: ${Name}"
    Write-Verbose -Message "New-PSDrive $($Attributes|ConvertTo-Json -Compress)"
    try {
        New-PSDrive @Attributes
    } catch { throw $_ }
}
##### END: Connect ShareFile PSDrive.


##### BEGIN: All Employees Items
# Get allEmployee accounts
$Attributes = @{
    Client = $SfClient
    Method = 'GET'
    Entity = 'Accounts/Employees'
    Select = 'Id,Email'
}
Write-Host "Getting all employee accounts."
Write-Verbose -Message "Send-SfRequest $($Attributes|ConvertTo-Json -Compress)"
try {
    $Employees = Send-SfRequest @Attributes
} catch { throw $_ }

# Loop through all Employees HomeFolder
$Counter0 = 0
foreach ($Employee in $Employees) {
    $Counter0++
    $Progres0Attributes = @{
        Id = 0
        Activity = 'All Employee folders'
        CurrentOperation = "$($Employee.Email) ($($Employee.Id))"
        PercentComplete = ($Counter0 / $Employees.Count) * 100
    }
    Write-Progress @Progres0Attributes
    $Attributes = @{
        Client = $SfClient
        Method = 'GET'
        Entity = "Users($($Employee.Id))/HomeFolder"
        Select = 'Id,Email'
        Expand = 'Children'
    }
    Write-Verbose -Message "Send-SfRequest $($Attributes|ConvertTo-Json -Compress)"
    $EmployeeHomeFolder = Send-SfRequest @Attributes

    # Get 'current' folder items.
    $Attributes = @{
        Client = $SfClient
        Entity = 'Items'
        Id     = $EmployeeHomeFolder.Id
    }
    Write-Verbose -Message "Send-SfRequest $($Attributes|ConvertTo-Json -Compress)"
    $Source = Send-SfRequest @Attributes
    $SourcePath = "${SfDrive}:/$($Source.Name)"

    # Download 'current' item.
    $Attributes = @{
        Path        = $SourcePath
        Destination = $DestinationChildren.Employees.Path
        Resume      = $true
        Force       = $true
    }
    Write-Verbose -Message "Copy-SfItem $($Attributes|ConvertTo-Json -Compress)"
    Write-Host $(Get-Date -Format 'o') -NoNewline -ForegroundColor Cyan
    Write-Host " Copying '" -NoNewline
    Write-Host $Attributes.Path -NoNewline -ForegroundColor Yellow
    Write-Host "' to '" -NoNewline
    Write-Host $Attributes.Destination -NoNewline -ForegroundColor Green
    Write-Host "'"
    Copy-SfItem @Attributes
}
##### END: All Employees Items


##### BEGIN: All Shared Items
# Get 'allshared' items
$Attributes = @{
    Client = $SfClient
    Method = 'GET'
    Entity = 'Items'
    Id     = 'allshared'
    Expand = 'Children'
}
Write-Verbose -Message "Send-SfRequest $($Attributes|ConvertTo-Json -Compress)"
Write-Host 'Getting all Shared folders.'
$Shares = Send-SfRequest @Attributes

# Loop through all folders in 'allshared' items.
$Counter0 = 0
foreach ($Share in $Shares.Children) {
    $Counter0++
    $Progres0Attributes = @{
        Id = 0
        Activity = 'All Shared folders'
        CurrentOperation = $Share.Name
        PercentComplete = ($Counter0 / $Shares.Children.Count) * 100
    }
    Write-Progress @Progres0Attributes

    # Get 'current' folder items.
    $Attributes = @{
        Client = $SfClient
        Entity = 'Items'
        Id     = $Share.Id
    }
    Write-Verbose -Message "Send-SfRequest $($Attributes|ConvertTo-Json -Compress)"
    $Source = Send-SfRequest @Attributes
    $SourcePath = "${SfDrive}:/$($Source.Name)"

    # Download 'current' item.
    $Attributes = @{
        Path        = $SourcePath
        Destination = $DestinationChildren.Shared.Path
        Resume      = $true
        Force       = $true
    }
    Write-Verbose -Message "Copy-SfItem $($Attributes|ConvertTo-Json -Compress)"
    Write-Host $(Get-Date -Format 'o') -NoNewline -ForegroundColor Cyan
    Write-Host " Copying '" -NoNewline
    Write-Host $Attributes.Path -NoNewline -ForegroundColor Yellow
    Write-Host "' to '" -NoNewline
    Write-Host $Attributes.Destination -NoNewline -ForegroundColor Green
    Write-Host "'"
    Copy-SfItem @Attributes
}
##### END: All Shared Items
Get-PSDrive -PSProvider ShareFile | Remove-PSDrive
Stop-Transcript