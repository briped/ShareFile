<#
.DESCRIPTION
ShareFile API cmdlets.

.SYNOPSIS
ShareFile API cmdlets.

.NOTES
TODO
.EXAMPLE
TODO
#>
$FunctionsPath = Join-Path -Path $PSScriptRoot -ChildPath 'functions'
Get-ChildItem -File -Path $FunctionsPath -Filter '*.ps1' | 
    Where-Object { $_.BaseName -notmatch '(^\.|\.dev$|\.test$)' } | 
    ForEach-Object {
        . $_.FullName
    }
function Add-Credential {
	[CmdletBinding(SupportsShouldProcess = $true)]
	param(
		# Credential to be added
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[pscredential]
		$Credential
		,
		# Force add. Overwrite if exists. Don't ask for confirmation unless explicitly specified.
		[Parameter()]
		[switch]
		$Force
	)
	if ($Force -and !$Confirm) {
		$ConfirmPreference = 'None'
	}
	$EnvUser = if ($IsLinux) { 'USER' } else { 'USERNAME' }
	$EnvName = if ($IsLinux) { 'NAME' } else { 'COMPUTERNAME' }
	$HostUser = [System.Environment]::GetEnvironmentVariable($EnvUser)
	$HostName = [System.Environment]::GetEnvironmentVariable($EnvName)
	$UserHost = "$($HostUser)@$($HostName)"

	Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Authenticating with user '$($Credential.UserName)' and password."
	$Script:Token = Get-SfToken -Credential $Credential
	if (!$Script:Token) {
		Remove-Variable -Name Credential
		Write-Error -Message "$($MyInvocation.MyCommand.Name) : Authentication failed using '$($Credential.UserName)' and password." -ErrorAction Stop
	}

	$UserHostCredential = New-Object -TypeName PSCustomObject -Property @{
		Name = $UserHost
		Credential = $Credential
	}

	if (!($Script:Config.PSObject.Properties | Where-Object { $_.Name -eq 'credentials' })) {
		Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Creating credential array and adding credential."
		$Script:Config | Add-Member -MemberType NoteProperty -Name credentials -Value @($UserHostCredential)
		return $Script:Config
	}
	Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Checking for existing credentials for '$($UserHost)'."
	$ExistingCredential = $Script:Config.credentials | Where-Object { $_.Name -eq $UserHost }

	if (!$ExistingCredential) {
		Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Adding '$($UserHostCredential.Credential.UserName)' in '$($UserHostCredential.Name)' to the configuration."
		$Script:Config.credentials += $UserHostCredential
		return $Script:Config
	}
	else {
		Write-Warning -Message "$($MyInvocation.MyCommand.Name) : Credential for '$($UserHost)' already exists."
		if ($Force) {
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Updating credential for '$($UserHost)'."
			$ExistingCredential.Credential = $Credential
		}
	}
	$Script:Config
}
function Update-Credential {
	[CmdletBinding()]
	param(
		# Credential to be updated
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[pscredential]
		$Credential
	)
	Add-Credential -Credential $Credential -Force
}
function Remove-Credential {
	[CmdletBinding(SupportsShouldProcess = $true)]
	param(
		# Credential to be removed
		[Parameter()]
		[string]
		$Name
		,
		# Force remove. Don't ask for confirmation unless explicitly specified.
		[Parameter()]
		[switch]
		$Force
	)
	if ($Force -and !$Confirm) {
		$ConfirmPreference = 'None'
	}
	$EnvUser = if ($IsLinux) { 'USER' } else { 'USERNAME' }
	$EnvName = if ($IsLinux) { 'NAME' } else { 'COMPUTERNAME' }
	$HostUser = [System.Environment]::GetEnvironmentVariable($EnvUser)
	$HostName = [System.Environment]::GetEnvironmentVariable($EnvName)
	$UserHost = "$($HostUser)@$($HostName)"

	if (!$Name) {
		Write-Warning -Message "No credential name given. Using '$($UserHost)'."
		$Name = $UserHost
	}
	if ($PSCmdlet.ShouldProcess($Name)) {
		Write-Verbose -Message "Removing credential for '$($Name)'."
		$Script:Config.credentials = $Script:Config.credentials | Where-Object { $_.Name -ne $Name }
	}
	$Script:Config
}
function Import-Config {
	[CmdletBinding()]
	param(
		# Path to CliXML config.
		[Parameter(Mandatory = $true
				,  Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true
				,  HelpMessage="Path to CliXML config")]
		[Alias("PSPath")]
		[ValidateNotNullOrEmpty()]
		[System.IO.FileInfo]
		$Path
	)
	Import-Clixml -Path $Path
}
function Export-Config {
	[CmdletBinding()]
	param(
		# Path to CliXML config.
		[Parameter(Mandatory = $true
				,  Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true
				,  HelpMessage="Path to CliXML config")]
		[Alias("PSPath")]
		[ValidateNotNullOrEmpty()]
		[string]
		$Path
		,
		# Object containing configuration.
		[Parameter(Mandatory = $true
				,  HelpMessage="Object containing configuration")]
		[ValidateNotNullOrEmpty()]
		[System.Object]
		$Config
	)
	$Config | Export-Clixml -Path $Path
}
New-Variable -Force -Scope Script -Name ConfigPath -Value (Join-Path -Path $PSScriptRoot -ChildPath '.config.xml')
New-Variable -Force -Scope Script -Name Config -Value (Import-Config -Path $ConfigPath)
New-Variable -Force -Scope Script -Name Token -Value $null