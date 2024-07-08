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
function Get-Token {
	[CmdletBinding()]
	param (
		# Company subdomain; f.ex. "MyCompany" is the subdomain of "MyCompany.sharefile.com"
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]
		$SubDomain
		,
		# ShareFile.com or ShareFile.eu. Part of the issued token.
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[alias('appcp')]
		[string]
		$AppControlPlane
		,
		# The Client ID generated on api.sharefile.com
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[Alias('client_id')]
		[string]
		$ClientID
		,
		# The Client Secret generated on api.sharefile.com
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[Alias('client_secret')]
		[string]
		$ClientSecret
		,
		# A credential containing the username and password for accessing the API
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[pscredential]
		$Credential
	)
	$EnvUser = if ($IsLinux) { 'USER' } else { 'USERNAME' }
	$EnvName = if ($IsLinux) { 'NAME' } else { 'COMPUTERNAME' }
	$HostUser = [System.Environment]::GetEnvironmentVariable($EnvUser)
	$HostName = [System.Environment]::GetEnvironmentVariable($EnvName)
	$UserHost = "$($HostUser)@$($HostName)"
	if (!$Script:Token -or !$Script:Token.expire_date -or $Script:Token.expire_date -le (Get-Date)) {
		if (!$ClientID -and !$Script:Config.client_id) {
			throw 'Required ClientID is missing.'
		}
		$ClientID = if ($ClientID) { $ClientID } else { $Script:Config.client_id }

		if (!$ClientSecret -and !$Script:Config.client_secret) {
			throw 'Required ClientSecret is missing.'
		}
		$ClientSecret = if ($ClientSecret) { $ClientSecret } else { $Script:Config.client_secret }

		if (!$Script:Token.subdomain -and !$SubDomain -and !$Script:Config.subdomain) {
			throw 'Required SubDomain is missing.'
		}
		$SubDomain = if ($Script:Token.subdomain) { $Script:Token.subdomain } elseif ($SubDomain) { $SubDomain } else { $Script:Config.subdomain }

		if (!$Script:Token.appcp -and !$AppControlPlane -and !$Script:Config.appcp) {
			throw 'Required AppControlPlane is missing.'
		}
		$AppControlPlane = if ($Script:Token.appcp) { $Script:Token.appcp } elseif ($AppControlPlane) { $AppControlPlane } else { $Script:Config.appcp }

		$Data = @{
			client_id = $ClientID
			client_secret = $ClientSecret
		}
		if (!$Script:Token.refresh_token) {
			$UserHostCredential = $Script:Config.credentials | Where-Object { $_.Name -eq $UserHost }
			if (!$Credential -and !$UserHostCredential.Credential) {
				throw 'Required Credential is missing.'
			}
			$Credential = if ($Credential) { $Credential } else { $UserHostCredential.Credential }

			$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
			$Secret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
			$Data.grant_type = 'password'
			$Data.username = $Credential.UserName
			$Data.password = $Secret
		}
		else {
			$Data.grant_type = 'refresh_token'
			$Data.refresh_token = $Script:Token.refresh_token
		}
		$Query = @()
		foreach ($k in $Data.Keys) {
			$Query += "$($k)=$($Data[$k])"
		}
		$Body = $Query -join '&'
		$Uri = "https://$($SubDomain).$($AppControlPlane)/oauth/token"
		$Splatter = @{
			ContentType = 'application/x-www-form-urlencoded'
			Method = 'POST'
			Uri = $Uri
			Body = $Body
		}
		if ($Script:Config.Proxy) {
			$Splatter.Proxy = $Script:Config.Proxy
		}
		Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
		$Script:Token = Invoke-RestMethod @Splatter
		if ($Script:Token -and !$Script:Token.expire_date) {
			$Script:Token | Add-Member -MemberType NoteProperty -Name 'expire_date' -Value (Get-Date).AddSeconds($Script:Token.expires_in).AddMinutes(-5)
		}
	}
	$Script:Token
}
function Get-Account {
	# https://api.sharefile.com/docs/resource?name=Accounts#Get_current_Account
	[CmdletBinding()]
	param (
		# Account ID to get information about. Get all if no ID specified.
		[Parameter()]
		[string]
		$Id
	)
	$Script:Token = Get-Token
	$Header = @{
		Authorization = "Bearer $($Script:Token.access_token)"
	}
	$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Accounts"
	if ($Id) {
		$Uri += "($($Id))"
	}
	$Splatter = @{
		ContentType = 'application/json'
		Method = 'GET'
		Uri = $Uri
		Header = $Header
	}
	if ($Script:Config.Proxy) {
		$Splatter.Proxy = $Script:Config.Proxy
	}
	Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
	Invoke-RestMethod @Splatter
}
function Get-AccountPreference {
	# https://api.sharefile.com/docs/resource?name=Accounts#Get_Account_Preferences
	[CmdletBinding()]
	param ()
	$Script:Token = Get-Token
	$Header = @{
		Authorization = "Bearer $($Script:Token.access_token)"
	}
	$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Accounts/Preferences"
	$Splatter = @{
		ContentType = 'application/json'
		Method = 'GET'
		Uri = $Uri
		Header = $Header
	}
	if ($Script:Config.Proxy) {
		$Splatter.Proxy = $Script:Config.Proxy
	}
	Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
	Invoke-RestMethod @Splatter
}
function Get-Branding {
	# https://api.sharefile.com/docs/resource?name=Accounts#Get_current_Account_branding
	[CmdletBinding()]
	param ()
	$Script:Token = Get-Token
	$Header = @{
		Authorization = "Bearer $($Script:Token.access_token)"
	}
	$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Accounts/Branding"
	$Splatter = @{
		ContentType = 'application/json'
		Method = 'GET'
		Uri = $Uri
		Header = $Header
	}
	if ($Script:Config.Proxy) {
		$Splatter.Proxy = $Script:Config.Proxy
	}
	Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
	Invoke-RestMethod @Splatter
}
function Get-AccountSSO {
	# https://api.sharefile.com/docs/resource?name=Accounts#Get_Account_Single_Sign-On_Configuration
	[CmdletBinding()]
	param (
		[Parameter()]
		[string]
		$Provider
		,
		# IDP Entity ID
		[Parameter()]
		[string]
		$Entity
	)
	$Script:Token = Get-Token
	$Header = @{
		Authorization = "Bearer $($Script:Token.access_token)"
	}
	$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Accounts/SSO?"
	$Data = @{}
	if ($Provider) { $Data.provider = [uri]::EscapeDataString($Provider) }
	if ($Entity) { $Data.idpEntityId = [uri]::EscapeDataString($Entity) }
	$Query = @()
	foreach ($k in $Data.Keys) {
		$Query += "$($k)=$($Data[$k])"
	}
	$Uri += $Query -join '&'
	$Splatter = @{
		ContentType = 'application/json'
		Method = 'GET'
		Uri = $Uri
		Header = $Header
	}
	if ($Script:Config.Proxy) {
		$Splatter.Proxy = $Script:Config.Proxy
	}
	Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
	Invoke-RestMethod @Splatter
}
function Get-AccountSSOInfo {
	# https://api.sharefile.com/docs/resource?name=Accounts#Get_SSO_Info
	[CmdletBinding()]
	param (
		# Company subdomain; f.ex. "MyCompany" is the subdomain of "MyCompany.sharefile.com"
		[Parameter(Mandatory = $true)]
		[string]
		$SubDomain
	)
	$Script:Token = Get-Token
	$Header = @{
		Authorization = "Bearer $($Script:Token.access_token)"
	}
	$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Accounts/SSO?subdomain=$($SubDomain)"
	$Splatter = @{
		ContentType = 'application/json'
		Method = 'GET'
		Uri = $Uri
		Header = $Header
	}
	if ($Script:Config.Proxy) {
		$Splatter.Proxy = $Script:Config.Proxy
	}
	Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
	Invoke-RestMethod @Splatter
}
function Get-AddressBook {
	# https://api.sharefile.com/docs/resource?name=Accounts#Get_Account_AddressBooks
	[CmdletBinding()]
	param (
		# Defines the type of Address Book to retrieve. Default is Personal
		[Parameter()]
		[ValidateSet('Personal', 'Shared', 'Group')]
		[string]
		$Type = 'Personal'
		,
		# Use if you want server-side searching to happen across email or name
		[Parameter()]
		[string]
		$Search
	)
	$Script:Token = Get-Token
	$Header = @{
		Authorization = "Bearer $($Script:Token.access_token)"
	}
	$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Accounts/AddressBook?"
	$Data = @{
		type = $Type.ToLower()
	}
	if ($Search) { $Data.searchTerm = [uri]::EscapeDataString($Search) }
	$Query = @()
	foreach ($k in $Data.Keys) {
		$Query += "$($k)=$($Data[$k])"
	}
	$Uri += $Query -join '&'

	$Splatter = @{
		ContentType = 'application/json'
		Method = 'GET'
		Uri = $Uri
		Header = $Header
	}
	if ($Script:Config.Proxy) {
		$Splatter.Proxy = $Script:Config.Proxy
	}
	Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
	Invoke-RestMethod @Splatter
}
function Get-Capability {
	# https://api.sharefile.com/docs/resource?name=Capabilities
	[CmdletBinding()]
	param ()
	$Script:Token = Get-Token
	$Header = @{
		Authorization = "Bearer $($Script:Token.access_token)"
	}
	$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Capabilities"
	$Splatter = @{
		ContentType = 'application/json'
		Method = 'GET'
		Uri = $Uri
		Header = $Header
	}
	if ($Script:Config.Proxy) {
		$Splatter.Proxy = $Script:Config.Proxy
	}
	Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
	Invoke-RestMethod @Splatter
}
function Get-Employee {
	# https://api.sharefile.com/docs/resource?name=Accounts#Get_List_of_current_Account_Employees
	[CmdletBinding()]
	param ()
	$Script:Token = Get-Token
	$Header = @{
		Authorization = "Bearer $($Script:Token.access_token)"
	}
	$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Accounts/Employees"
	$Splatter = @{
		ContentType = 'application/json'
		Method = 'GET'
		Uri = $Uri
		Header = $Header
	}
	if ($Script:Config.Proxy) {
		$Splatter.Proxy = $Script:Config.Proxy
	}
	Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
	Invoke-RestMethod @Splatter
}
function Get-Client {
	# https://api.sharefile.com/docs/resource?name=Accounts#Get_List_of_current_Account_Clients
	[CmdletBinding()]
	param ()
	$Script:Token = Get-Token
	$Header = @{
		Authorization = "Bearer $($Script:Token.access_token)"
	}
	$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Accounts/Clients"
	$Splatter = @{
		ContentType = 'application/json'
		Method = 'GET'
		Uri = $Uri
		Header = $Header
	}
	if ($Script:Config.Proxy) {
		$Splatter.Proxy = $Script:Config.Proxy
	}
	Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
	Invoke-RestMethod @Splatter
}
function Get-Zone {
	# https://api.sharefile.com/docs/resource?name=Zones#Get_List_of_Zones
	# https://api.sharefile.com/docs/resource?name=Zones#Get_Zone_by_ID
	[CmdletBinding(DefaultParameterSetName = 'Default')]
	param (
		# Zone identifier
		[Parameter(ParameterSetName = 'Id'
				,  Mandatory = $true
				,  Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true)]
		[string]
		$Id
		,
		# Include "disabled" zones - zones without an associated enabled storagecenter. Defaults to off.
		[Parameter(ParameterSetName = 'Default')]
		[switch]
		$Disabled
		,
		[Parameter(ParameterSetName = 'Id')]
		[switch]
		$Secret
	)
	$Script:Token = Get-Token
	$Header = @{
		Authorization = "Bearer $($Script:Token.access_token)"
	}
	$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Zones"
	if ($Id) {
		$Uri += "($($Id))"
		$Uri += "?secret=$($Secret)"
	}
	else {
		$Uri += "?includeDisabled=$($Disabled)"
	}
	$Splatter = @{
		ContentType = 'application/json'
		Method = 'GET'
		Uri = $Uri
		Header = $Header
	}
	if ($Script:Config.Proxy) {
		$Splatter.Proxy = $Script:Config.Proxy
	}
	Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
	Invoke-RestMethod @Splatter
}
function Get-User {
	# https://api.sharefile.com/docs/resource?name=Users#Get_User
	[CmdletBinding(DefaultParameterSetName = 'Id')]
	param (
		# User ID to lookup
		[Parameter(ParameterSetName = 'Id'
				,  Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$Id
		,
		# User email address to lookup
		[Parameter(ParameterSetName = 'Email')]
		[ValidateNotNullOrEmpty()]
		[ValidatePattern('^[\w-\.]+@([a-z0-9-]+\.)+[a-z0-9-]{2,4}$')]
		[string]
		$Email
	)
	begin {
		$Script:Token = Get-Token
		$Header = @{
			Authorization = "Bearer $($Script:Token.access_token)"
		}
	}
	process {
		$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Users"
		if ($Id) {
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Getting user by ID: $($Id)"
			$Uri += "($($Id))"
		}
		elseif ($PSCmdlet.ParameterSetName -eq 'Email') {
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Getting user by email: $($Email)"
			$Uri += "?emailaddress=$($Email)"
		}
		else {
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Getting current user."
		}
		$Splatter = @{
			ContentType = 'application/json'
			Method = 'GET'
			Uri = $Uri
			Header = $Header
		}
		if ($Script:Config.Proxy) {
			$Splatter.Proxy = $Script:Config.Proxy
		}
		Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
		Invoke-RestMethod @Splatter
	}
}
function Set-User {
	# https://api.sharefile.com/docs/resource?name=Users#Update_User
	[CmdletBinding()]
	param (
		# User ID to update
		[Parameter(Mandatory = $true
				,  Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$Id
		,
		[Parameter()]
		[ValidatePattern('^[\w-\.]+@([a-z0-9-]+\.)+[a-z0-9-]{2,4}$')]
		[ValidateNotNullOrEmpty()]
		[string]
		$Email
		,
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]
		$Username
	)
	$Script:Token = Get-Token
	$Header = @{
		Authorization = "Bearer $($Script:Token.access_token)"
	}
	$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Users($Id)"
	$Data = @{
		Email = $Email
		Username = $Username
	}
	$Splatter = @{
		ContentType = 'application/json'
		Method = 'PATCH'
		Uri = $Uri
		Header = $Header
		Body = $Data | ConvertTo-Json -Compress
	}
	if ($Script:Config.Proxy) {
		$Splatter.Proxy = $Script:Config.Proxy
	}
	Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
	Invoke-RestMethod @Splatter
}
function Get-UserSecurity {
	# https://api.sharefile.com/docs/resource?name=Users#Get_User_Security
	[CmdletBinding()]
	param (
		# User ID to lookup
		[Parameter(Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$Id
	)
	begin {
		$Script:Token = Get-Token
		$Header = @{
			Authorization = "Bearer $($Script:Token.access_token)"
		}
	}
	process {
		$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Users"
		if ($Id) {
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Getting user's securityinfo by ID: $($Id)"
			$Uri += "($($Id))"
		}
		else {
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Getting current user's securityinfo."
		}
		$Uri += '/Security'
		$Splatter = @{
			ContentType = 'application/json'
			Method = 'GET'
			Uri = $Uri
			Header = $Header
		}
		if ($Script:Config.Proxy) {
			$Splatter.Proxy = $Script:Config.Proxy
		}
		Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
		Invoke-RestMethod @Splatter
	}
}
function Get-UserPreference {
	# https://api.sharefile.com/docs/resource?name=Users#Get_User_Preferences
	[CmdletBinding()]
	param (
		# User ID to lookup
		[Parameter(Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$Id
	)
	begin {
		$Script:Token = Get-Token
		$Header = @{
			Authorization = "Bearer $($Script:Token.access_token)"
		}
	}
	process {
		$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Users"
		if ($Id) {
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Getting user preferences by ID: $($Id)"
			$Uri += "($($Id))"
		}
		else {
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Getting current user preferences."
		}
		$Uri += "/Preferences"
		$Splatter = @{
			ContentType = 'application/json'
			Method = 'GET'
			Uri = $Uri
			Header = $Header
		}
		if ($Script:Config.Proxy) {
			$Splatter.Proxy = $Script:Config.Proxy
		}
		Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
		Invoke-RestMethod @Splatter
	}
}
function Get-UserSharedFolders {
	# https://api.sharefile.com/docs/resource?name=Users#Get_List_of_User_Shared_Folders
	[CmdletBinding()]
	param (
		# User ID to lookup
		[Parameter(Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$Id
	)
	begin {
		$Script:Token = Get-Token
		$Header = @{
			Authorization = "Bearer $($Script:Token.access_token)"
		}
	}
	process {
		$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Users"
		if ($Id) {
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Getting user's shared folders by ID: $($Id)"
			$Uri += "($($Id))"
		}
		else {
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Getting current user's shared folders."
		}
		$Uri += "/AllSharedFolders"
		$Splatter = @{
			ContentType = 'application/json'
			Method = 'GET'
			Uri = $Uri
			Header = $Header
		}
		if ($Script:Config.Proxy) {
			$Splatter.Proxy = $Script:Config.Proxy
		}
		Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
		Invoke-RestMethod @Splatter
	}
}
function Get-UserFileBox {
	# https://api.sharefile.com/docs/resource?name=Users#Get_User's_FileBox_folder
	[CmdletBinding()]
	param (
		# User ID to lookup
		[Parameter(Mandatory = $true
				,  Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$Id
		,
		[Parameter()]
		[switch]
		$Children
	)
	begin {
		$Script:Token = Get-Token
		$Header = @{
			Authorization = "Bearer $($Script:Token.access_token)"
		}
	}
	process {
		if (!$Id) {
			$Id = (Get-User).Id
		}
		$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Users($($Id))"
		if ($Children) {
			$Uri += '/Box'
		}
		else {
			$Uri += '/FileBox'
		}
		$Splatter = @{
			ContentType = 'application/json'
			Method = 'GET'
			Uri = $Uri
			Header = $Header
		}
		if ($Script:Config.Proxy) {
			$Splatter.Proxy = $Script:Config.Proxy
		}
		Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
		Invoke-RestMethod @Splatter
	}
}
function Get-UserHomeFolder {
	# https://api.sharefile.com/docs/resource?name=Users#Get_HomeFolder
	[CmdletBinding()]
	param (
		# User ID to lookup
		[Parameter(Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$Id
	)
	begin {
		$Script:Token = Get-Token
		$Header = @{
			Authorization = "Bearer $($Script:Token.access_token)"
		}
	}
	process {
		$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Users"
		if ($Id) {
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Getting user by ID: $($Id)"
			$Uri += "($($Id))"
		}
		$Uri += '/HomeFolder'
		$Splatter = @{
			ContentType = 'application/json'
			Method = 'GET'
			Uri = $Uri
			Header = $Header
		}
		if ($Script:Config.Proxy) {
			$Splatter.Proxy = $Script:Config.Proxy
		}
		Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
		Invoke-RestMethod @Splatter
	}
}
function Get-Item {
	# https://api.sharefile.com/docs/resource?name=Items#Get_HomeFolder_for_Current_User
	# https://api.sharefile.com/docs/resource?name=Items#Get_Item_by_ID
	# https://api.sharefile.com/docs/resource?name=Items#Get_Item_by_Path
	# https://api.sharefile.com/docs/resource?name=Items#Get_Item_by_relative_Path_from_ID
	# https://api.sharefile.com/docs/resource?name=Items#Get_Parent_Item
	# https://api.sharefile.com/docs/resource?name=Items#Get_Children
	[CmdletBinding()]
	param (
		# Item identifier
		[Parameter(Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true)]
		[string]
		$Id
		,
		# Path to retrieve
		[Parameter()]
		[string]
		$Path
		,
		# Specifies whether or not the list of items returned should include deleted children
		[Parameter()]
		[switch]
		$Deleted
		,
		# Returns: the Parent Item of the give object ID.
		[Parameter()]
		[switch]
		$Parent
		,
		# Returns: the list of children under the given object ID
		[Parameter()]
		[switch]
		$Children
	)
	begin {
		$Script:Token = Get-Token
		$Header = @{
			Authorization = "Bearer $($Script:Token.access_token)"
		}
	}
	process {
		$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Items"
		if ($Id) {
			$Uri += "($($Id))"
			if ($Children) {
				$Uri += '/Children'
			}
			elseif ($Parent) {
				$Uri += '/Parent'
			}
		}
		if ($Path) {
			$EscapedPath = [uri]::EscapeDataString($Path)
			$Uri += "/ByPath?path=$($EscapedPath)"
		}
		$Splatter = @{
			ContentType = 'application/json'
			Method = 'GET'
			Uri = $Uri
			Header = $Header
		}
		if ($Script:Config.Proxy) {
			$Splatter.Proxy = $Script:Config.Proxy
		}
		Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
		Invoke-RestMethod @Splatter
	}
}
function Download-Item {
	# https://api.sharefile.com/docs/resource?name=Items#Download_Item_Content
	[CmdletBinding()]
	param (
		# Item identifier
		[Parameter(Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true)]
		[string]
		$Id
		,
		# Redirect to download link if set to true (default), or return a DownloadSpecification object if set to false
		[Parameter()]
		[switch]
		$Redirect
		,
		# For folder downloads only, includes old versions of files in the folder in the zip when true, current versions only when false (default)
		[Parameter()]
		[switch]
		$AllVersions
		,
		# For FINRA or other archive enabled account only, Super User can set includeDelete=true to download archived item. The default value of includeDeleted is false
		[Parameter()]
		[switch]
		$Deleted
	)
	$Script:Token = Get-Token
	$Header = @{
		Authorization = "Bearer $($Script:Token.access_token)"
	}
	$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Items($($Id))/Download?"
	$Data = @{
		redirect = $Redirect
		includeAllVersions = $AllVersions
		includeDeleted = $Deleted
	}
	$Query = @()
	foreach ($k in $Data.Keys) {
		$Query += "$($k)=$($Data[$k])"
	}
	$Uri += $Query -join '&'
	$Splatter = @{
		ContentType = 'application/json'
		Method = 'GET'
		Uri = $Uri
		Header = $Header
	}
	if ($Script:Config.Proxy) {
		$Splatter.Proxy = $Script:Config.Proxy
	}
	Write-Verbose -Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
	Invoke-WebRequest @Splatter
}
function Get-AccessControl {
	# https://api.sharefile.com/docs/resource?name=AccessControls
	[CmdletBinding()]
	param (
		# Item Identifier
		[Parameter(Mandatory = $true
				,  Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true)]
		[Alias('Item', 'ItemId')]
		[string]
		$Id
		,
		# Principal Identifier
		[Parameter(Position = 1
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true)]
		[Alias('User', 'UserId')]
		[string]
		$Principal
	)
	$Script:Token = Get-Token
	$Header = @{
		Authorization = "Bearer $($Script:Token.access_token)"
	}
	$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3"
	if ($Principal) {
		$Uri += "/AccessControls(principalid=$($Principal),itemid=$($Id))"
	}
	else {
		$Uri += "/Items($($Id))/AccessControls"
	}

	$Splatter = @{
		ContentType = 'application/json'
		Method = 'GET'
		Uri = $Uri
		Header = $Header
	}
	if ($Script:Config.Proxy) {
		$Splatter.Proxy = $Script:Config.Proxy
	}
	Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
	Invoke-RestMethod @Splatter
}
function Get-Device {
	# https://api.sharefile.com/docs/resource?name=Devices
	[CmdletBinding()]
	param (
		# Get Device by ID
		[Parameter(Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$Id
		,
		# Get Devices for UserID
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]
		$UserId
	)
	$Script:Token = Get-Token
	$Header = @{
		Authorization = "Bearer $($Script:Token.access_token)"
	}
	$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3"
	if ($UserId) {
		Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Getting devices for UserID: $($UserId)"
		$Uri += "/User($($UserId))/Devices"
	}
	elseif ($Id) {
		Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Getting device by ID: $($Id)"
		$Uri += "/Devices($($Id))"
	}
	else {
		Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Getting devices for current user."
		$Uri += "/Devices"
	}
	$Splatter = @{
		ContentType = 'application/json'
		Method = 'GET'
		Uri = $Uri
		Header = $Header
	}
	if ($Script:Config.Proxy) {
		$Splatter.Proxy = $Script:Config.Proxy
	}
	Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
	Invoke-RestMethod @Splatter
}
function Remove-User {
	# https://api.sharefile.com/docs/resource?name=Users#Delete_User
	[CmdletBinding(DefaultParameterSetName = 'ReassignAll'
				,  SupportsShouldProcess = $true
				,  ConfirmImpact = 'High')]
	param (
		# GUID of the user to be deleted.
		[Parameter(Mandatory = $true
				,  Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$Id
		,
		# Combined ReassignItemsTo and ReassignGroupsTo. If set, all user item and group records will be reassigned to the user provided.
		[Parameter(ParameterSetName = 'ReassignAll')]
		[string]
		$ReassignTo
		,
		# If set, all user item records will be reassigned to the user provided.
		[Parameter(ParameterSetName = 'Reassign')]
		[string]
		$ReassignItemsTo
		,
		# If set, all user group records will be reassigned to the user provided.
		[Parameter(ParameterSetName = 'Reassign')]
		[string]
		$ReassignGroupsTo
		,
		# If set, all user records will be removed. Otherwise, the user will be disabled, but not removed from the system. A complete removal is not recoverable.
		[Parameter()]
		[switch]
		$Completely
		,
		# Force remove. Don't ask for confirmation unless explicitly specified.
		[Parameter()]
		[switch]
		$Force
	)
	begin {
		$Script:Token = Get-Token
		if ($Force -and !$Confirm) {
			$ConfirmPreference = 'None'
		}
		$Header = @{
			Authorization = "Bearer $($Script:Token.access_token)"
		}
		$Data = @{
			completely = $Completely
		}
		if ($ReassignTo) {
			$ReassignUser = Get-User -Id $ReassignTo
			if (!$ReassignUser) {
				throw 'ReassignTo user does not exist.'
			}
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Reassigning to: '$($ReassignUser.FullName)' ($($ReassignUser.Username)) ($($ReassignUser.Id))."
			$Data.itemsReassignTo = $ReassignTo
			$Data.groupsReassignTo = $ReassignTo
		}
	}
	process {
		$Query = @()
		foreach ($k in $Data.Keys) {
			$Query += "$($k)=$($Data[$k])"
		}
		$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Users($($Id))?"
		$Uri += $Query -join '&'
		$SfUser = Get-User -Id $Id
		if ($PSCmdlet.ShouldProcess("'$($SfUser.FullName)' ($($SfUser.Username)) ($($SfUser.Id)).")) {
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Deleting user: '$($SfUser.FullName)' ($($SfUser.Username)) ($($SfUser.Id))."
			$Splatter = @{
				ContentType = 'application/json'
				Method = 'DELETE'
				Uri = $Uri
				Header = $Header
			}
			if ($Script:Config.Proxy) {
				$Splatter.Proxy = $Script:Config.Proxy
			}
			try {
				Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
				$Response = Invoke-RestMethod @Splatter
			}
			catch {
				Write-Error -Message "$($MyInvocation.MyCommand.Name) : ERROR : Deleting user: '$($SfUser.FullName)' ($($SfUser.Username)) ($($SfUser.Id))." + $Error
			}
		}
	}
}
function Remove-Client {
	# https://api.sharefile.com/docs/resource?name=Users#Delete_multiple_client_users
	[CmdletBinding(SupportsShouldProcess = $true
				,  ConfirmImpact = 'High')]
	param (
		# GUID of the client to be deleted.
		[Parameter(Mandatory = $true
				,  Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$Id
		,
		# Force remove. Don't ask for confirmation unless explicitly specified.
		[Parameter()]
		[switch]
		$Force
	)
	$Script:Token = Get-Token
	if ($Force -and !$Confirm) {
		$ConfirmPreference = 'None'
	}
	$Header = @{
		Authorization = "Bearer $($Script:Token.access_token)"
	}
	$Data = @{
		UserIds = @($Id)
	}
	$Splatter = @{
		ContentType = 'application/json'
		#Method = 'DELETE'
		#Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Users/Clients"
		Method = 'POST'
		Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Users/Clients/BulkDelete"
		Header = $Header
		Body = $Data | ConvertTo-Json -Compress
	}
	if ($Script:Config.Proxy) {
		$Splatter.Proxy = $Script:Config.Proxy
	}

	$SfUser = Get-User -Id $Id
	if ($PSCmdlet.ShouldProcess("'$($SfUser.FullName)' ($($SfUser.Username)) ($($SfUser.Id)).")) {
		Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Deleting user: '$($SfUser.FullName)' ($($SfUser.Username)) ($($SfUser.Id))."
		Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
		Invoke-RestMethod @Splatter
	}
}
function Revoke-Employee {
	# https://api.sharefile.com/docs/resource?name=Users#Downgrade_multiple_employee_users_to_clients
	[CmdletBinding(DefaultParameterSetName = 'ReassignAll'
				,  SupportsShouldProcess = $true
				,  ConfirmImpact = 'High')]
	param (
		# GUID of the user to have employee status revoked.
		[Parameter(Mandatory = $true
				,  Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[string[]]
		$Id
		,
		# Combined ReassignItemsTo and ReassignGroupsTo. If set, all user item and group records will be reassigned to the user provided.
		[Parameter(ParameterSetName = 'ReassignAll')]
		[string]
		$ReassignTo
		,
		# If set, all user item records will be reassigned to the user provided.
		[Parameter(ParameterSetName = 'Reassign')]
		[string]
		$ReassignItemsTo
		,
		# If set, all user group records will be reassigned to the user provided.
		[Parameter(ParameterSetName = 'Reassign')]
		[string]
		$ReassignGroupsTo
		,
		# Force revoke. Don't ask for confirmation unless explicitly specified.
		[Parameter()]
		[switch]
		$Force
	)
	begin {
		$Script:Token = Get-Token
		if ($Force -and !$Confirm) {
			$ConfirmPreference = 'None'
		}
		$Header = @{
			Authorization = "Bearer $($Script:Token.access_token)"
		}
		if ($ReassignTo) {
			$ReassignToUser = Get-User -Id $ReassignTo
			if (!$ReassignToUser) {
				throw 'ReassignTo user does not exist.'
			}
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Reassigning to: '$($ReassignToUser.FullName)' ($($ReassignToUser.Username)) ($($ReassignToUser.Id))."
			$ItemsReassignTo = $ReassignToUser.Id
			$GroupsReassignTo = $ReassignToUser.Id
		}
		if ($ReassignItemsTo) {
			$ReassignItemsToUser = Get-User -Id $ReassignItemsTo
			if (!$ReassignItemsToUser) {
				throw 'ReassignItemsTo user does not exist.'
			}
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Reassigning items to: '$($ReassignItemsToUser.FullName)' ($($ReassignItemsToUser.Username)) ($($ReassignItemsToUser.Id))."
			$ItemsReassignTo = $ReassignItemsToUser.Id
		}
		if ($ReassignGroupsTo) {
			$ReassignGroupsToUser = Get-User -Id $ReassignGroupsTo
			if (!$ReassignGroupsToUser) {
				throw 'ReassignGroupsTo user does not exist.'
			}
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Reassigning groups to: '$($ReassignGroupsToUser.FullName)' ($($ReassignGroupsToUser.Username)) ($($ReassignGroupsToUser.Id))."
			$GroupsReassignTo = $ReassignGroupsToUser.Id
		}
		$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Users/Employees/Downgrade"
	}
	process {
		if ($id.Count -gt 1) {
			$UserIds = $Id
			$Message = "Revoking 'Employee' status from $($Id.Count) users."
		}
		else {
			$SfUser = Get-User -Id $Id[0]
			$UserIds = @($SfUser.Id)
			$Message = "Revoking 'Employee' status from user: '$($SfUser.FullName)' ($($SfUser.Username)) ($($SfUser.Id))."
		}
		$Data = @{
			UserIds = $UserIds
			ReassignItemsToId = $ItemsReassignTo
			ReassignGRoupsToId = $GroupsReassignTo
		}
		if ($PSCmdlet.ShouldProcess($Message)) {
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : $($Message)"
			$Splatter = @{
				ContentType = 'application/json'
				Method = 'POST'
				Uri = $Uri
				Header = $Header
				Body = $Data | ConvertTo-Json -Compress
			}
			if ($Script:Config.Proxy) {
				$Splatter.Proxy = $Script:Config.Proxy
			}
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
			try {
				$Response = Invoke-RestMethod @Splatter
			}
			catch {
				$Message = "Failed revoking 'Employee' status from user: '$($SfUser.FullName)' ($($SfUser.Username)) ($($SfUser.Id)). Error: $($_)"
				Write-Warning -Message $Message
			}
		}
	}
	end {}
}
function Grant-Employee {
	# https://api.sharefile.com/docs/resource?name=Users#Update_Employee_or_Promote_Customer
	[CmdletBinding(SupportsShouldProcess = $true
				,  ConfirmImpact = 'Medium')]
	param (
		# GUID of the user to have employee status granted.
		[Parameter(Mandatory = $true
				,  Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$Id
		,
		# Force grant. Don't ask for confirmation unless explicitly specified.
		[Parameter()]
		[switch]
		$Force
	)
	begin {
		$Script:Token = Get-Token
		if ($Force -and !$Confirm) {
			$ConfirmPreference = 'None'
		}
		$Header = @{
			Authorization = "Bearer $($Script:Token.access_token)"
		}
		$Data = @{
			isEmployee = $true
		}
	}
	process {
		$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Users/AccountUser($($Id))"
		$SfUser = Get-User -Id $Id
		if ($PSCmdlet.ShouldProcess("'$($SfUser.FullName)' ($($SfUser.Username)) ($($SfUser.Id)).")) {
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Granting 'Employee' status to user: '$($SfUser.FullName)' ($($SfUser.Username)) ($($SfUser.Id))."
			$Splatter = @{
				ContentType = 'application/json'
				Method = 'PATCH'
				Uri = $Uri
				Header = $Header
				Body = $Data | ConvertTo-Json -Compress
			}
			if ($Script:Config.Proxy) {
				$Splatter.Proxy = $Script:Config.Proxy
			}
			Write-Verbose -Message "$($MyInvocation.MyCommand.Name) : Invoke-RestMethod @$($Splatter | ConvertTo-Json -Compress)"
			Invoke-RestMethod @Splatter
		}
	}
	end {}
}
New-Variable -Force -Scope Script -Name ConfigPath -Value (Join-Path -Path $PSScriptRoot -ChildPath '.config.xml')
New-Variable -Force -Scope Script -Name Config -Value (Import-Config -Path $ConfigPath)
New-Variable -Force -Scope Script -Name Token -Value $null