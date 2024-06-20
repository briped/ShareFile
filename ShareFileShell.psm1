function Get-Token {
	[CmdletBinding()]
	param (
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]
		$SubDomain
		,
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[alias('appcp')]
		[string]
		$AppControlPlane
		,
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$ClientID
		,
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$ClientSecret
		,
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[pscredential]
		$Credential
	)
	if (!$Token -or !$Token.expire_date -or $Token.expire_date -le (Get-Date)) {
		$ContentType = 'application/x-www-form-urlencoded'
		$Method = 'POST'
		$Data = @{
			client_id = $ClientID
			client_secret = $ClientSecret
		}
		if (!$Token.refresh_token) {
			$Uri = "https://$($SubDomain).$($AppControlPlane)/oauth/token"
			$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
			$Secret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
			$Data.grant_type = 'password'
			$Data.username = $Credential.UserName
			$Data.password = $Secret
		}
		else {
			$Uri = "https://$($Token.subdomain).$($Token.appcp)/oauth/token"
			$Data.grant_type = 'refresh_token'
			$Data.refresh_token = $Token.refresh_token
		}
		$Query = @()
		foreach ($k in $Data.Keys) {
			$Query += "$($k)=$($Data[$k])"
		}
		$Body = $Query -join '&'
		$Token = Invoke-RestMethod -ContentType $ContentType -Method $Method -Uri $Uri -Body $Body
		$Token | Add-Member -MemberType NoteProperty -Name 'expire_date' -Value (Get-Date).AddSeconds($Token.expires_in).AddMinutes(-5)
	}
	$Token
}
function Get-Account {
	[CmdletBinding()]
	param (
		[Parameter()]
		[System.Object]
		$Token
		,
		[Parameter(ParameterSetName = 'Id')]
		[string]
		$Id
	)
	$Header = @{
		Authorization = "Bearer $($Token.access_token)"
	}
	$ContentType = 'application/json'
	$Method = 'GET'
	$Uri = "https://$($Token.subdomain).$($Token.apicp)/sf/v3/Accounts"
	if ($null -ne $Id) {
		$Uri += "($($Id))"
	}
	Invoke-RestMethod -ContentType $ContentType -Headers $Header -Method $Method -Uri $Uri
}
function Get-Employee {
	[CmdletBinding()]
	param (
		[Parameter()]
		[System.Object]
		$Token
	)
	$Header = @{
		Authorization = "Bearer $($Token.access_token)"
	}
	$ContentType = 'application/json'
	$Method = 'GET'
	$Uri = "https://$($Token.subdomain).$($Token.apicp)/sf/v3/Accounts/Employees"
	Invoke-RestMethod -ContentType $ContentType -Headers $Header -Method $Method -Uri $Uri
}
function Get-Client {
	[CmdletBinding()]
	param (
		[Parameter()]
		[System.Object]
		$Token
	)
	$Header = @{
		Authorization = "Bearer $($Token.access_token)"
	}
	$ContentType = 'application/json'
	$Method = 'GET'
	$Uri = "https://$($Token.subdomain).$($Token.apicp)/sf/v3/Accounts/Clients"
	Invoke-RestMethod -ContentType $ContentType -Headers $Header -Method $Method -Uri $Uri
}
function Get-Zone {
	[CmdletBinding()]
	param (
		[Parameter()]
		[System.Object]
		$Token
		,
		[Parameter(ParameterSetName = 'Id')]
		[string]
		$Id
	)
	$Header = @{
		Authorization = "Bearer $($Token.access_token)"
	}
	$ContentType = 'application/json'
	$Method = 'GET'
	$Uri = "https://$($Token.subdomain).$($Token.apicp)/sf/v3/Zones"
	if ($null -ne $Id) {
		$Uri += "($($Id))"
	}
	Invoke-RestMethod -ContentType $ContentType -Headers $Header -Method $Method -Uri $Uri
}
function Get-User {
	[CmdletBinding(DefaultParameterSetName = 'Default')]
	param (
		[Parameter(Mandatory = $true
				  ,ParameterSetName = 'Default')]
		[Parameter(ParameterSetName = 'Id')]
		[Parameter(ParameterSetName = 'Email')]
		[ValidateNotNullOrEmpty()]
		[System.Object]
		$Token
		,
		[Parameter(ParameterSetName = 'Id')]
		[ValidateNotNullOrEmpty()]
		[guid]
		$Id
		,
		[Parameter(ParameterSetName = 'Email')]
		[ValidateNotNullOrEmpty()]
		[ValidatePattern('^[\w-\.]+@([a-z0-9-]+\.)+[a-z0-9-]{2,4}$')]
		[string]
		$Email
		,
		[Parameter()]
		[switch]
		$HomeFolder
	)
	$Header = @{
		Authorization = "Bearer $($Token.access_token)"
	}
	$ContentType = 'application/json'
	$Method = 'GET'
	$Uri = "https://$($Token.subdomain).$($Token.apicp)/sf/v3/Users"
	if ($PSCmdlet.ParameterSetName -eq 'Id') {
		$Uri += "($($Id))"
		if ($HomeFolder) {
			$Uri += '/HomeFolder'
		}
	}
	elseif ($PSCmdlet.ParameterSetName -eq 'Email') {
		$Uri += "?emailaddress=$($Email)"
	}
	Write-Verbose -Message "Invoke-RestMethod -ContentType $ContentType -Headers $Header -Method $Method -Uri $Uri"
	Invoke-RestMethod -ContentType $ContentType -Headers $Header -Method $Method -Uri $Uri
}
function Get-Item {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[System.Object]
		$Token
		,
		[Parameter()]
		[string]
		$Id
		,
		[Parameter()]
		[string]
		$Path
		,
		[Parameter()]
		[switch]
		$IncludeDeleted
		,
		[Parameter()]
		[switch]
		$Parent
		,
		[Parameter()]
		[switch]
		$Children
	)
	$Header = @{
		Authorization = "Bearer $($Token.access_token)"
	}
	$ContentType = 'application/json'
	$Method = 'GET'
	$Uri = "https://$($Token.subdomain).$($Token.apicp)/sf/v3/Items"
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
	Write-Verbose -Message "Invoke-RestMethod -ContentType $ContentType -Headers $Header -Method $Method -Uri $Uri"
	Invoke-RestMethod -ContentType $ContentType -Headers $Header -Method $Method -Uri $Uri
}
function Delete-User {
	[CmdletBinding(SupportsShouldProcess = $true)]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[System.Object]
		$Token
		,
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[guid]
		$Id
		,
		[Parameter()]
		[guid]
		$ReassignTo
		,
		[Parameter()]
		[switch]
		$Completely
	)
	$Header = @{
		Authorization = "Bearer $($Token.access_token)"
	}
	$Data = @{
		completely = $Completely
	}
	if ($ReassignTo) {
		$ReassignUser = Get-User -Token $Token -Id $ReassignTo
		if (!$ReassignUser) {
			throw 'ReassignTo user does not exist.'
		}
		$Data.itemsReassignTo = $ReassignTo
		$Data.groupsReassignTo = $ReassignTo
	}
	$Query = @()
	foreach ($k in $Data.Keys) {
		$Query += "$($k)=$($Data[$k])"
	}
	$ContentType = 'application/json'
	$Method = 'DELETE'
	$Uri = "https://$($Token.subdomain).$($Token.apicp)/sf/v3/Users($($Id))?"
	$Uri += $Query -join '&'
	$SfUser = Get-User -Token $Token -Id $Id
	if ($PSCmdlet.ShouldProcess("'$($SfUser.FullName)' ($($SfUser.Username)) ($($SfUser.Id)).")) {
		Write-Verbose -Message "Deleting user: '$($SfUser.FullName)' ($($SfUser.Username)) ($($SfUser.Id))."
		#Invoke-RestMethod -ContentType $ContentType -Headers $Header -Method $Method -Uri $Uri
	}
}
