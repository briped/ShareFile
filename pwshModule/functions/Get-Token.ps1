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
