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
