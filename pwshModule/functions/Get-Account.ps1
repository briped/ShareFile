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
