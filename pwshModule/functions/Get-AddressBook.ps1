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
