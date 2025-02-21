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
