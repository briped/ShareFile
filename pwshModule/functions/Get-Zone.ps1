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
