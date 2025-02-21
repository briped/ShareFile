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
