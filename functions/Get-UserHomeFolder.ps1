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
