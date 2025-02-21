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
