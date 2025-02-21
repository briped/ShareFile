function Get-Item {
	# https://api.sharefile.com/docs/resource?name=Items#Get_HomeFolder_for_Current_User
	# https://api.sharefile.com/docs/resource?name=Items#Get_Item_by_ID
	# https://api.sharefile.com/docs/resource?name=Items#Get_Item_by_Path
	# https://api.sharefile.com/docs/resource?name=Items#Get_Item_by_relative_Path_from_ID
	# https://api.sharefile.com/docs/resource?name=Items#Get_Parent_Item
	# https://api.sharefile.com/docs/resource?name=Items#Get_Children
	[CmdletBinding()]
	param (
		# Item identifier
		[Parameter(Position = 0
				,  ValueFromPipeline = $true
				,  ValueFromPipelineByPropertyName = $true)]
		[string]
		$Id
		,
		# Path to retrieve
		[Parameter()]
		[string]
		$Path
		,
		# Specifies whether or not the list of items returned should include deleted children
		[Parameter()]
		[switch]
		$Deleted
		,
		# Returns: the Parent Item of the give object ID.
		[Parameter()]
		[switch]
		$Parent
		,
		# Returns: the list of children under the given object ID
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
		$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Items"
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
