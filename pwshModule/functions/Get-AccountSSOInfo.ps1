function Get-AccountSSOInfo {
	# https://api.sharefile.com/docs/resource?name=Accounts#Get_SSO_Info
	[CmdletBinding()]
	param (
		# Company subdomain; f.ex. "MyCompany" is the subdomain of "MyCompany.sharefile.com"
		[Parameter(Mandatory = $true)]
		[string]
		$SubDomain
	)
	$Script:Token = Get-Token
	$Header = @{
		Authorization = "Bearer $($Script:Token.access_token)"
	}
	$Uri = "https://$($Script:Token.subdomain).$($Script:Token.apicp)/sf/v3/Accounts/SSO?subdomain=$($SubDomain)"
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
