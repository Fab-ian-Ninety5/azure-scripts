#  Author : Fabian Sundara Raj
#
# This script allows you to list all hostname in WAFv1. You may amend the resource graph query below to get the list of hostnames for other tiers.
# The script will export the result to a CSV file in the same directory where the script is executed.
# Run the script in Azure Cloud Shell or in your local machine with Az PowerShell module installed.
# Advisable to run the script in Azure Cloud Shell to avoid any issues with the Az PowerShell module version.

$agwQuery = @"
resources
| where type == "microsoft.network/applicationgateways"
| where properties.sku.tier == "WAF"
| project id, name, location, resourceGroup, subscriptionId, skuName = properties.sku.name, skuTier = properties.sku.tier
"@

$agwList = Search-AzGraph -Query $agwQuery
$hostnames = @()

Write-Host "_________________________________________________________________________________________________________________"
Write-Host "Processing Application Gateways" -ForegroundColor Green
Write-Host "#################################################################################################################"

foreach ($agw in $agwList) {
    Set-AzContext -SubscriptionId $agw.subscriptionId | Out-Null
    
    $agwDetails = Get-AzApplicationGateway -ResourceGroupName $agw.resourceGroup -Name $agw.name

    Write-Host "_________________________________________________________________________________________________________________"
    Write-Host "Processing HTTP Listeners for Application Gateway: $($agw.name)" -ForegroundColor Green
    Write-Host "#################################################################################################################"

    Write-Host ""
    Write-Host ""
    
    foreach ($listener in $agwDetails.HttpListeners) {
        Write-Host "Checking DNS Resolution for: $($listener.HostName)"
        try {
            $dnsResult = Resolve-DnsName -Name $listener.HostName -Type A -ErrorAction Stop
            $actualDnsResult = $dnsResult.IPAddress
        }
        catch {
            $actualDnsResult = "Not Resolved"
        }
        $hostnames += [PSCustomObject]@{
            ApplicationGatewayName = $agw.name
            ResourceGroup          = $agw.resourceGroup
            SubscriptionId         = $agw.subscriptionId
            Location               = $agw.location
            Hostname               = $listener.HostName
            ResolvedIp             = $actualDnsResult
        }
    }
}

$datetimeSuffix = Get-Date -Format "yyyyMMdd_HHmmss"
$filePath = "AGW_Hostnames_$datetimeSuffix.csv"


Write-Host "_________________________________________________________________________________________________________________"
Write-Host "Exporting result to CSV File - $filePath" -ForegroundColor Green
Write-Host "#################################################################################################################"
#$hostnames
$hostnames | Export-Csv -Path $filePath -NoTypeInformation
