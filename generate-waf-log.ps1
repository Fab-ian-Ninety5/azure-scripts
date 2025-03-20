#  Author : Fabian Sundara Raj
#
# This script allows you to generate WAF Logs.
# Please turn off any VPN/Proxy connections before running this script.
# This script only works if your application gateway is logging to a Log Analytics workspace.
# Run the script in Azure Cloud Shell or in your local machine with Az PowerShell module installed.


$hostname = Read-Host "Enter Hostname"
$lineLength = 93 # Adjust this if you want a different total line length

$lineText = "Resolving $hostname to an IP address"
$dotLength = $lineLength - $lineText.Length - 2
$dots = "." * $dotLength

Write-Host "| $lineText$dots |" -ForegroundColor Cyan

try {
    $wafPIP = (Resolve-DnsName $hostname -Type A -Server 8.8.8.8).IPAddress
}
catch {
    Write-Host "Failed to resolve hostname to an IP address. Please check the hostname and try again." -ForegroundColor Red
    exit
}

$query = @"
// Run query to see results.
resources
| where type =~ "microsoft.network/applicationgateways"
| extend skuName = tostring(properties.sku.name)
| extend localizedSkuName = case(skuName =~ 'Standard_Small', 'Small',
    skuName =~ 'Standard_Medium', 'Medium',
    skuName =~ 'Standard_Large', 'Large',
    skuName =~ 'Standard_Large_V2', 'Large V2',
    skuName =~ 'WAF_Medium', 'Medium',
    skuName =~ 'WAF_Large', 'Large',
    skuName =~ 'WAF_v2', 'Waf_v2',
    skuName =~ 'Standard_v2', 'Standard_v2',
    coalesce(skuName, '-'))
| extend instanceCount = coalesce(properties.sku.capacity, '-')
| extend frontendIPConfigs=iff(array_length(properties.frontendIPConfigurations) == 0, dynamic(null), properties.frontendIPConfigurations)
| extend gatewayIPConfigs=iff(array_length(properties.gatewayIPConfigurations) == 0, dynamic(null), properties.gatewayIPConfigurations)
| mvexpand frontendIPConfigurations=frontendIPConfigs, gatewayIPConfigurations=gatewayIPConfigs limit 400
// When `parse_ipv4` fails (returns null), it implies the address is not IPv4, hence considered IPv6. This is used to differentiate between IPv4 and IPv6 addresses, as there's no direct `parse_ipv6` function.
| extend privateIpV4Address=iff(isnotempty(parse_ipv4(tostring(frontendIPConfigurations.properties.privateIPAddress))), tostring(frontendIPConfigurations.properties.privateIPAddress), '')
| extend privateIpV6Address=iff(isnotempty(parse_ipv4(tostring(frontendIPConfigurations.properties.privateIPAddress))), '', tostring(frontendIPConfigurations.properties.privateIPAddress))
| summarize publicIpAddressId=tostring(tolower(any(frontendIPConfigurations.properties.publicIPAddress.id))),
            privateIpV4Address=any(privateIpV4Address),
            privateIpV6Address=any(privateIpV6Address),
            subnetId=tostring(tolower(any(gatewayIPConfigurations.properties.subnet.id))),
            tags=any(tags)
            by name, id, type, kind, location, resourceGroup, subscriptionId, localizedSkuName, instanceCount
| parse kind=regex tostring(subnetId) with 'microsoft.network/virtualnetworks/' virtualNetwork '/subnets/' subnet
| join kind=leftouter hint.strategy=shuffle (data
    | where type =~ 'microsoft.network/publicipaddresses'
    | extend publicIpV4Address = iff(tostring(tolower(properties.publicIPAddressVersion)) == 'ipv4', tostring(properties.ipAddress), '')
    | extend publicIpV6Address = iff(tostring(tolower(properties.publicIPAddressVersion)) == 'ipv6', tostring(properties.ipAddress), '')
    | extend fqdn = tostring(properties.dnsSettings.fqdn)
    | project publicIpAddressId=tolower(id), publicIpV4Address, publicIpV6Address, fqdn)
    on publicIpAddressId
| project name,
          id,
          type,
          kind,
          location,
          resourceGroup,
          subscriptionId,
          tags,
          publicIpV4Address=coalesce(publicIpV4Address, '-'),
          publicIpV6Address=coalesce(publicIpV6Address, '-'),
          publicDnsName=coalesce(split(fqdn, '.')[0], '-'),
          privateIpV4Address=coalesce(privateIpV4Address, '-'),
          privateIpV6Address=coalesce(privateIpV6Address, '-'),
          virtualNetwork=coalesce(virtualNetwork, '-'),
          subnet=coalesce(subnet, '-'),
          localizedSkuName,
          instanceCount
| extend locationDisplayName=case(location =~ 'eastus','East US',location =~ 'southcentralus','South Central US',location =~ 'westus2','West US 2',location =~ 'westus3','West US 3',location =~ 'australiaeast','Australia East',location =~ 'southeastasia','Southeast Asia',location =~ 'northeurope','North Europe',location =~ 'swedencentral','Sweden Central',location =~ 'uksouth','UK South',location =~ 'westeurope','West Europe',location =~ 'centralus','Central US',location =~ 'southafricanorth','South Africa North',location =~ 'centralindia','Central India',location =~ 'eastasia','East Asia',location =~ 'indonesiacentral','Indonesia Central',location =~ 'japaneast','Japan East',location =~ 'japanwest','Japan West',location =~ 'koreacentral','Korea Central',location =~ 'newzealandnorth','New Zealand North',location =~ 'canadacentral','Canada Central',location =~ 'francecentral','France Central',location =~ 'germanywestcentral','Germany West Central',location =~ 'italynorth','Italy North',location =~ 'norwayeast','Norway East',location =~ 'polandcentral','Poland Central',location =~ 'spaincentral','Spain Central',location =~ 'switzerlandnorth','Switzerland North',location =~ 'mexicocentral','Mexico Central',location =~ 'uaenorth','UAE North',location =~ 'brazilsouth','Brazil South',location =~ 'israelcentral','Israel Central',location =~ 'qatarcentral','Qatar Central',location =~ 'centralusstage','Central US (Stage)',location =~ 'eastusstage','East US (Stage)',location =~ 'eastus2stage','East US 2 (Stage)',location =~ 'northcentralusstage','North Central US (Stage)',location =~ 'southcentralusstage','South Central US (Stage)',location =~ 'westusstage','West US (Stage)',location =~ 'westus2stage','West US 2 (Stage)',location =~ 'asia','Asia',location =~ 'asiapacific','Asia Pacific',location =~ 'australia','Australia',location =~ 'brazil','Brazil',location =~ 'canada','Canada',location =~ 'europe','Europe',location =~ 'france','France',location =~ 'germany','Germany',location =~ 'global','Global',location =~ 'india','India',location =~ 'israel','Israel',location =~ 'italy','Italy',location =~ 'japan','Japan',location =~ 'korea','Korea',location =~ 'newzealand','New Zealand',location =~ 'norway','Norway',location =~ 'poland','Poland',location =~ 'qatar','Qatar',location =~ 'singapore','Singapore',location =~ 'southafrica','South Africa',location =~ 'sweden','Sweden',location =~ 'switzerland','Switzerland',location =~ 'uae','United Arab Emirates',location =~ 'uk','United Kingdom',location =~ 'unitedstates','United States',location =~ 'unitedstateseuap','United States EUAP',location =~ 'eastasiastage','East Asia (Stage)',location =~ 'southeastasiastage','Southeast Asia (Stage)',location =~ 'brazilus','Brazil US',location =~ 'eastus2','East US 2',location =~ 'northcentralus','North Central US',location =~ 'westus','West US',location =~ 'jioindiawest','Jio India West',location =~ 'westcentralus','West Central US',location =~ 'southafricawest','South Africa West',location =~ 'australiacentral','Australia Central',location =~ 'australiacentral2','Australia Central 2',location =~ 'australiasoutheast','Australia Southeast',location =~ 'jioindiacentral','Jio India Central',location =~ 'koreasouth','Korea South',location =~ 'southindia','South India',location =~ 'westindia','West India',location =~ 'canadaeast','Canada East',location =~ 'francesouth','France South',location =~ 'germanynorth','Germany North',location =~ 'norwaywest','Norway West',location =~ 'switzerlandwest','Switzerland West',location =~ 'ukwest','UK West',location =~ 'uaecentral','UAE Central',location =~ 'brazilsoutheast','Brazil Southeast',location)
| extend subscriptionDisplayName=case(subscriptionId =~ '28bc2e9f-6879-40cf-8cf4-40411860db14','Myminutes (PROD)',subscriptionId =~ 'b4ff1bb8-5058-44a6-8807-0b0316e6e13a','PETRONAS Microsoft Azure Enterprise',subscriptionId =~ '3caaf296-fe14-41e6-8ba2-4f1dd8dfc7fd','PTAZBR-PROD ENVIRONMENT',subscriptionId =~ '2a6acc04-1f59-422b-8ce3-53c7fd75b35f','PTAZJP-DR ENVIRONMENT',subscriptionId =~ '77e7ce15-02ec-4beb-bf56-383894f57669','PTAZSCUS-CORE ENVIRONMENT',subscriptionId =~ '1cd65eea-84f4-48da-bdcf-c5b956b0eda0','PTAZSCUS-PROD ENVIRONMENT',subscriptionId =~ '1cb9e211-f425-4519-ac3d-5f8b148e1728','PTAZSG-CoC-Lab ENVIRONMENT',subscriptionId =~ '8a71ac81-04ed-4e9b-adea-c852951f4d69','PTAZSG-CORE ENVIRONMENT',subscriptionId =~ 'b5a67ad5-d38a-4258-aa5e-31e39d3b709f','PTAZSG-DEV ENVIRONMENT',subscriptionId =~ '2be5068f-e0ac-4d57-aedc-96bc9798a265','PTAZSG-IAC-DEV ENVIRONMENT',subscriptionId =~ '9ffdd582-5cb5-4b93-a16f-27d84e5b5293','PTAZSG-IAC-DEV-DAA ENVIRONMENT',subscriptionId =~ '76b6b7bf-38ac-47cf-b921-dc6e066bcee0','PTAZSG-IAC-NONPROD-EDH ENVIRONMENT',subscriptionId =~ 'e2c2906c-8901-4443-a9ee-50ffe123541a','PTAZSG-IAC-PROD ENVIRONMENT',subscriptionId =~ '7003ae80-02ed-43c8-9c84-c16f3d931f2f','PTAZSG-IAC-PROD-DAA ENVIRONMENT',subscriptionId =~ 'd861daf0-920b-4930-b69c-7b3c0467e7ef','PTAZSG-IAC-PROD-EDH ENVIRONMENT',subscriptionId =~ '1c334150-08b8-4088-9170-074fa26a9926','PTAZSG-IAC-UAT ENVIRONMENT',subscriptionId =~ '9f85a9aa-940f-43b5-bda8-edf972f6026c','PTAZSG-POC-OT-ENVIRONMENT',subscriptionId =~ '2493e36c-7992-45d9-919b-8afe2e6018d7','PTAZSG-POC-PLI ENVIRONMENT',subscriptionId =~ '5f782fe2-8948-4fd8-8bce-a09ad5d3cb62','PTAZSG-PROD ENVIRONMENT',subscriptionId =~ 'd3388e15-92da-4acc-b85b-bd5b3f88f9ec','PTAZSG-PROD-GEOC ENVIRONMENT',subscriptionId =~ '96ed4214-643d-4990-9df6-636e49577104','PTAZSG-PROD-OLV ENVIRONMENT',subscriptionId =~ 'a215e848-9be3-46c4-ac91-85558f9c26af','PTAZSG-SANDBOX ENVIRONMENT',subscriptionId =~ 'cb5468c2-6fd1-4289-b24a-05a36baa129c','PTAZSG-SANDBOX-EA ENVIRONMENT',subscriptionId =~ 'b9c4e2a3-a10d-4a47-94b7-0fb93b30690f','PTAZSG-UAT ENVIRONMENT',subscriptionId =~ '69fc90d0-5e9f-4cc2-85bb-55c12618fee2','PTAZWEU-PROD ENVIRONMENT',subscriptionId)
| where (type !~ ('dell.storage/filesystems'))
| where (type !~ ('microsoft.weightsandbiases/instances'))
| where (type !~ ('pinecone.vectordb/organizations'))
| where (type !~ ('mongodb.atlas/organizations'))
| where (type !~ ('lambdatest.hyperexecute/organizations'))
| where (type !~ ('commvault.contentstore/cloudaccounts'))
| where (type !~ ('arizeai.observabilityeval/organizations'))
| where (type !~ ('paloaltonetworks.cloudngfw/globalrulestacks'))
| where (type !~ ('microsoft.liftrpilot/organizations'))
| where (type !~ ('purestorage.block/storagepools/avsstoragecontainers'))
| where (type !~ ('purestorage.block/reservations'))
| where (type !~ ('purestorage.block/storagepools'))
| where (type !~ ('solarwinds.observability/organizations'))
| where (type !~ ('microsoft.agfoodplatform/farmbeats'))
| where (type !~ ('microsoft.agricultureplatform/agriservices'))
| where (type !~ ('microsoft.appsecurity/policies'))
| where (type !~ ('microsoft.arc/allfairfax'))
| where (type !~ ('microsoft.arc/all'))
| where (type !~ ('microsoft.cdn/profiles/securitypolicies'))
| where (type !~ ('microsoft.cdn/profiles/secrets'))
| where (type !~ ('microsoft.cdn/profiles/rulesets'))
| where (type !~ ('microsoft.cdn/profiles/rulesets/rules'))
| where (type !~ ('microsoft.cdn/profiles/afdendpoints/routes'))
| where (type !~ ('microsoft.cdn/profiles/origingroups'))
| where (type !~ ('microsoft.cdn/profiles/origingroups/origins'))
| where (type !~ ('microsoft.cdn/profiles/afdendpoints'))
| where (type !~ ('microsoft.cdn/profiles/customdomains'))
| where (type !~ ('microsoft.chaos/privateaccesses'))
| where (type !~ ('microsoft.sovereign/transparencylogs'))
| where (type !~ ('microsoft.sovereign/landingzoneconfigurations'))
| where (type !~ ('microsoft.hardwaresecuritymodules/cloudhsmclusters'))
| where (type !~ ('microsoft.cloudtest/accounts'))
| where (type !~ ('microsoft.cloudtest/hostedpools'))
| where (type !~ ('microsoft.cloudtest/images'))
| where (type !~ ('microsoft.cloudtest/pools'))
| where (type !~ ('microsoft.compute/virtualmachineflexinstances'))
| where (type !~ ('microsoft.compute/standbypoolinstance'))
| where (type !~ ('microsoft.compute/computefleetscalesets'))
| where (type !~ ('microsoft.compute/computefleetinstances'))
| where (type !~ ('microsoft.containerservice/managedclusters/microsoft.kubernetesconfiguration/fluxconfigurations'))
| where (type !~ ('microsoft.kubernetes/connectedclusters/microsoft.kubernetesconfiguration/fluxconfigurations'))
| where (type !~ ('microsoft.containerservice/managedclusters/microsoft.kubernetesconfiguration/namespaces'))
| where (type !~ ('microsoft.kubernetes/connectedclusters/microsoft.kubernetesconfiguration/namespaces'))
| where (type !~ ('microsoft.containerservice/managedclusters/microsoft.kubernetesconfiguration/extensions'))
| where (type !~ ('microsoft.kubernetesconfiguration/extensions'))
| where (type !~ ('microsoft.portalservices/extensions/deployments'))
| where (type !~ ('microsoft.portalservices/extensions'))
| where (type !~ ('microsoft.portalservices/extensions/slots'))
| where (type !~ ('microsoft.portalservices/extensions/versions'))
| where (type !~ ('microsoft.deviceregistry/devices'))
| where (type !~ ('microsoft.deviceupdate/updateaccounts'))
| where (type !~ ('microsoft.deviceupdate/updateaccounts/updates'))
| where (type !~ ('microsoft.deviceupdate/updateaccounts/deviceclasses'))
| where (type !~ ('microsoft.deviceupdate/updateaccounts/deployments'))
| where (type !~ ('microsoft.deviceupdate/updateaccounts/agents'))
| where (type !~ ('microsoft.deviceupdate/updateaccounts/activedeployments'))
| where (type !~ ('microsoft.documentdb/fleets'))
| where (type !~ ('private.easm/workspaces'))
| where (type !~ ('microsoft.workloads/epicvirtualinstances'))
| where (type !~ ('microsoft.fairfieldgardens/provisioningresources'))
| where (type !~ ('microsoft.fairfieldgardens/provisioningresources/provisioningpolicies'))
| where (type !~ ('microsoft.healthmodel/healthmodels'))
| where (type !~ ('microsoft.hybridcompute/machinessoftwareassurance'))
| where (type !~ ('microsoft.hybridcompute/machinespaygo'))
| where (type !~ ('microsoft.hybridcompute/machinesesu'))
| where (type !~ ('microsoft.hybridcompute/machinessovereign'))
| where (type !~ ('microsoft.hybridcompute/arcserverwithwac'))
| where (type !~ ('microsoft.network/networkvirtualappliances'))
| where (type !~ ('microsoft.network/virtualhubs')) or ((kind =~ ('routeserver')))
| where (type !~ ('microsoft.devhub/iacprofiles'))
| where (type !~ ('microsoft.modsimworkbench/workbenches/chambers'))
| where (type !~ ('microsoft.modsimworkbench/workbenches/chambers/files'))
| where (type !~ ('microsoft.modsimworkbench/workbenches/chambers/filerequests'))
| where (type !~ ('microsoft.modsimworkbench/workbenches/chambers/licenses'))
| where (type !~ ('microsoft.modsimworkbench/workbenches/chambers/connectors'))
| where (type !~ ('microsoft.modsimworkbench/workbenches/sharedstorages'))
| where (type !~ ('microsoft.modsimworkbench/workbenches/chambers/storages'))
| where (type !~ ('microsoft.modsimworkbench/workbenches/chambers/workloads'))
| where (type !~ ('microsoft.dashboard/dashboards'))
| where (type !~ ('private.monitorgrafana/dashboards'))
| where (type !~ ('microsoft.insights/diagnosticsettings'))
| where not((type =~ ('microsoft.network/serviceendpointpolicies')) and ((kind =~ ('internal'))))
| where (type !~ ('microsoft.resources/resourcegraphvisualizer'))
| where (type !~ ('microsoft.orbital/cloudaccessrouters'))
| where (type !~ ('microsoft.orbital/terminals'))
| where (type !~ ('microsoft.orbital/sdwancontrollers'))
| where (type !~ ('microsoft.orbital/spacecrafts/contacts'))
| where (type !~ ('microsoft.orbital/contactprofiles'))
| where (type !~ ('microsoft.orbital/edgesites'))
| where (type !~ ('microsoft.orbital/geocatalogs'))
| where (type !~ ('microsoft.orbital/groundstations'))
| where (type !~ ('microsoft.orbital/l2connections'))
| where (type !~ ('microsoft.orbital/spacecrafts'))
| where (type !~ ('microsoft.recommendationsservice/accounts/modeling'))
| where (type !~ ('microsoft.recommendationsservice/accounts/serviceendpoints'))
| where (type !~ ('microsoft.recoveryservicesintd2/vaults'))
| where (type !~ ('microsoft.recoveryservicesintd/vaults'))
| where (type !~ ('microsoft.recoveryservicesbvtd2/vaults'))
| where (type !~ ('microsoft.recoveryservicesbvtd/vaults'))
| where (type !~ ('microsoft.relationships/servicegroupmember'))
| where (type !~ ('microsoft.relationships/dependencyof'))
| where (type !~ ('microsoft.resources/virtualsubscriptionsforresourcepicker'))
| where (type !~ ('microsoft.resources/deletedresources'))
| where (type !~ ('microsoft.deploymentmanager/rollouts'))
| where (type !~ ('microsoft.features/featureprovidernamespaces/featureconfigurations'))
| where (type !~ ('microsoft.saashub/cloudservices/hidden'))
| where (type !~ ('microsoft.providerhub/providerregistrations'))
| where (type !~ ('microsoft.providerhub/providerregistrations/customrollouts'))
| where (type !~ ('microsoft.providerhub/providerregistrations/defaultrollouts'))
| where (type !~ ('microsoft.edge/configurations'))
| where not((type =~ ('microsoft.synapse/workspaces/sqlpools')) and ((kind =~ ('v3'))))
| where (type !~ ('microsoft.mission/virtualenclaves/workloads'))
| where (type !~ ('microsoft.mission/virtualenclaves'))
| where (type !~ ('microsoft.mission/communities/transithubs'))
| where (type !~ ('microsoft.mission/virtualenclaves/enclaveendpoints'))
| where (type !~ ('microsoft.mission/enclaveconnections'))
| where (type !~ ('microsoft.mission/communities/communityendpoints'))
| where (type !~ ('microsoft.mission/communities'))
| where (type !~ ('microsoft.mission/catalogs'))
| where (type !~ ('microsoft.mission/approvals'))
| where (type !~ ('microsoft.workloads/insights'))
| where (type !~ ('microsoft.hanaonazure/sapmonitors'))
| where (type !~ ('microsoft.zerotrustsegmentation/segmentationmanagers'))
| where (type !~ ('microsoft.cloudhealth/healthmodels'))
| where (type !~ ('microsoft.connectedcache/enterprisemcccustomers/enterprisemcccachenodes'))
| where not((type =~ ('microsoft.sql/servers')) and ((kind =~ ('v12.0,analytics'))))
| where not((type =~ ('microsoft.sql/servers/databases')) and ((kind in~ ('system','v2.0,system','v12.0,system','v12.0,system,serverless','v12.0,user,datawarehouse,gen2,analytics'))))
| project name,publicIpV4Address,privateIpV4Address,resourceGroup,locationDisplayName,subscriptionDisplayName,localizedSkuName,subscriptionId,id,type,kind,location,tags
| sort by (tolower(tostring(name))) asc
"@

$lineText = "Executing query for Application Gateway"
$dotLength = $lineLength - $lineText.Length - 2
$dots = "." * $dotLength
Write-Host "| $lineText$dots |" -ForegroundColor Cyan

$queryResult = Search-AzGraph -Query $query

$targetAGW = $queryResult | Where-Object { $_.publicIpV4Address -eq $wafPIP }

if (-not $targetAGW) {
    Write-Host "No Application Gateway found with the resolved public IP address." -ForegroundColor Yellow
    exit
}

Set-AzContext -SubscriptionId $targetAGW.subscriptionId | Out-Null

$lineText = "Executing query on LAW"
$dotLength = $lineLength - $lineText.Length - 2
$dots = "." * $dotLength
Write-Host "| $lineText$dots |" -ForegroundColor Cyan

$agwLogQuery = @"
AzureDiagnostics
    | where TimeGenerated >= ago(1d)
    | where ResourceType == 'APPLICATIONGATEWAYS' and Category == 'ApplicationGatewayFirewallLog'
    | where hostname_s == '$hostname'
    | where clientIp_s !contains '4.145.106.87'
    | project TimeGenerated, hostname_s, requestUri_s, details_message_s, action_s, ruleSetType_s, details_data_s, clientIp_s, Message, ruleId_s, ruleSetVersion_s, Resource
"@

$targetAGWObj = Get-AzApplicationGateway -Name $targetAGW.name -ResourceGroupName $targetAGW.resourceGroup

$lineText = "Displaying AGW Details"
$dotLength = $lineLength - $lineText.Length - 2
$dots = "." * $dotLength
Write-Host "| $lineText$dots |" -ForegroundColor Cyan

$targetAGWObj | Select-Object Name, ResourceGroupName, Location, Sku, @{N = "Listener_Count"; E = { $_.HttpListeners.Count } }

$workspaceId = (Get-AzDiagnosticSetting -ResourceId $targetAGW.id).WorkspaceId
$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $workspaceId.Split("/")[4] -Name $workspaceId.Split("/")[8]

$lineText = "LAW Details"
$dotLength = $lineLength - $lineText.Length - 2
$dots = "." * $dotLength
Write-Host "| $lineText$dots |" -ForegroundColor Cyan

$workspace | Select-Object Name, ResourceGroupName, Location

if (-not $workspaceId) {
    Write-Host "No Log Analytics workspace found for the Application Gateway." -ForegroundColor Yellow
    exit
}

$lineText = "Exporting CSV"
$dotLength = $lineLength - $lineText.Length - 2
$dots = "." * $dotLength
Write-Host "| $lineText$dots |" -ForegroundColor Cyan

$ResultList = Invoke-AzOperationalInsightsQuery -Workspace $workspace -Query $agwLogQuery
$ResultList.Results | Export-Csv -Path waf-query-$hostname-$(get-date -f yyyy-MM-dd-HH-mm).csv
