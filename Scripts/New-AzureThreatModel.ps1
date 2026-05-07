<#
.SYNOPSIS
    Connects to an Azure subscription, enumerates resources, and generates a
    Microsoft Threat Modeling Tool (.tm7) file plus an inventory CSV and a
    Markdown STRIDE-prompt report.

.DESCRIPTION
    Workflow:
      1. Connect-AzAccount  (skipped if already connected to the target sub)
      2. Get-AzResource     (optionally filtered by ResourceGroupName)
      3. Load the .tb7 template, parse ElementTypes
      4. Load the baseline .tm7 (provides the embedded KnowledgeBase that
         TMT requires - hand-rolling that payload is too brittle, so we
         clone it from a known-good model created from the same template)
      5. Map each Azure resource type to a template stencil
      6. Emit:
            <Output>\<sub>-<timestamp>.tm7   (open with TMT 7.x)
            <Output>\<sub>-<timestamp>.csv   (resource -> stencil inventory)
            <Output>\<sub>-<timestamp>.md    (per-resource STRIDE prompts)

.PARAMETER SubscriptionId
    Azure subscription ID (GUID) or name. Required.

.PARAMETER ResourceGroupName
    Optional. Limit enumeration to a single resource group.

.PARAMETER TemplatePath
    Local path to the .tb7 file. Defaults to a copy next to the script.

.PARAMETER TemplateUrl
    Source URL for the .tb7 if TemplatePath does not exist.

.PARAMETER BaselineTm7
    Path to a .tm7 file that was previously saved by TMT against the SAME .tb7
    template. Its embedded KnowledgeBase is reused as the basis for the new
    model. If you do not have one, open TMT once, File -> Create A Model,
    select your .tb7, save as an empty model, and pass that path here.

.PARAMETER OutputDirectory
    Directory for generated files. Defaults to .\output next to this script.

.EXAMPLE
    .\New-AzureThreatModel.ps1 -SubscriptionId 00000000-0000-0000-0000-000000000000

.EXAMPLE
    .\New-AzureThreatModel.ps1 -SubscriptionId "Prod" -ResourceGroupName "rg-app-prod" `
        -BaselineTm7 "C:\path\to\baseline.tm7"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $SubscriptionId,

    [string] $ResourceGroupName,

    [string] $TemplatePath = (Join-Path $PSScriptRoot 'MicrosoftTemplate.v2.2.tb7'),

    [string] $TemplateUrl = 'https://raw.githubusercontent.com/PatrickGallucci/threat-model-templates/master/MicrosoftTemplate.v2.2.tb7',

    [string] $BaselineTm7 = "$env:USERPROFILE\OneDrive - Microsoft\Documents\GitHub\threat-model-templates\Samples\az-security-threat-model.tm7",

    [string] $OutputDirectory = (Join-Path $PSScriptRoot 'output')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

#region ---------- Azure resource type -> stencil-name map ----------

# Stencil names are taken verbatim from MicrosoftTemplate.v2.2.tb7.
# Anything missing falls back to 'Generic Process' and is flagged in the report.
$AzureTypeToStencil = @{
    'Microsoft.Web/sites'                               = 'App Service'
    'Microsoft.Web/sites/slots'                         = 'App Service'
    'Microsoft.Web/serverFarms'                         = 'App Service'
    'Microsoft.Web/staticSites'                         = 'Web Application'
    'Microsoft.Web/connections'                         = 'API App'
    'Microsoft.Web/customApis'                          = 'API App'
    'Microsoft.Compute/virtualMachines'                 = 'Windows Virtual Machines'
    'Microsoft.Compute/virtualMachineScaleSets'         = 'Virtual Machine Scale Sets'
    'Microsoft.Compute/disks'                           = 'Azure Storage'
    'Microsoft.Compute/snapshots'                       = 'Backup'
    'Microsoft.Compute/images'                          = 'Windows Virtual Machines'
    'Microsoft.ContainerInstance/containerGroups'       = 'App Service'
    'Microsoft.ContainerService/managedClusters'        = 'Azure Kubernetes Service'
    'Microsoft.ContainerRegistry/registries'            = 'Container Registry'
    'Microsoft.Storage/storageAccounts'                 = 'Azure Storage'
    'Microsoft.KeyVault/vaults'                         = 'Key Vault'
    'Microsoft.KeyVault/managedHSMs'                    = 'Key Vault'
    'Microsoft.Sql/servers'                             = 'Azure SQL Database Managed Instance'
    'Microsoft.Sql/servers/databases'                   = 'Azure SQL Database Managed Instance'
    'Microsoft.Sql/managedInstances'                    = 'Azure SQL Database Managed Instance'
    'Microsoft.DBforPostgreSQL/servers'                 = 'Azure Database for PostgreSQL'
    'Microsoft.DBforPostgreSQL/flexibleServers'         = 'Azure Database for PostgreSQL'
    'Microsoft.DBforMySQL/servers'                      = 'Azure Database for MySQL'
    'Microsoft.DBforMySQL/flexibleServers'              = 'Azure Database for MySQL'
    'Microsoft.DBforMariaDB/servers'                    = 'Azure Database for MariaDB'
    'Microsoft.DocumentDB/databaseAccounts'             = 'CosmosDB'
    'Microsoft.Cache/Redis'                             = 'Azure Redis Cache'
    'Microsoft.Cache/redisEnterprise'                   = 'Azure Redis Cache'
    'Microsoft.Search/searchServices'                   = 'Azure Search'
    'Microsoft.DataFactory/factories'                   = 'Azure Data Factory'
    'Microsoft.Synapse/workspaces'                      = 'Azure Synapse Workspace'
    'Microsoft.Synapse/workspaces/sqlPools'             = 'Azure Synapse SQL Pool'
    'Microsoft.Synapse/workspaces/bigDataPools'         = 'Azure Synapse Spark Pools'
    'Microsoft.Databricks/workspaces'                   = 'Azure Databricks'
    'Microsoft.MachineLearningServices/workspaces'      = 'Machine Learning'
    'Microsoft.CognitiveServices/accounts'              = 'Cognitive Services'
    'Microsoft.BotService/botServices'                  = 'Bot Service'
    'Microsoft.Network/virtualNetworks'                 = 'Virtual Network'
    'Microsoft.Network/virtualNetworks/subnets'         = 'Virtual Network'
    'Microsoft.Network/networkInterfaces'               = 'Virtual Network'
    'Microsoft.Network/publicIPAddresses'               = 'Virtual Network'
    'Microsoft.Network/networkSecurityGroups'           = 'Network Security Group'
    'Microsoft.Network/applicationGateways'             = 'Application Gateway'
    'Microsoft.Network/loadBalancers'                   = 'Load Balancer'
    'Microsoft.Network/azureFirewalls'                  = 'Azure Firewall'
    'Microsoft.Network/firewallPolicies'                = 'Azure Firewall'
    'Microsoft.Network/virtualWans'                     = 'Azure Virtual WAN'
    'Microsoft.Network/virtualHubs'                     = 'Azure Virtual WAN'
    'Microsoft.Network/vpnGateways'                     = 'VPN Gateway'
    'Microsoft.Network/expressRouteCircuits'            = 'VPN Gateway'
    'Microsoft.Network/trafficmanagerprofiles'          = 'Traffic Manager'
    'Microsoft.Network/frontDoors'                      = 'Application Gateway'
    'Microsoft.Network/dnsZones'                        = 'DNS'
    'Microsoft.Network/privateDnsZones'                 = 'DNS'
    'Microsoft.Cdn/profiles'                            = 'CDN'
    'Microsoft.Cdn/profiles/endpoints'                  = 'CDN'
    'Microsoft.ApiManagement/service'                   = 'API Management'
    'Microsoft.ServiceBus/namespaces'                   = 'Service Bus'
    'Microsoft.EventHub/namespaces'                     = 'Azure Event Hub'
    'Microsoft.EventGrid/topics'                        = 'Event Grid'
    'Microsoft.EventGrid/systemTopics'                  = 'Event Grid'
    'Microsoft.Logic/workflows'                         = 'LogicApp'
    'Microsoft.Logic/integrationAccounts'               = 'LogicApp'
    'Microsoft.NotificationHubs/namespaces'             = 'Notification Hub'
    'Microsoft.SignalRService/SignalR'                  = 'Notification Hub'
    'Microsoft.Devices/IotHubs'                         = 'IoT Cloud Gateway Zone'
    'Microsoft.StreamAnalytics/streamingjobs'           = 'Stream Analytics'
    'Microsoft.HDInsight/clusters'                      = 'HDInsight'
    'Microsoft.DataLakeStore/accounts'                  = 'Data Lake Store'
    'Microsoft.DataLakeAnalytics/accounts'              = 'Data Lake Analytics'
    'Microsoft.AnalysisServices/servers'                = 'Analysis Services'
    'Microsoft.PowerBIDedicated/capacities'             = 'Power BI Embedded'
    'Microsoft.MediaServices/mediaServices'             = 'Media Services'
    'Microsoft.RecoveryServices/vaults'                 = 'Site Recovery'
    'Microsoft.OperationalInsights/workspaces'          = 'Log Analytics'
    'Microsoft.Insights/components'                     = 'Application Insights'
    'Microsoft.Insights/actionGroups'                   = 'Azure Alerts'
    'Microsoft.Insights/scheduledQueryRules'            = 'Azure Alerts'
    'Microsoft.AlertsManagement/smartDetectorAlertRules' = 'Azure Alerts'
    'Microsoft.Automation/automationAccounts'           = 'Automation'
    'Microsoft.Automation/automationAccounts/runbooks'  = 'Automation Runbook'
    'Microsoft.SecurityCenter/pricings'                 = 'Security Center'
    'Microsoft.Security/assessments'                    = 'Advanced Threat Protection'
    'Microsoft.OperationsManagement/solutions'          = 'Microsoft Sentinal'
    'Microsoft.Purview/accounts'                        = 'Microsoft Purview'
    'Microsoft.ManagedIdentity/userAssignedIdentities'  = 'Microsoft Entra ID'
    'Microsoft.AAD/domainServices'                      = 'Active Directory Domain Services'
    'Microsoft.Web/sites/functions'                     = 'Functions'
    'Microsoft.Batch/batchAccounts'                     = 'Batch'
    'Microsoft.ServiceFabric/clusters'                  = 'Service Fabric'
    'Microsoft.ServiceFabric/managedClusters'           = 'Service Fabric'
    'Microsoft.HealthcareApis/services'                 = 'Azure API for FHIR'
    'Microsoft.HealthcareApis/workspaces/fhirservices'  = 'Azure API for FHIR'
    'Microsoft.DevTestLab/labs'                         = 'Devtest Labs'
    'Microsoft.DataShare/accounts'                      = 'Azure Data Share'
    'Microsoft.DataBox/jobs'                            = 'Azure Data Box'
    'Microsoft.Kusto/clusters'                          = 'Azure Data Explorer'
    'Microsoft.Network/bastionHosts'                    = 'Azure Cloud Shell'
}

# Heuristic fallback: pick a stencil if the resource type isn't in the table.
function Resolve-AzureStencil {
    param([string] $ResourceType)
    if ($AzureTypeToStencil.ContainsKey($ResourceType)) {
        return $AzureTypeToStencil[$ResourceType]
    }
    # crude prefix heuristics
    switch -Wildcard ($ResourceType) {
        'Microsoft.Sql/*'              { return 'Azure SQL Database Managed Instance' }
        'Microsoft.Storage/*'          { return 'Azure Storage' }
        'Microsoft.Network/*'          { return 'Virtual Network' }
        'Microsoft.Compute/*'          { return 'Windows Virtual Machines' }
        'Microsoft.Web/*'              { return 'App Service' }
        'Microsoft.DBfor*'             { return 'Azure Database for PostgreSQL' }
        'Microsoft.Insights/*'         { return 'Application Insights' }
        'Microsoft.Security*/*'        { return 'Security Center' }
        'Microsoft.OperationalInsights/*' { return 'Log Analytics' }
        'Microsoft.CognitiveServices/*'   { return 'Cognitive Services' }
        default                        { return 'Generic Process' }
    }
}
#endregion

#region ---------- helpers ----------

function Ensure-AzModule {
    if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
        throw "The 'Az' PowerShell module is not installed. Install with: Install-Module Az -Scope CurrentUser"
    }
    Import-Module Az.Accounts -ErrorAction Stop | Out-Null
    Import-Module Az.Resources -ErrorAction Stop | Out-Null
}

function Connect-AzureSubscription {
    param([string] $SubscriptionId)

    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    $needLogin = $true
    if ($ctx -and $ctx.Subscription) {
        if ($ctx.Subscription.Id -eq $SubscriptionId -or $ctx.Subscription.Name -eq $SubscriptionId) {
            $needLogin = $false
        }
    }
    if ($needLogin) {
        Write-Host "Signing in to Azure..." -ForegroundColor Cyan
        Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
    }
    Set-AzContext -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
    return (Get-AzContext)
}

function Get-TemplateFile {
    param([string] $Path, [string] $Url)
    if (-not (Test-Path $Path)) {
        Write-Host "Downloading template from $Url" -ForegroundColor Cyan
        $dir = Split-Path $Path -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
        Invoke-WebRequest -Uri $Url -OutFile $Path -UseBasicParsing | Out-Null
    }
    return $Path
}

function Read-TemplateStencils {
    param([string] $Path)
    [xml] $xml = Get-Content -Path $Path -Raw
    $kb = $xml.KnowledgeBase
    $manifest = $kb.Manifest

    $elementNodes = @()
    foreach ($section in 'GenericElements','StandardElements') {
        if ($kb.$section -and $kb.$section.ElementType) {
            $elementNodes += @($kb.$section.ElementType)
        }
    }

    $stencils = @{}
    foreach ($et in $elementNodes) {
        $name = $et.Name
        if (-not $name) { continue }
        $name = $name.Trim()
        if (-not $stencils.ContainsKey($name)) {
            $stencils[$name] = [pscustomobject]@{
                Name           = $name
                Id             = $et.ID
                Representation = $et.Representation
                ParentElement  = $et.ParentElement
            }
        }
    }

    return [pscustomobject]@{
        ManifestId   = $manifest.id
        ManifestName = $manifest.name
        Version      = $manifest.version
        Stencils     = $stencils
    }
}

function ConvertTo-XmlText {
    param([string] $Text)
    if ($null -eq $Text) { return '' }
    return ($Text -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' -replace "'",'&apos;')
}

function Get-StencilTypeAndGeneric {
    <#
        Returns a 2-element array @($iType, $genericTypeId).
        - $iType is the xsi:type used inside <a:Value>: StencilEllipse,
          StencilRectangle, StencilParallelLines, BorderBoundary, or LineBoundary.
        - $genericTypeId is the parent category id from .tb7 ParentElement.
          If the parent is "ROOT" (i.e. this stencil IS a root category like
          GE.P), GenericTypeId equals the stencil's own ID instead.
    #>
    param($Stencil)
    $rep = ''
    if ($Stencil.Representation) { $rep = $Stencil.Representation }
    $parent = $Stencil.ParentElement
    if (-not $parent -or $parent -eq 'ROOT') { $parent = $Stencil.Id }
    if (-not $parent) { $parent = 'GE.P' }

    switch -Wildcard ($rep) {
        'Ellipse'         { return @('StencilEllipse',        $parent) }
        'Rectangle'       { return @('StencilRectangle',      $parent) }
        'Parallel Lines'  { return @('StencilParallelLines',  $parent) }
        'ParallelLines'   { return @('StencilParallelLines',  $parent) }
        'Border*'         { return @('BorderBoundary',        $parent) }
        'Line*'           { return @('LineBoundary',          $parent) }
        default           { return @('StencilEllipse',        $parent) }
    }
}

function New-BorderXml {
    <#
        Emits one <a:KeyValueOfguidanyType> element matching the shape used by
        the Microsoft Threat Modeling Tool's DataContractSerializer output.
        Element ordering inside <a:Value> is significant.
    #>
    param(
        [string] $ResourceName,
        [string] $StencilName,
        [string] $TypeId,
        [string] $GenericTypeId,
        [string] $IType,
        [int] $ZId,
        [int] $Left,
        [int] $Top,
        [int] $Width = 100,
        [int] $Height = 100
    )
    $guid = [Guid]::NewGuid().ToString()
    $name = ConvertTo-XmlText $ResourceName
    $stencilDisplay = ConvertTo-XmlText $StencilName

    $absNs = 'http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts'
    $kbNs  = 'http://schemas.datacontract.org/2004/07/ThreatModeling.KnowledgeBase'
    $xsNs  = 'http://www.w3.org/2001/XMLSchema'

    return @"
<a:KeyValueOfguidanyType><a:Key>$guid</a:Key><a:Value z:Id="i$ZId" i:type="$IType"><GenericTypeId xmlns="$absNs">$GenericTypeId</GenericTypeId><Guid xmlns="$absNs">$guid</Guid><Properties xmlns="$absNs"><a:anyType i:type="b:HeaderDisplayAttribute" xmlns:b="$kbNs"><b:DisplayName>$stencilDisplay</b:DisplayName><b:Name/><b:Value i:nil="true"/></a:anyType><a:anyType i:type="b:StringDisplayAttribute" xmlns:b="$kbNs"><b:DisplayName>Name</b:DisplayName><b:Name/><b:Value i:type="c:string" xmlns:c="$xsNs">$name</b:Value></a:anyType><a:anyType i:type="b:BooleanDisplayAttribute" xmlns:b="$kbNs"><b:DisplayName>Out Of Scope</b:DisplayName><b:Name>71f3d9aa-b8ef-4e54-8126-607a1d903103</b:Name><b:Value i:type="c:boolean" xmlns:c="$xsNs">false</b:Value></a:anyType><a:anyType i:type="b:StringDisplayAttribute" xmlns:b="$kbNs"><b:DisplayName>Reason For Out Of Scope</b:DisplayName><b:Name>752473b6-52d4-4776-9a24-202153f7d579</b:Name><b:Value i:type="c:string" xmlns:c="$xsNs"/></a:anyType></Properties><TypeId xmlns="$absNs">$TypeId</TypeId><Height xmlns="$absNs">$Height</Height><Left xmlns="$absNs">$Left</Left><StrokeDashArray i:nil="true" xmlns="$absNs"/><StrokeThickness xmlns="$absNs">1</StrokeThickness><Top xmlns="$absNs">$Top</Top><Width xmlns="$absNs">$Width</Width></a:Value></a:KeyValueOfguidanyType>
"@
}

function Get-BaselineKnownIds {
    # Collects every <a:Id> value from the baseline's embedded KnowledgeBase so
    # we can avoid emitting borders that reference stencils the baseline KB
    # doesn't know about (those would null-ref TMT's deserializer on open).
    param([string] $Text)
    $ids = New-Object System.Collections.Generic.HashSet[string]
    $matches = [regex]::Matches($Text, '<a:Id>([^<]+)</a:Id>')
    foreach ($m in $matches) { [void]$ids.Add($m.Groups[1].Value) }
    return $ids
}

function New-DrawingSurfaceXml {
    <#
        Builds one <DrawingSurfaceModel> for a single resource group.
        Returns @{ Xml = <string>; NextZId = <int>; Fallbacks = <int> } so the
        caller can chain z:Id values across multiple surfaces (z:Id must be
        unique across the whole document, not just within a surface).
    #>
    param(
        [string] $RgName,
        [array]  $Resources,
        [hashtable] $Stencils,
        [System.Collections.Generic.HashSet[string]] $KnownIds,
        [int] $StartZId
    )

    $absNs = 'http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts'
    $kbNs  = 'http://schemas.datacontract.org/2004/07/ThreatModeling.KnowledgeBase'
    $arrNs = 'http://schemas.microsoft.com/2003/10/Serialization/Arrays'
    $xsNs  = 'http://www.w3.org/2001/XMLSchema'
    $zNs   = 'http://schemas.microsoft.com/2003/10/Serialization/'

    $surfaceZId = $StartZId
    $zId = $StartZId + 1
    $surfaceGuid = [Guid]::NewGuid().ToString()
    $rgSafe = ConvertTo-XmlText $RgName

    $cols  = [Math]::Max(1, [int][Math]::Ceiling([Math]::Sqrt([Math]::Max(1,$Resources.Count))))
    $cellW = 200; $cellH = 160
    $padX  = 120; $padY  = 120
    $borders = New-Object System.Text.StringBuilder
    $i = 0
    $fallbacks = 0
    foreach ($r in $Resources) {
        $col = $i % $cols
        $row = [Math]::Floor($i / $cols)
        $left = $padX + ($col * $cellW)
        $top  = $padY + ($row * $cellH)

        $stencil = $null
        if ($Stencils.ContainsKey($r.StencilName)) { $stencil = $Stencils[$r.StencilName] }
        if (-not $stencil -or -not $KnownIds.Contains($stencil.Id)) {
            $stencil = $Stencils['Generic Process']
            $fallbacks++
        }
        $pair = Get-StencilTypeAndGeneric $stencil

        [void]$borders.Append((New-BorderXml `
            -ResourceName  $r.Name `
            -StencilName   $stencil.Name `
            -TypeId        $stencil.Id `
            -GenericTypeId $pair[1] `
            -IType         $pair[0] `
            -ZId           $zId `
            -Left          $left `
            -Top           $top))
        $zId++
        $i++
    }

    $surfaceXml = @"
<DrawingSurfaceModel z:Id="i$surfaceZId" xmlns:z="$zNs"><GenericTypeId xmlns="$absNs">DRAWINGSURFACE</GenericTypeId><Guid xmlns="$absNs">$surfaceGuid</Guid><Properties xmlns="$absNs" xmlns:a="$arrNs"><a:anyType i:type="b:HeaderDisplayAttribute" xmlns:b="$kbNs"><b:DisplayName>Diagram</b:DisplayName><b:Name/><b:Value i:nil="true"/></a:anyType><a:anyType i:type="b:StringDisplayAttribute" xmlns:b="$kbNs"><b:DisplayName>Name</b:DisplayName><b:Name/><b:Value i:type="c:string" xmlns:c="$xsNs">$rgSafe</b:Value></a:anyType></Properties><TypeId xmlns="$absNs">DRAWINGSURFACE</TypeId><Borders xmlns:a="$arrNs">$($borders.ToString())</Borders><Header>$rgSafe</Header><Lines xmlns:a="$arrNs"/><Zoom>1</Zoom></DrawingSurfaceModel>
"@

    return @{ Xml = $surfaceXml; NextZId = $zId; Fallbacks = $fallbacks }
}

function New-Tm7FromBaseline {
    <#
        Reuses an existing TMT-saved .tm7 (the baseline) as the structural
        carrier. Only the diagram is replaced; the embedded KnowledgeBase and
        Profile are preserved verbatim, which is what makes the output loadable.
        Emits one <DrawingSurfaceModel> per resource group.
    #>
    param(
        [string] $BaselinePath,
        [hashtable] $Stencils,
        [array] $Resources,
        [string] $SubscriptionDisplay
    )

    if (-not (Test-Path $BaselinePath)) {
        throw "Baseline .tm7 not found: $BaselinePath. Open the Microsoft Threat Modeling Tool, File -> Create A Model, select your .tb7, save it as an empty model, then re-run with -BaselineTm7 pointing at that file."
    }

    $text = Get-Content -Path $BaselinePath -Raw
    $knownIds = Get-BaselineKnownIds -Text $text
    Write-Host "  Baseline KB knows $($knownIds.Count) stencil IDs" -ForegroundColor Gray

    # Group resources by RG name (anything missing one goes to "(no resource group)").
    $groups = $Resources | Group-Object {
        if ($_.ResourceGroupName) { $_.ResourceGroupName } else { '(no resource group)' }
    } | Sort-Object Name
    Write-Host "  Resource groups: $($groups.Count)" -ForegroundColor Gray

    $surfaces = New-Object System.Text.StringBuilder
    $zId = 1
    $totalFallbacks = 0
    foreach ($g in $groups) {
        $result = New-DrawingSurfaceXml `
            -RgName    $g.Name `
            -Resources @($g.Group) `
            -Stencils  $Stencils `
            -KnownIds  $knownIds `
            -StartZId  $zId
        [void]$surfaces.Append($result.Xml)
        $zId = $result.NextZId
        $totalFallbacks += $result.Fallbacks
        Write-Host ("    [{0,-40}] {1,3} resource(s){2}" -f $g.Name, $g.Count, $(if ($result.Fallbacks){' ('+$result.Fallbacks+' fallback)'}else{''})) -ForegroundColor DarkGray
    }
    if ($totalFallbacks -gt 0) {
        Write-Host "  $totalFallbacks total fell back to 'Generic Process' (stencil not in baseline KB)" -ForegroundColor Yellow
    }
    $newSurfaceList = "<DrawingSurfaceList>$($surfaces.ToString())</DrawingSurfaceList>"

    # Replace diagram + threat data; keep KnowledgeBase + Profile + Version.
    # Use MatchEvaluator to avoid $-substitution surprises in the replacement text.
    $text = [regex]::Replace($text, '(?s)<DrawingSurfaceList>.*?</DrawingSurfaceList>',  { param($m) $newSurfaceList })
    $text = [regex]::Replace($text, '(?s)<ThreatInstances[^>]*>.*?</ThreatInstances>',   { param($m) '<ThreatInstances xmlns:a="http://schemas.microsoft.com/2003/10/Serialization/Arrays"/>' })

    $subSafe = ConvertTo-XmlText $SubscriptionDisplay
    $now     = (Get-Date).ToString('u')
    $metaNew = @"
<MetaInformation><Assumptions>Auto-generated $now from Azure subscription enumeration.</Assumptions><Contributors/><ExternalDependencies/><HighLevelSystemDescription>Generated diagram of resources discovered in subscription $subSafe. One diagram per resource group. Refine layout, add data flows, and complete the threat review in the Microsoft Threat Modeling Tool.</HighLevelSystemDescription><Owner/><Reviewer/><ThreatModelName>Azure - $subSafe</ThreatModelName></MetaInformation>
"@
    $text = [regex]::Replace($text, '(?s)<MetaInformation>.*?</MetaInformation>', { param($m) $metaNew.Trim() })

    return $text
}

function New-MarkdownReport {
    param([array] $Resources, [string] $SubscriptionDisplay, [int] $UnmappedCount)

    $strideByCategory = @{
        'data'         = 'Tampering, Information Disclosure, Denial of Service'
        'compute'      = 'Spoofing, Tampering, Elevation of Privilege, Denial of Service'
        'network'      = 'Spoofing, Information Disclosure, Denial of Service'
        'identity'     = 'Spoofing, Repudiation, Elevation of Privilege'
        'integration'  = 'Tampering, Information Disclosure, Repudiation'
        'observability'= 'Tampering, Repudiation, Information Disclosure'
        'security'     = 'Tampering, Elevation of Privilege'
        'generic'      = 'STRIDE - review manually'
    }

    function Get-Category([string] $stencil) {
        switch -Wildcard ($stencil) {
            'Azure Storage'                             { return 'data' }
            'Azure SQL*'                                { return 'data' }
            'Azure Database*'                           { return 'data' }
            'CosmosDB'                                  { return 'data' }
            'Data Lake*'                                { return 'data' }
            'Azure Synapse*'                            { return 'data' }
            'Azure Redis Cache'                         { return 'data' }
            'Azure Search'                              { return 'data' }
            '*Virtual Machine*'                         { return 'compute' }
            'App Service'                               { return 'compute' }
            'Web Application'                           { return 'compute' }
            'Functions'                                 { return 'compute' }
            'Azure Kubernetes Service'                  { return 'compute' }
            'Container Registry'                        { return 'compute' }
            'Batch'                                     { return 'compute' }
            'Service Fabric'                            { return 'compute' }
            'Virtual Network'                           { return 'network' }
            'Application Gateway'                       { return 'network' }
            'Load Balancer'                             { return 'network' }
            'Azure Firewall'                            { return 'network' }
            'VPN Gateway'                               { return 'network' }
            'Traffic Manager'                           { return 'network' }
            'CDN'                                       { return 'network' }
            'DNS'                                       { return 'network' }
            'Network Security Group'                    { return 'network' }
            'API Management'                            { return 'network' }
            'Azure Virtual WAN'                         { return 'network' }
            'Key Vault'                                 { return 'identity' }
            'Active Directory*'                         { return 'identity' }
            'Microsoft Entra*'                          { return 'identity' }
            'ADFS'                                      { return 'identity' }
            'Multi Factor Authentication'               { return 'identity' }
            'Service Bus'                               { return 'integration' }
            'Azure Event Hub'                           { return 'integration' }
            'Event Grid'                                { return 'integration' }
            'LogicApp'                                  { return 'integration' }
            'Notification Hub'                          { return 'integration' }
            'Application Insights'                      { return 'observability' }
            'Log Analytics'                             { return 'observability' }
            'Monitor'                                   { return 'observability' }
            'Azure Alerts'                              { return 'observability' }
            'Network Watcher'                           { return 'observability' }
            'Security Center'                           { return 'security' }
            'Microsoft Sentinal'                        { return 'security' }
            'Advanced Threat Protection'                { return 'security' }
            'Microsoft Purview'                         { return 'security' }
            default                                     { return 'generic' }
        }
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("# Azure Threat Model: $SubscriptionDisplay")
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("Generated: $((Get-Date).ToString('u'))")
    [void]$sb.AppendLine("Resources scanned: $($Resources.Count) (unmapped: $UnmappedCount)")
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("## STRIDE prompts by resource")
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("| Resource | Resource Group | Type | Stencil | STRIDE focus |")
    [void]$sb.AppendLine("|---|---|---|---|---|")
    foreach ($r in $Resources | Sort-Object ResourceGroupName, Name) {
        $cat = Get-Category $r.StencilName
        $stride = $strideByCategory[$cat]
        [void]$sb.AppendLine("| $($r.Name) | $($r.ResourceGroupName) | $($r.ResourceType) | $($r.StencilName) | $stride |")
    }

    if ($UnmappedCount -gt 0) {
        [void]$sb.AppendLine()
        [void]$sb.AppendLine("## Unmapped resource types")
        [void]$sb.AppendLine()
        [void]$sb.AppendLine("These were placed as ``Generic Process``. Add explicit entries to ``\$AzureTypeToStencil`` in the script if you want better stencils:")
        [void]$sb.AppendLine()
        $Resources | Where-Object { $_.StencilName -eq 'Generic Process' } |
            Group-Object ResourceType |
            Sort-Object Count -Descending |
            ForEach-Object { [void]$sb.AppendLine("- ``$($_.Name)``  ($($_.Count))") }
    }
    return $sb.ToString()
}
#endregion

#region ---------- main ----------

Ensure-AzModule

$ctx = Connect-AzureSubscription -SubscriptionId $SubscriptionId
Write-Host "Using subscription: $($ctx.Subscription.Name) ($($ctx.Subscription.Id))" -ForegroundColor Green

$tbPath = Get-TemplateFile -Path $TemplatePath -Url $TemplateUrl
Write-Host "Loading template: $tbPath" -ForegroundColor Cyan
$template = Read-TemplateStencils -Path $tbPath
Write-Host "  Manifest: $($template.ManifestName) ($($template.ManifestId)) v$($template.Version)" -ForegroundColor Gray
Write-Host "  Stencils available: $($template.Stencils.Count)" -ForegroundColor Gray

Write-Host "Enumerating Azure resources..." -ForegroundColor Cyan
if ($ResourceGroupName) {
    $azResources = Get-AzResource -ResourceGroupName $ResourceGroupName
} else {
    $azResources = Get-AzResource
}
Write-Host "  Found $($azResources.Count) resource(s)." -ForegroundColor Gray

# Build unified resource list with mapped stencils
$mapped = foreach ($r in $azResources) {
    $stencilName = Resolve-AzureStencil -ResourceType $r.ResourceType
    $stencilId   = $null
    if ($template.Stencils.ContainsKey($stencilName)) {
        $stencilId = $template.Stencils[$stencilName].Id
    }
    [pscustomobject]@{
        Name              = $r.Name
        ResourceGroupName = $r.ResourceGroupName
        ResourceType      = $r.ResourceType
        Location          = $r.Location
        ResourceId        = $r.ResourceId
        StencilName       = $stencilName
        StencilId         = $stencilId
    }
}

$unmappedCount = ($mapped | Where-Object { $_.StencilName -eq 'Generic Process' }).Count

if (-not (Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
}
$stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$safeSub = ($ctx.Subscription.Name -replace '[^A-Za-z0-9_-]', '_')
$base = Join-Path $OutputDirectory "$safeSub-$stamp"

$csvPath = "$base.csv"
$mdPath  = "$base.md"
$tm7Path = "$base.tm7"

$mapped | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "Wrote inventory: $csvPath" -ForegroundColor Green

$markdown = New-MarkdownReport -Resources $mapped -SubscriptionDisplay $ctx.Subscription.Name -UnmappedCount $unmappedCount
Set-Content -Path $mdPath -Value $markdown -Encoding UTF8
Write-Host "Wrote report:    $mdPath" -ForegroundColor Green

if (Test-Path $BaselineTm7) {
    Write-Host "Building .tm7 from baseline: $BaselineTm7" -ForegroundColor Cyan
    $tm7 = New-Tm7FromBaseline -BaselinePath $BaselineTm7 -Stencils $template.Stencils -Resources $mapped -SubscriptionDisplay $ctx.Subscription.Name
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($tm7Path, $tm7, $utf8NoBom)
    Write-Host "Wrote model:     $tm7Path" -ForegroundColor Green
    Write-Host ""
    Write-Host "Open $tm7Path with the Microsoft Threat Modeling Tool." -ForegroundColor Yellow
} else {
    Write-Host ""
    Write-Host "Skipping .tm7 generation - baseline not found: $BaselineTm7" -ForegroundColor Yellow
    Write-Host "To enable .tm7 generation:" -ForegroundColor Yellow
    Write-Host "  1. Open Microsoft Threat Modeling Tool" -ForegroundColor Yellow
    Write-Host "  2. File -> Create A Model -> Browse -> $tbPath" -ForegroundColor Yellow
    Write-Host "  3. Save the empty model as a baseline .tm7" -ForegroundColor Yellow
    Write-Host "  4. Re-run this script with -BaselineTm7 <path>" -ForegroundColor Yellow
}

#endregion
