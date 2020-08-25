Connect-AzAccount 

$SubscriptionId = Get-AzSubscription | Out-GridView -PassThru
$SubscriptionName = $SubscriptionId.Name
Select-AzSubscription -SubscriptionId ($SubscriptionId).Id

$filename = $subscriptionId.Name + "_VMs.csv"

$azurevms = @()
foreach ($vm in (Get-AzVM))
{
    $NIC = Get-AzNetworkInterface -ResourceId $VM.NetworkProfile.NetworkInterfaces.id
    $Disk = Get-AzDisk -DiskName (Get-AzResource -ResourceId $VM.StorageProfile.OsDisk.ManagedDisk.Id).Name
    $azurevms += [pscustomobject]@{
        Name = $VM.Name
        ResourceGroup = $VM.ResourceGroupName
        Size = $VM.HardwareProfile.VmSize
        ASNAME = if ($VM.AvailabilitySetReference.id -eq $null) {"no AvSet"} ELSE {(Get-AzResource -ResourceId $VM.AvailabilitySetReference.id).Name}
        Status = (get-azvm -ResourceGroupName $VM.ResourceGroupName -Name $VM.name -status).Statuses.code[1]  
        ImageReference = $VM.StorageProfile.ImageReference.Offer
        License = $VM.LicenseType
        TAGs = ([string]($vm.Tags.GetEnumerator() | ForEach-Object { "$($_.Key):$($_.Value)," }))
        OSDiskType = $VM.StorageProfile.OsDisk.OsType
        OSDiskManaged = $Disk.Name
        OSDiskManagedSize = $Disk.DiskSizeGB
        OSDiskManagedIOPS = $Disk.DiskIOPSReadWrite
        OSDiskManagedMB = $Disk.DiskMBpsReadWrite
        OSDiskUnManaged = $VM.StorageProfile.OsDisk.Vhd
        DataDisk = $VM.StorageProfile.DataDisks.name -join ";"
        VMAgentStatus = IF ($VM.StorageProfile.OsDisk.OsType -eq "Windows"){$VM.OSProfile.WindowsConfiguration.ProvisionVMAgent} ELSE {$VM.OSProfile.LinuxConfiguration.ProvisionVMAgent}
        DiagEnabled = $VM.DiagnosticsProfile.BootDiagnostics.Enabled
        DiagConfig = $VM.DiagnosticsProfile.BootDiagnostics.StorageUri
        Nic = $NIC.Primary
        NicIP = $NIC.IpConfigurations.PrivateIpAddress -join ";"
        NicIPPUB = if ($NIC.IpConfigurations.PublicIpAddress.Id -eq $null) {"no PIP"} ELSE {(Get-AzResource -ResourceId $NIC.IpConfigurations.PublicIpAddress.Id).Name}
        NicAccNet = $NIC.EnableAcceleratedNetworking
        NicIPFor = $NIC.EnableIPForwarding
        NicNSG = if ($NIC.NetworkSecurityGroup.id -eq $null) {"no nsg"} ELSE {(Get-AzResource -ResourceId $NIC.NetworkSecurityGroup.id).Name}
        NicAppSecG = if ($NIC.IpConfigurations[0].ApplicationSecurityGroups.id -eq $null){"no appsecgroup"} ELSE {($appsec = foreach ($1 in $NIC.IpConfigurations[0].ApplicationSecurityGroups.id){(Get-AzResource -ResourceId $1).name}) -join ";" }
        NicLBBEPool = $NIC.IpConfigurations.LoadBalancerBackendAddressPools.id -join ";"
        NicAppgtwBEPool = $NIC.IpConfigurations.ApplicationGatewayBackendAddressPools -join ";"
    }
}

$azurevms | Export-Csv ".\$filename" -NoTypeInformation -Encoding UTF8

#-----------------------------------------------------------------------------------------
$SubscriptionId = Get-AzSubscription | Out-GridView -PassThru
$SubscriptionName = $SubscriptionId.Name
Select-AzSubscription -SubscriptionId ($SubscriptionId).Id


$azurevms = @()
foreach ($vm in (Get-AzVM))
{
    $azurevms += [pscustomobject]@{
        Name = $VM.Name
        ResourceGroup = $VM.ResourceGroupName
        Size = $VM.HardwareProfile.VmSize
        ASNAME = if ($VM.AvailabilitySetReference.id -eq $null) {"no AvSet"} ELSE {(Get-AzResource -ResourceId $VM.AvailabilitySetReference.id).Name}
        Status = (get-azvm -ResourceGroupName $VM.ResourceGroupName -Name $VM.name -status).Statuses.code[1]  
        ImageReference = $VM.StorageProfile.ImageReference.Offer
        License = $VM.LicenseType
        TAGs = ([string]($vm.Tags.GetEnumerator() | ForEach-Object { "$($_.Key):$($_.Value)," }))
        OSDiskType = $VM.StorageProfile.OsDisk.OsType
        OSDiskUnManaged = $VM.StorageProfile.OsDisk.Vhd
        DataDisk = $VM.StorageProfile.DataDisks.name -join ";"
        VMAgentStatus = IF ($VM.StorageProfile.OsDisk.OsType -eq "Windows"){$VM.OSProfile.WindowsConfiguration.ProvisionVMAgent} ELSE {$VM.OSProfile.LinuxConfiguration.ProvisionVMAgent}
        DiagEnabled = $VM.DiagnosticsProfile.BootDiagnostics.Enabled
        DiagConfig = $VM.DiagnosticsProfile.BootDiagnostics.StorageUri
    }
}

$azurevms | Export-Csv ".\$($SubscriptionName)-vms.Csv" -NoTypeInformation
#------------------------------------------------------------------------------------------------------------------------------


$azurevnets =@()
$azurevnets = foreach ($VNET in (Get-AzVirtualNetwork))
{
    [pscustomobject]@{
     VNETNAME=$VNET.Name
     ResourceGroupName=$VNET.ResourceGroupName
     Location=$VNET.Location
     AddressSpace=$VNET.AddressSpace.AddressPrefixes -join ";"
     Subnets=$VNET.Subnets.name -join ";"
     Peering=$VNET.VirtualNetworkPeerings.Name -join ";"
     DNSServer=$VNET.DhcpOptions.DnsServers -join ";"
     DDOS=$VNET.EnableDdosProtection
     DDOSPlan=$VNET.DdosProtectionPlan
    } 
}

$azurevnets | Select VNETNAME, ResourceGroupName, Location,AddressSpace,Subnets,Peering `
,DNSServer, DDOS, DDOSPlan | Export-Csv C:\temp\Rodobens\vnet.Csv -NoTypeInformation

$GTW = (Get-AzVirtualNetworkGateway -ResourceGroupName RG_NetworkPRD01)[0]

$listagtw = @()
foreach ($RG in (Get-AzResourceGroup).ResourceGroupName){
    
    foreach ($GTW in (Get-AzVirtualNetworkGateway -ResourceGroupName $RG))
    {
        $IP = (Get-AzResource -ResourceId $GTW.IpConfigurations.PublicIpAddress.Id)

        $listagtw += [pscustomobject]@{
            Name = $GTW.NAme
            ResourceGroup = $GTW.ResourceGroupName
            Location = $GTW.Location
            VNET = $GTW.IpConfigurations.Subnet.id.Split('/')[8]+":"+$GTW.IpConfigurations.Subnet.id.Split('/')[10]
            PublicIP = $IP.Properties.ipAddress
            Gtype = $GTW.GatewayType
            VPNType = $GTW.VpnType
            BGP = $GTW.EnableBgp
            AcxAc = $GTW.ActiveActive
            Sku = $GTW.Sku.Tier
            BGPSetting = if ($GTW.BgpSettings.ASN -eq $null) {"no BGP"} ELSE {$GTW.BgpSettings.ASN.ToString()+":"+$GTW.BgpSettings.BgpPeeringAddress.ToString()+":"+$GTW.BgpSettings.PeerWeight.ToString()}
        }
    } 
}
$listagtw | Export-Csv C:\temp\Rodobens\gtw.Csv -NoTypeInformation

foreach ($RG in (Get-AzResourceGroup).ResourceGroupName)
    {
        Get-AzVirtualNetworkGatewayConnection -ResourceGroupName $RG
    }




Get-azPublicIpAddress |?{$_.IpConfiguration -eq $null} | select Name, ResourceGRoup, PublicIpAllocationMethod, IpAddress
Get-azNetworkInterface|?{$_.VirtualMachine  -eq $null} | select NAme, VirtualMachine 

$OrphanDisk=@()
$OrphanDisk = foreach ($ODISK in (Get-azDisk |?{$_.ManagedBy -eq $null}))
{
    [pscustomobject]@{
     Name = $ODISK.Name
     ResourceGroup = $ODISK.ResourceGroupName
     SKUName = $ODISK.sku.name
     SKUTier  = $ODISK.sku.tier
     Size = $ODISK.DiskSizeGB
     State = $ODISK.DiskState
    } 
}
$OrphanDisk | Select Name, ResourceGroup, SKUName, SKUTier,Size,State `
| Export-Csv c:\temp\OrphanDisk.Csv -NoTypeInformation

$AzStorage = @() 
$AzStorage += foreach ($Stor in (Get-AzStorageAccount))
{
    [pscustomobject]@{
    StorageAccountName = $Stor.StorageAccountName
    ResourceGroupName  = $Stor.ResourceGroupName
    Location           = $Stor.Location         
    Tier               = $Stor.Sku.Tier
    SkuName            = $Stor.Sku.Name
    Kind               = $Stor.Kind
    EncrypServicesBlob = $Stor.Encryption.Services.Blob.Enabled -join ";"      
    EncrypServicesFile = $Stor.Encryption.Services.File.Enabled
    AccessTier         = $Stor.AccessTier
    CustomDomain       = $Stor.CustomDomain -join ";"    
    Identity           = $Stor.Identity         
    PrimaryEndpoints   = $Stor.PrimaryEndpoints.Blob
    StatusOfPrimary    = $Stor.StatusOfPrimary
    SecondaryEndpoints = $Stor.SecondaryEndpoints.Blob
    StatusOfSecondary  = $Stor.StatusOfSecondary
    HttpsTrafficOnly   = $Stor.EnableHttpsTrafficOnly      
    NetkRuleDefAction  = $Stor.NetworkRuleSet.DefaultAction -join ";"
    NetkRuleNetRuleact = $Stor.NetworkRuleSet.VirtualNetworkRules.action -join ";"
    NetkRuleNetID      = $Stor.NetworkRuleSet.VirtualNetworkRules.VirtualNetworkResourceId -join ";"
    }
}

$AzStorage | Select StorageAccountName,ResourceGroupName,Location,Tier,SkuName,Kind,EncrypServicesBlob, EncrypServicesFile,AccessTier,CustomDomain,Identity `
,PrimaryEndpoints,StatusOfPrimary,SecondaryEndpoints,StatusOfSecondary,HttpsTrafficOnly,NetkRuleDefAction,NetkRuleNetRuleact,NetkRuleNetID  `
| Export-Csv c:\temp\storage_brmalls.Csv -NoTypeInformation

#######################

# Azure Login
Login-AzAccount
$SubscriptionId = Get-AzSubscription | Out-GridView -PassThru
$SubscriptionName = $SubscriptionId.Name
Select-AzSubscription -SubscriptionId ($SubscriptionId).Id

##Subscription
function Get-AzureRmInvTenantInfo() {
$tenantinfo = Select-AzSubscription ($SubscriptionId).Id 
      foreach ($ten in $tenantinfo) {
       
        $obj = New-Object -TypeName PSCustomObject
        $obj | Add-Member -MemberType NoteProperty -Name Name -Value $ten.Name -Force
        $obj | Add-Member -MemberType NoteProperty -Name Environment -Value $ten.Environment -Force
        $obj | Add-Member -MemberType NoteProperty -Name TenantId -Value $ten.Tenant -Force
        $obj | Add-Member -MemberType NoteProperty -Name SubscriptionName -Value ($SubscriptionId).Name
     
        $obj
    }

}
#Locks
function Get-AzureRmInvResourceLocks() {

$resourcelocks = Get-AzResourceLock
       foreach ($locks in $resourcelocks) {
        $lockid = $locks.LockId -split("/")
        $obj = New-Object -TypeName PSCustomObject
        $obj | Add-Member -MemberType NoteProperty -Name Name -Value $locks.Name -Force
        $obj | Add-Member -MemberType NoteProperty -Name ResourceGroupName -Value $locks.ResourceGroupName -Force
        $obj | Add-Member -MemberType NoteProperty -Name resourceType -Value $locks.resourceType -Force
        $obj | Add-Member -MemberType NoteProperty -Name Properties -Value $($locks.Properties) -Force
        $obj | Add-Member -MemberType NoteProperty -Name LockID -Value $lockid[8]  -Force
        $obj | Add-Member -MemberType NoteProperty -Name SubscriptionName -Value ($SubscriptionId).Name
     
        $obj

        }
    }
##ARM VM:
function Get-AzureRmInvVMs() {
    Get-AzVM -Status | Select `
        Name,
        ResourceGroupName,
        Location,
        @{Name="VmSize";Expression={$_.HardwareProfile.VmSize}},
        PowerState,
        @{Name="AvailabilitySet";Expression={$_.AvailabilitySetReference.Id.Substring($_.AvailabilitySetReference.Id.LastIndexOf('/')+1)}}, `
        @{Name="OsType";Expression={$_.StorageProfile.OsDisk.OsType}}, `
        @{Name="LicenseType (AHB)";Expression={$_.LicenseType}}, `
        @{Name="ImageReference.Publisher";Expression={$_.StorageProfile.ImageReference.Publisher}}, `
        @{Name="ImageReference.Offer";Expression={$_.StorageProfile.ImageReference.Offer}}, `
        @{Name="ImageReference.Sku";Expression={$_.StorageProfile.ImageReference.Sku}}, `
        @{Name="ImageReference.Version";Expression={$_.StorageProfile.ImageReference.Version}}, `
        @{Name="Plan.Publisher";Expression={$_.Plan.Publisher}}, `
        @{Name="Plan.Product (Offer)";Expression={$_.Plan.Product}}, `
        @{Name="Plan.Name (SKU)";Expression={$_.Plan.Name}},
        @{Name="Tags";Expression={$_.Plan.Tag}}
           
}
##ARM Vhds:
function Get-AzureRmInvUnManagedDisk() {
    Get-AzStorageAccount | ForEach-Object {
        $saName = $_.StorageAccountName
        $saRgName = $_.ResourceGroupName
        $saSkuName = $_.Sku.Name
        $saSkuTier = $_.Sku.Tier
        $saKind = $_.Kind
        $saContext = $_.Context
        Get-AzStorageContainer -Context $saContext | ForEach-Object {
            $token = $null
            do {
                $blobs = Get-AzStorageBlob -Container $_.Name -Context $saContext -ContinuationToken $token -MaxCount 1000 | `
                    where {$_.Name.ToLower().EndsWith(".vhd")} | select `
                @{Name = "StorageAccount.Name"; Expression = {$saName}},
                @{Name = "StorageAccount.RgName"; Expression = {$saRgName}},
                @{Name = "StorageAccount.SkuTier"; Expression = {$saSkuTier}},
                @{Name = "StorageAccount.Kind"; Expression = {$saKind}},
                @{Name = "Blob.Name"; Expression = {$_.Name}}, `
                @{Name = "Blob.BlobType"; Expression = {$_.BlobType}}, `
                @{Name = "Blob.Length (GB)"; Expression = {[math]::round($_.Length / 1GB)}}, `
                @{Name = "Blob.LeaseStatus"; Expression = {$_.ICloudBlob.Properties.LeaseStatus}}, `
                @{Name = "Blob.Metadata.RgName"; Expression = {$_.ICloudBlob.Metadata["MicrosoftAzureCompute_ResourceGroupName"]}}, `
                @{Name = "Blob.Metadata.VMName"; Expression = {$_.ICloudBlob.Metadata["MicrosoftAzureCompute_VMName"]}}, `
                @{Name = "Blob.Metadata.DiskId"; Expression = {$_.ICloudBlob.Metadata["MicrosoftAzureCompute_DiskId"]}}, `
                @{Name = "Blob.Metadata.DiskName"; Expression = {$_.ICloudBlob.Metadata["MicrosoftAzureCompute_DiskName"]}}, `
                @{Name = "Blob.Metadata.DiskType"; Expression = {$_.ICloudBlob.Metadata["MicrosoftAzureCompute_DiskType"]}}, `
                @{Name = "Blob.Metadata.DiskSizeInGB"; Expression = {$_.ICloudBlob.Metadata["MicrosoftAzureCompute_DiskSizeInGB"]}}, `
                @{Name = "Blob.AbsoluteUri"; Expression = {$_.ICloudBlob.StorageUri.PrimaryUri.AbsoluteUri}}
                $blobs
                try {
                    $token = $blobs[$blobs.Count - 1].ContinuationToken
                }
                catch {}
            } while ($token -ne $null)
        }
    }
       
}
#ARM ManagedDisk
function Get-AzureRmInvManagedDisk() {
    
 $manageddisk = Get-AzDisk 
    foreach ($md in $manageddisk) {
        $Managedby =  $md.ManagedBy  -split("/")
        $obj = New-Object -TypeName PSCustomObject
        $obj | Add-Member -MemberType NoteProperty -Name DiskName -Value $md.Name -Force
        $obj | Add-Member -MemberType NoteProperty -Name DiskName -Value $md.Name -Force
        $obj | Add-Member -MemberType NoteProperty -Name Sku -Value $md.Sku.Name -Force
        $obj | Add-Member -MemberType NoteProperty -Name Location -Value $md.Location -Force
        $obj | Add-Member -MemberType NoteProperty -Name OsType  -Value $md.OsType -Force
        $obj | Add-Member -MemberType NoteProperty -Name DiskSizeGB -Value $md.Location -Force
        $obj | Add-Member -MemberType NoteProperty -Name ManagedBy  -Value $Managedby[8] -Force
        $obj | Add-Member -MemberType NoteProperty -Name SubscriptionName -Value ($SubscriptionId).Name
     
        $obj
    }
}
# RBAC
function Get-AzureRmInvRBAC () {
     $subid = (Get-AzContext).subscription.id
     $RBAC = Get-AzRoleAssignment -scope "/subscriptions/$subid"    
    foreach ($perm in $RBAC) {
       
        $obj = New-Object -TypeName PSCustomObject
        $obj | Add-Member -MemberType NoteProperty -Name DisplayName -Value $perm.DisplayName -Force
        $obj | Add-Member -MemberType NoteProperty -Name SignInName -Value $perm.SignInName -Force
        $obj | Add-Member -MemberType NoteProperty -Name Scope -Value $perm.Scope -Force
        $obj | Add-Member -MemberType NoteProperty -Name Actions -Value $(Get-AzRoleDefinition -Name perm.roledefinitionname).actions -Force
        $obj | Add-Member -MemberType NoteProperty -Name ObjectType -Value $perm.ObjectType
        $obj | Add-Member -MemberType NoteProperty -Name RoleDefinition -Value $perm.roledefinitionname
        $obj | Add-Member -MemberType NoteProperty -Name SubscriptionName -Value ($SubscriptionId).Name
     
        $obj
    }
}

$RBAC = @()
$ACL = @()
foreach ($RG in (Get-AzResourceGroup).ResourceGroupName){

    $scope = "/subscriptions/$subid/resourceGroups/$rg"
    foreach ($ACL in (Get-AzRoleAssignment | ?{$_.scope -eq $scope}))
        {
           $RBAC += [pscustomobject]@{
                Name = $ACL.DisplayName
                Signin = $ACL.SignInName
                ResourceGroup = $ACL.Scope.Substring($ACL.Scope.LastIndexOf("/")+1) 
                Role = $ACL.RoleDefinitionName
                Roleid = $ACL.RoleDefinitionID
                Type = $ACL.ObjectType
                CanBeDelegate = $ACL.CanDelegate
                }
        } 
        
}
$RBAC | Export-Csv ".\$($SubscriptionName)-rbac.csv" -NoTypeInformation

$RBACRoot = @()
$ACL = @()
$scope = "/subscriptions/$subid"
    
foreach ($ACL in (Get-AzRoleAssignment | ?{$_.scope -eq $scope}))
    {
        $RBACRoot += [pscustomobject]@{
            Name = $ACL.DisplayName
            Signin = $ACL.SignInName
            ResourceGroup = $ACL.Scope.Substring($ACL.Scope.LastIndexOf("/")+1) 
            Role = $ACL.RoleDefinitionName
            Roleid = $ACL.RoleDefinitionID
            Type = $ACL.ObjectType
            CanBeDelegate = $ACL.CanDelegate
            }
    } 
$RBACRoot  | Export-Csv ".\$($SubscriptionName)-rbacroot.csv" -NoTypeInformation

# NIC's
function Get-AzureRmInvNIC () {  
                $ipInterface = Get-AzNetworkInterface 
                foreach ($nic in $ipInterface) {
                
                        $obj = New-Object -TypeName PSCustomObject
                        $virtualmachine = $nic.VirtualMachine.id -split("/")
                        $pip = $nic.IpConfigurations.PublicIpAddress.id -split("/")
                        $nsg = $nic.NetworkSecurityGroup.id -split("/")
                        
                        $obj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $virtualmachine[8]
                        $obj | Add-Member -MemberType NoteProperty -Name NicName -Value $nic.name
                        $obj | Add-Member -MemberType NoteProperty -Name PublicIP -Value $pip[8]
                        $obj | Add-Member -MemberType NoteProperty -Name Resource -Value $pip[7]
                        $obj | Add-Member -MemberType NoteProperty -Name Location -Value $nic.Location
                        $obj | Add-Member -MemberType NoteProperty -Name ResourceGroupName -Value $nic.ResourceGroupName
                        $obj | Add-Member -MemberType NoteProperty -Name NetworkSecurityGroup -Value $nsg[8]
                        $obj | Add-Member -MemberType NoteProperty -Name DNSServers -Value (@($nic.DnsSettings.DnsServers) -join ', ')
                        $obj | Add-Member -MemberType NoteProperty -Name PrivateIPAddress -Value $nic.IpConfigurations.PrivateIpAddress
                        $obj | Add-Member -MemberType NoteProperty -Name SubscriptionName -Value ($SubscriptionId).Name
                            
                        $obj
                            
                  
               }  
               
}  
 # Vnet Settings
function Get-AzureRmInvVNetSettings() {
      $obj = New-Object -TypeName PSCustomObject
        ForEach ($net in Get-AzVirtualNetwork) {
                $nsg = $net.Subnets.NetworkSecurityGroup.id -split("/")
                $vnett =$net.Id -split("/")
               # $subnet = $($net.Subnets.Name)
               #$subnetpref = $($net.Subnets.AddressPrefix)
                $vnetpeerremote = $net.VirtualNetworkPeerings.RemoteVirtualNetwork.Id -split("/")
                $obj | Add-Member -MemberType NoteProperty -Name VnetName -Value $($net.Name) -Force
                $obj | Add-Member -MemberType NoteProperty -Name AddressSpace -Value $($net.AddressSpace.AddressPrefixes)  -Force
                $obj | Add-Member -MemberType NoteProperty -Name Resource -Value $vnett[7]  -Force
                $obj | Add-Member -MemberType NoteProperty -Name Location -Value $net.Location  -Force   
                $obj | Add-Member -MemberType NoteProperty -Name DNSServerVnet -Value $($net.DhcpOptions.DnsServers) -Force
                $obj | Add-Member -MemberType NoteProperty -Name Subnets -Value (@($net.Subnets.Name) -join ', ')  -Force
                $obj | Add-Member -MemberType NoteProperty -Name SubnetsAddressPrefix -Value  (@($net.Subnets.AddressPrefix) -join ', ') -Force
                $obj | Add-Member -MemberType NoteProperty -Name NetworkSecurityGroup -Value $nsg[8]  -Force
                $obj | Add-Member -MemberType NoteProperty -Name ServiceEnpoints -Value $net.ServiceEnpoints  -Force
                $obj | Add-Member -MemberType NoteProperty -Name VnetPeerings -Value $net.VirtualNetworkPeerings.name  -Force
                $obj | Add-Member -MemberType NoteProperty -Name VnetPeeringsState -Value $net.VirtualNetworkPeerings.PeeringState  -Force
                $obj | Add-Member -MemberType NoteProperty -Name VnetPeeringsRemoteVnet -Value $vnetpeerremote[8]  -Force
                $obj | Add-Member -MemberType NoteProperty -Name SubscriptionName -Value ($SubscriptionId).Name  -Force

            $obj
        }
                      
    }                      
# List Resources    
function Get-AzureRmInvResources() {
    $obj = New-Object -TypeName PSCustomObject
    ForEach ($rec in Get-AzResource ) {
        $obj | Add-Member -MemberType NoteProperty -Name Name -Value $rec.Name -Force
        $obj | Add-Member -MemberType NoteProperty -Name ResourceType -Value $rec.ResourceType -Force
        $obj | Add-Member -MemberType NoteProperty -Name ResourceGroupName -Value $rec.ResourceGroupName -Force
        $obj | Add-Member -MemberType NoteProperty -Name Location -Value $rec.Location -Force
        if ($null -eq $rec.Tags) {
            $obj | Add-Member -MemberType NoteProperty -Name Tags -Value " " -Force
        }
        else {
            $RecTag = ([string]($rec.Tags.GetEnumerator() | ForEach-Object { "$($_.Key):$($_.Value)," }))
            $obj | Add-Member -MemberType NoteProperty -Name Tags -Value $RecTag -Force
        }
        
        $obj | Add-Member -MemberType NoteProperty -Name SubscriptionID -Value ($SubscriptionId).Id -Force
        $obj | Add-Member -MemberType NoteProperty -Name SubscriptionName -Value ($SubscriptionId).Name -Force
        $obj
    }
}

$SubscriptionId = Get-AzSubscription | Out-GridView -PassThru
$SubscriptionName = $SubscriptionId.Name
Select-AzSubscription -SubscriptionId ($SubscriptionId).Id


#Export
Get-AzureRmInvTenantInfo | Export-Csv -Path ".\$($SubscriptionName)-AzureRmInvTenantInfo.csv" -Force
Get-AzureRmInvResourceLocks | Export-Csv -Path ".\$($SubscriptionName)-AzureRmInvResourceLocks.csv" -Force
Get-AzureRmInvVMs | Export-Csv -Path ".\$($SubscriptionName)-AzureRmInvVMs.csv" -Force
Get-AzureRmInvUnManagedDisk| Export-Csv -Path ".\$($SubscriptionName)-AzureRmInvUnManagedDisk.csv" -Force
Get-AzureRmInvRBAC | Export-Csv -Path  ".\$($SubscriptionName)-AzureRmInvRBAC.csv" -Force
Get-AzureRmInvNIC | Export-Csv -Path ".\$($SubscriptionName)-AzureRmInvNIC.csv" -Force
Get-AzureRmInvVNetSettings | Export-Csv -Path ".\$($SubscriptionName)-AzureRmInvVNetSettings.csv" -Force
Get-AzureRmInvResources | Export-Csv -Path ".\$($SubscriptionName)-AzureRmInvResources.csv" -Force
