
function Get-AzureRmInvVmHasAppliedLock() 
{
    foreach ($vm in (Get-AzVM))
    {
        $obj = New-Object -TypeName PSCustomObject
        $obj | Add-Member -MemberType NoteProperty -Name Subscription $SubscriptionName -Force
        $obj | Add-Member -MemberType NoteProperty -Name Name -Value $vm.Name -Force
        $obj | Add-Member -MemberType NoteProperty -Name ResourceGroupName -Value $vm.ResourceGroupName -Force

        $vmRG = $vm.ResourceGroupName
        $vmHasAppliedLock = $null
        $vmHasAppliedLock = Get-AzResourceLock -ResourceGroupName $vmRG
        if ($vmHasAppliedLock)
        {
            $obj | Add-Member -MemberType NoteProperty -Name AppliedLockName -Value $vmHasAppliedLock.Name -Force
            $obj | Add-Member -MemberType NoteProperty -Name AppliedLockProperties -Value $vmHasAppliedLock.Properties -Force
        }
        else 
        {
            $obj | Add-Member -MemberType NoteProperty -Name AppliedLockName -Value "" -Force
            $obj | Add-Member -MemberType NoteProperty -Name AppliedLockProperties -Value "" -Force
        }

        $obj
    }

}

function Get-AzureRmInvResourceHasBackupVault()
{
    foreach ($servicevault in (Get-AzRecoveryservicesvault))
    {
        $containerTypes = @("AzureVM","Windows","AzureSQL","AzureStorage","AzureVMAppContainer")
        foreach ($containerType in $containerTypes)
        {
            if ($containerType -eq "Windows")
            {
                $protectedResources = Get-AzRecoveryServicesBackupContainer -ContainerType $containerType -BackupManagementType "MARS" -VaultId $servicevault.ID -Status "Registered"
                foreach ($resource in $protectedResources)
                {
                    $obj = New-Object -TypeName PSCustomObject
                    $obj | Add-Member -MemberType NoteProperty -Name Subscription -Value $SubscriptionName -Force
                    $obj | Add-Member -MemberType NoteProperty -Name ResourceName -Value $resource.FriendlyName -Force
                    $obj | Add-Member -MemberType NoteProperty -Name ResourceGroup -Value $resource.ResourceGroupName -Force
                    $obj | Add-Member -MemberType NoteProperty -Name ServiceVaultName -Value $servicevault.Name -Force
                    $obj | Add-Member -MemberType NoteProperty -Name ContainerType -Value $containerType -Force
    
                    $obj
                }
            }
            else 
            {
                $protectedResources = Get-AzRecoveryServicesBackupContainer -ContainerType $containerType -VaultId $servicevault.ID -Status "Registered"
                foreach ($resource in $protectedResources)
                {
                    $obj = New-Object -TypeName PSCustomObject
                    $obj | Add-Member -MemberType NoteProperty -Name Subscription -Value $SubscriptionName -Force
                    $obj | Add-Member -MemberType NoteProperty -Name ResourceName -Value $resource.FriendlyName -Force
                    $obj | Add-Member -MemberType NoteProperty -Name ResourceGroup -Value $resource.ResourceGroupName -Force
                    $obj | Add-Member -MemberType NoteProperty -Name ServiceVaultName -Value $servicevault.Name -Force
                    $obj | Add-Member -MemberType NoteProperty -Name ContainerType -Value $containerType -Force

                    $obj
                }
            }
        }
    }
}



Connect-AzAccount 

$SubscriptionId = Get-AzSubscription | Out-GridView -PassThru
$SubscriptionName = $SubscriptionId.Name
Select-AzSubscription -SubscriptionId ($SubscriptionId).Id

Get-AzureRmInvVmHasAppliedLock | Export-Csv -Path ".\$($SubscriptionName)-AzureRmInvVmHasAppliedLock.csv" -Force
Get-AzureRmInvResourceHasBackupVault | Export-Csv -Path ".\$($SubscriptionName)-AzureRmInvResourceHasBackupVault.csv" -Force





