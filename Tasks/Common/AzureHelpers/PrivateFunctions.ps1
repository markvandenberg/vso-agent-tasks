function Set-CurrentAzureSubscription {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SubscriptionId,
        [string]$StorageAccount)

    $additional = @{ }
    if ($script:azureModuleVersion -lt ([version]'0.8.15')) {
        $additional['Default'] = $true # The Default switch is required prior to 0.8.15.
    }

    Write-Host "Select-AzureSubscription -SubscriptionId $SubscriptionId $(Format-Splat $additional)"
    $null = Select-AzureSubscription -SubscriptionId $SubscriptionId @additional
    if ($StorageAccount) {
        Write-Host "Set-AzureSubscription -SubscriptionId $SubscriptionId -CurrentStorageAccountName $StorageAccount"
        Set-AzureSubscription -SubscriptionId $SubscriptionId -CurrentStorageAccountName $StorageAccount
    }
}

function Set-CurrentAzureRMSubscription {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$SubscriptionId,
        [string]$TenantId)

    $additional = @{ }
    if ($TenantId) { $additional['TenantId'] = $TenantId }
    Write-Host "Select-AzureRMSubscription -SubscriptionId $SubscriptionId $(Format-Splat $additional)"
    $null = Select-AzureRMSubscription -SubscriptionId $SubscriptionId @additional
}

function Initialize-AzureSubscription {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Endpoint,
        [Parameter(Mandatory=$false)]
        [string]$StorageAccount)

    if ($Endpoint.Auth.Scheme -eq 'Certificate') {
        # Certificate is only supported for the Azure module.
        if (!(Get-Module Azure)) {
            throw (Get-VstsLocString -Key AZ_CertificateAuthNotSupported)
        }

        $bytes = [System.Convert]::FromBase64String($Endpoint.Auth.Parameters.Certificate)
        $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $certificate.Import($bytes)
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
            ([System.Security.Cryptography.X509Certificates.StoreName]::My),
            ([System.Security.Cryptography.X509Certificates.StoreLocation]::'CurrentUser'))
        $store.Open(([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite))
        $store.Add($certificate)
        $store.Close()
        $additional = @{ }
        if ($script:azureModuleVersion -lt ([version]'0.8.8')) {
            $additional['ServiceEndpoint'] = $Endpoint.Url
        } else {
            $additional['Environment'] = 'AzureCloud'
        }

        if ($StorageAccount) {
            $additional['CurrentStorageAccountName'] = $StorageAccount
        }

        Write-Host "Set-AzureSubscription -SubscriptionName $($Endpoint.Data.SubscriptionName) -SubscriptionId $($Endpoint.Data.SubscriptionId) -Certificate $certificate $(Format-Splat $additional)"
        Set-AzureSubscription -SubscriptionName $Endpoint.Data.SubscriptionName -SubscriptionId $Endpoint.Data.SubscriptionId -Certificate $certificate @additional
        Write-Host "Set-CurrentAzureSubscription -SubscriptionId $($Endpoint.Data.SubscriptionId)"
        Set-CurrentAzureSubscription -SubscriptionId $Endpoint.Data.SubscriptionId
    } elseif ($Endpoint.Auth.Scheme -eq 'UserNamePassword') {
        $psCredential = New-Object System.Management.Automation.PSCredential(
            $Endpoint.Auth.Parameters.UserName,
            (ConvertTo-SecureString $Endpoint.Auth.Parameters.Password -AsPlainText -Force))
        if (Get-Module -Name Azure) {
            try {
                Write-Host "Add-AzureAccount -Credential $psCredential"
                $null = Add-AzureAccount -Credential $psCredential
            } catch {
                # Provide an additional, custom, credentials-related error message.
                Write-VstsTaskError -Message $_.Exception.Message
                throw (New-Object System.Exception((Get-VstsLocString -Key AZ_CredentialsError), $_.Exception))
            }

            Write-Host "Set-CurrentAzureSubscription -SubscriptionId $($Endpoint.Data.SubscriptionId) -StorageAccount $StorageAccount"
            Set-CurrentAzureSubscription -SubscriptionId $Endpoint.Data.SubscriptionId -StorageAccount $StorageAccount
        } else {
            try {
                Write-Host "Add-AzureRMAccount -Credential $psCredential"
                $null = Add-AzureRMAccount -Credential $psCredential
            } catch {
                # Provide an additional, custom, credentials-related error message.
                Write-VstsTaskError -Message $_.Exception.Message
                throw (New-Object System.Exception((Get-VstsLocString -Key AZ_CredentialsError), $_.Exception))
            }

            Write-Host "Set-CurrentAzureRMSubscription -SubscriptionId $($Endpoint.Data.SubscriptionId)"
            Set-CurrentAzureRMSubscription -SubscriptionId $Endpoint.Data.SubscriptionId
        }
    } elseif ($Endpoint.Auth.Scheme -eq 'ServicePrincipal') {
        $psCredential = New-Object System.Management.Automation.PSCredential(
            $Endpoint.Auth.Parameters.ServicePrincipalId,
            (ConvertTo-SecureString $Endpoint.Auth.Parameters.ServicePrincipalKey -AsPlainText -Force))
        if ($script:azureModuleVersion -lt ([version]'0.9.9')) {
            # Service principals arent supported from 0.9.9 and greater in the Azure module.
            try {
                Write-Host "Add-AzureAccount -ServicePrincipal -Tenant $($Endpoint.Auth.Parameters.TenantId) -Credential $psCredential"
                $null = Add-AzureAccount -ServicePrincipal -Tenant $Endpoint.Auth.Parameters.TenantId -Credential $psCredential
            } catch {
                # Provide an additional, custom, credentials-related error message.
                Write-VstsTaskError -Message $_.Exception.Message
                throw (New-Object System.Exception((Get-VstsLocString -Key AZ_ServicePrincipalError), $_.Exception))
            }

            Write-Host "Set-CurrentAzureSubscription -SubscriptionId $($Endpoint.Data.SubscriptionId) -StorageAccount $StorageAccount"
            Set-CurrentAzureSubscription -SubscriptionId $Endpoint.Data.SubscriptionId -StorageAccount $StorageAccount
        } elseif (!(Get-module -Name AzureRM)) {
            # Throw if >=0.9.9 Azure.
            throw (Get-VstsLocString -Key "AZ_ServicePrincipalAuthNotSupportedAzureVersion0" -ArgumentList $script:azureModuleVersion)
        } else {
            # Else, this is AzureRM.
            try {
                Write-Host "Add-AzureRMAccount -ServicePrincipal -Tenant $($Endpoint.Auth.Parameters.TenantId) -Credential $psCredential"
                $null = Add-AzureRMAccount -ServicePrincipal -Tenant $Endpoint.Auth.Parameters.TenantId -Credential $psCredential
            } catch {
                # Provide an additional, custom, credentials-related error message.
                Write-VstsTaskError -Message $_.Exception.Message
                throw (New-Object System.Exception((Get-VstsLocString -Key AZ_ServicePrincipalError), $_.Exception))
            }

            Write-Host "Set-CurrentAzureRMSubscription -SubscriptionId $($Endpoint.Data.SubscriptionId) -TenantId $($Endpoint.Auth.Parameters.TenantId)"
            Set-CurrentAzureRMSubscription -SubscriptionId $Endpoint.Data.SubscriptionId -TenantId $Endpoint.Auth.Parameters.TenantId
        }
    } else {
        throw (Get-VstsLocString -Key AZ_UnsupportedAuthScheme0 -ArgumentList $Endpoint.Auth.Scheme)
    }
}

function Import-AzureModule {
    [CmdletBinding()]
    param()

    Trace-VstsEnteringInvocation $MyInvocation
    try {
        # Look for the Azure module in a well-known location.
        $module = $null
        foreach ($programFiles in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
            if (!$programFiles) { continue }
            $path = [System.IO.Path]::Combine($programFiles, "Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Azure.psd1")
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                Write-Host "Import-Module -Name $path -Global"
                $module = Import-Module -Name $path -Global -PassThru
                break
            }
        }

        if (!$module) {
            # Attempt to load the Azure/AzureRM module from the module path.
            foreach ($name in @('Azure', 'AzureRM')) {
                $module = Get-Module -Name $name -ListAvailable |
                    Select-Object -First 1
                if ($module) {
                    Write-Host "Import-Module -Name $($module.Path) -Global"
                    $module = Import-Module -Name $module.Path -Global -PassThru
                    break
                }
            }
        }

        # Throw if the module wasn't found.
        if (!$module) {
            throw (Get-VstsLocString -Key AZ_ModuleNotFound)
        }

        # Store and validate the imported version.
        Write-Verbose "Imported module version: $($module.Version)"
        $script:azureModuleVersion = $module.Version
        $minimumVersion = [version]'0.8.10.1'
        if ($script:azureModuleVersion -lt $minimumVersion) {
            throw (Get-VstsLocString -Key AZ_RequiresMinVersion0 -ArgumentList $minimumVersion)
        }

        # Short-circuit if the Azure module was imported.
        if ($module.Name -eq "Azure") {
            return
        }

        # Validate the AzureRM.profile module can be found.
        $profileModule = Get-Module -Name AzureRM.profile -ListAvailable |
            Select-Object -First 1
        if (!$profileModule) {
            throw (Get-VstsLocString -Key AZ_AzureRMProfileModuleNotFound)
        }

        # Import the AzureRM.profile module.
        Write-Host "Import-Module -Name $($profileModule.Path) -Global"
        $profileModule = Import-Module -Name $profileModule.Path -Global -PassThru
        Write-Verbose "Imported module version: $($profileModule.Version)"
    } finally {
        Trace-VstsLeavingInvocation $MyInvocation
    }
}

function Format-Splat {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Hashtable)

    # Collect the parameters (names and values) in an array.
    $parameters = foreach ($key in $Hashtable.Keys) {
        $value = $Hashtable[$key]
        # If the value is a bool, format the parameter as a switch (ending with ':').
        if ($value -is [bool]) { "-$($key):" } else { "-$key" }
        $value
    }

    $OFS = " "
    "$parameters" # String join the array.
}