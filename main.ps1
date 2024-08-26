$logfile="../Error-Logs/scan_errors.log"
$exists="../Error-Logs/exists.log"

# Function to read configuration from a file
function Read-Config {
    $configPath = "./config.json"
    if (Test-Path $configPath) {
        $configContent = Get-Content -Path $configPath -Raw
        $config = $configContent | ConvertFrom-Json
        return $config
    } else {
        Write-Host -ForegroundColor Red "Configuration file not found."
        exit
    }
}

# Function to create a project
function Create-Project {
    param (
        [string]$ProjectName,
        [string]$VersionName,
        [string]$Token,
        [string]$ServerUrl,
        [string]$ProjectGroupId
    )

    $url = "$ServerUrl/api/projects/"
    $headers = @{
        "Accept"        = "application/vnd.blackducksoftware.project-detail-7+json"
        "Content-Type"  = "application/vnd.blackducksoftware.project-detail-7+json"
        "Authorization" = "Bearer $Token"
    }
    $postData = @{
        "cloneCategories"          = @("CUSTOM_FIELD_DATA", "COMPONENT_DATA", "DEEP_LICENSE", "VULN_DATA", "LICENSE_TERM_FULFILLMENT", "VERSION_SETTINGS")
        "projectGroup"             = "$ServerUrl/api/project-groups/$ProjectGroupId"
        "name"                     = $ProjectName
        "projectLevelAdjustments"  = $true
        "snippetAdjustmentApplied" = $true
        "versionRequest"           = @{
            "distribution" = "EXTERNAL"
            "phase"        = "PLANNING"
            "versionName"  = $VersionName
        }
    }
    $jsonPostData = $postData | ConvertTo-Json -Depth 10

    try {
        $response = Invoke-WebRequest -Uri $url -Method Post -Headers $headers -Body $jsonPostData -UseBasicParsing
        $response.StatusCode
        if ($response.StatusCode -eq 201) {
            Write-Host -ForegroundColor Green "Project created successfully with name '$ProjectName' and version '$VersionName'."
        } elseif ($response.StatusCode -eq 200 -or $response.StatusCode -eq $null) {
            Write-Host -ForegroundColor Green "Project created successfully (no specific status code received) with name '$ProjectName' and version '$VersionName'."
        } else {
            Write-Host -ForegroundColor Red "Unexpected status code: $($response.StatusCode). Response: $($response.Content)"
        }
        return $response.Content

    } catch {
        if ($_.Exception.Response.StatusCode.Value__ -eq 412) {
            Write-Host -ForegroundColor Yellow "Project already exists. Do you want to create a new version with version: '$VersionName'?(Y/N)"
            $createVersion = Read-Host

            if($createVersion -eq 'Y') {
            # URL for creating a new version
            $versionUrl = "$ServerUrl/api/projects/$ProjectName/versions"
            $versionData = @{
                "versionName" = $VersionName
                "phase"       = "PLANNING"
                "distribution" = "EXTERNAL"
            }
            $jsonVersionData = $versionData | ConvertTo-Json -Depth 10

            try {
                $versionResponse = Invoke-WebRequest -Uri $versionUrl -Method Post -Headers $headers -Body $jsonVersionData -UseBasicParsing
                if ($versionResponse.StatusCode -eq 201) {
                    Write-Host -ForegroundColor Green "New version '$VersionName' created successfully for project '$ProjectName'."
                } else {
                    Write-Host -ForegroundColor Red "Failed to create new version. Status code: $($versionResponse.StatusCode). Response: $($versionResponse.Content)"
                }
                return 
            } catch {
                Write-Host -ForegroundColor Red "An error occurred while creating the new version: $($_.Exception.Message)"
            }
        } else { exit }
    } else {
            Write-Host -ForegroundColor Red "An error occurred while creating the project: $($_.Exception.Message)"
        }
    }
}

# Function to send a GET request to the specified URL
function Query-ProjectName {
    param (
        [string]$Token,
        [string]$ProjectName,
        [string]$ServerUrl
    )

    $headers = @{
        "Accept" = "*/*"
        "Authorization" = "Bearer $Token"
    }
    $url = "$ServerUrl/api/projects?q=name:$ProjectName&limit=1000"

    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers
        return $response
    } catch {
        Write-Error $_.Exception.Message
    }
}

# Function to get the bearer token
function Get-BearerToken {
    param (
        [string]$Token,
        [string]$ServerUrl
    )

    $url = "$ServerUrl/api/tokens/authenticate"
    $headers = @{
        "Accept" = "application/vnd.blackducksoftware.user-4+json"
        "Authorization" = "token $Token"
    }

    try {
        $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers
        $bearerToken = $response.bearerToken
        return $bearerToken
    } catch {
        Write-Error $_.Exception.Message
    }
}

# Function to recursively parse JSON response and extract names
function Get-ProjectLink {
    param (
        [string]$JsonResponse
    )

    $jsonObject = $JsonResponse | ConvertFrom-Json
    $totalCount = $jsonObject.totalCount

    if ($totalCount -eq 0) {
        Write-Host -ForegroundColor Red "No projects found. Please try again."
        return
    }

    $items = $jsonObject.items
    Write-Host -ForegroundColor Yellow "`nTotal Count: $totalCount"
    Write-Host -ForegroundColor Yellow "Project Names:"
    
    $projectNames = @()
    $index = 0
    foreach ($item in $items) {
        $projectName = $item.name
        Write-Host -ForegroundColor Green "$index : $projectName"
        $projectNames += $projectName
        $index++
    }
    
    do {
        Write-Host -ForegroundColor Cyan "Enter the index of the project to get details:"
        $selectedProjectIndex = Read-Host
        if (($selectedProjectIndex -lt 0) -or ($selectedProjectIndex -ge $totalCount)) {
            Write-Host -ForegroundColor Red "Invalid index. Please enter a valid index."
        } else {
            break
        }
    } until ($selectedProjectIndex -ge 0 -and $selectedProjectIndex -lt $totalCount)

    $selectedProjectName = $projectNames[$selectedProjectIndex]
    Write-Host -ForegroundColor Yellow "Project Selected: $selectedProjectName"
    $selectedProject = $items[$selectedProjectIndex]
    $projectLink = $selectedProject._meta.links | Where-Object { $_.rel -eq "versions" } | Select-Object -ExpandProperty href

    return $projectLink
}

# Function to send a GET request to the specified URL
function Send-GetRequest {
    param (
        [string]$Url,
        [string]$Token
    )

    $headers = @{
        "Accept" = "*/*"
        "Authorization" = "Bearer $Token"
    }

    try {
        $response = Invoke-RestMethod -Uri $Url -Method Get -Headers $headers
        $response=$response | ConvertTo-Json -Depth 100
        # Write-Host "Send-getRequest: $response"
        return $response
    } catch {
        Write-Error $_.Exception.Message
    }
}

# Function to parse JSON response and extract version names
function Get-ProjectVersionLink {
    param (
        [string]$JsonResponse
    )
    
    $jsonObject = $JsonResponse | ConvertFrom-Json
    # Write-Host "$jsonObject"
    $items = $jsonObject.items

    Write-Host -ForegroundColor Yellow "Versions:"
    $versionNames = @()
    $index = 0
    foreach ($item in $items) {
        $versionName = $item.versionName
        Write-Host -ForegroundColor Green "$index : Version $versionName"
        $versionNames += $versionName
        $index++
    }
    
    Write-Host -ForegroundColor Cyan "Enter the index of the version to view details:"
    $selectedVersionIndex = Read-Host
    $selectedVersionName = $versionNames[$selectedVersionIndex]
    
    $selectedVersionObject = $items | Where-Object { $_.versionName -eq $selectedVersionName }
    $componentsLink = $selectedVersionObject._meta.links | Where-Object { $_.rel -eq "components" }

    if ($componentsLink -ne $null) {
        return $componentsLink.href
    } else {
        Write-Host -ForegroundColor Red "No components link found for version $selectedVersionName"
        return $null
    }
}

# Function to scan PyPI modules
function Scan-PyPIModules {
    param (
        [string]$FileName,
        [string]$Token,
        [string]$ServerUrl
    )

    $componentUrls = @()
    $moduleData = Get-Content $FileName

    foreach ($line in $moduleData) {
        $moduleName, $version = $line -split '\s*={1,}\s*'
        $moduleQuery = "pypi:$moduleName/$version"
        $queryUrl = "$ServerUrl/api/components?q=$moduleQuery"
        $headers = @{
            "Accept" = "application/vnd.blackducksoftware.component-detail-4+json"
            "Authorization" = "Bearer $Token"
        }

        try {
            $response = Invoke-RestMethod -Uri $queryUrl -Method Get -Headers $headers | ConvertTo-Json -Depth 100      
            $jsonObject = ConvertFrom-Json $response
            $totalCount = $jsonObject.totalCount

            if ($totalCount -eq 0) {
                throw "ZeroCount"
            }
            
            if ($totalCount -gt 1) {
                Display-ComponentChoices -JsonResponse $response
                Write-Host -ForegroundColor Cyan "Enter the index of the component to select:"
                $selectedComponentIndex = Read-Host
                $selectedComponent = $jsonObject.items[$selectedComponentIndex]
                $componentUrls += @{ $moduleName = $selectedComponent.component }
            } else {
                $componentUrls += @{ $moduleName = $jsonObject.items[0].variant }
            }
        } catch {
            if ($_.Exception.Message -eq "ZeroCount") {
                Write-Host -ForegroundColor Red "Failed to retrieve component information: $moduleName, Version: $version"

                $errMsg = "Module: $mouleName, Version: $version; Exists: False; Error: Failed to retrieve component info"
                Add-Content -Path "$exists" -Value $errMsg
            } else {
                $ExceptionMessage = $_.Exception.Message
                Write-Host -ForegroundColor Red "An error occurred while querying component: $moduleName, Version: $version. Error: $ExceptionMessage"

                $errMsg = "Module: $mouleName, Version: $version; Exists: False; Error: $ExceptionMessage"
                Add-Content -Path "$logfile" -Value $errMsg
            }
        }
    }

    return $componentUrls
}

# Function to scan RedHat modules
function Scan-RedHatModules {
    param (
        [string]$FileName,
        [string]$Token,
        [string]$ServerUrl
    )

    # Regex patterns
    $modulePattern = '([^-]+?-[^-\d.]+)|^([^-]+)'
    $archPattern = 'noarch|x86_64|aarch64|ppc64le|s390x'
 
    $componentUrls = @()
    $moduleData = Get-Content $FileName

    foreach ($line in $moduleData) {
        $moduleName = ''
        $version = ''
        $arch = ''

        # Extracting Module Name
        if ($line -match $modulePattern) {
            $moduleName = $matches[0]
            $line = $line -replace [regex]::Escape($moduleName), ''
        }

        # Remove leading hyphen from the remaining string if it exists
        $line = $line.TrimStart('-')

        # Extract architecture
        if ($line -match $archPattern) {
            $arch = $matches[0]
            $versionName = $line -replace [regex]::Escape($arch), ''
        }

        # Remove trailing dot (.) from the version name
        $versionName = $versionName.TrimEnd('.')

        if ($moduleName -and $versionName -and $arch) {
            $encodedModuleName = [System.Web.HttpUtility]::UrlEncode($moduleName)
            $encodedVersionName = [System.Web.HttpUtility]::UrlEncode($versionName)
            $encodedArch = [System.Web.HttpUtility]::UrlEncode($arch)

            $moduleQuery = "redhat:$encodedModuleName/$encodedVersionName/$encodedArch"
            $queryUrl = "$ServerUrl/api/components?q=$moduleQuery"
            $headers = @{
                "Accept" = "application/vnd.blackducksoftware.component-detail-4+json"
                "Authorization" = "Bearer $Token"
            }

            try {
                $response = Invoke-RestMethod -Uri $queryUrl -Method Get -Headers $headers | ConvertTo-Json -Depth 100      
                $jsonObject = ConvertFrom-Json $response
                $totalCount = $jsonObject.totalCount

                if ($totalCount -eq 0) {
                    throw "ZeroCount"
                }

                if ($totalCount -gt 1) {
                    Display-ComponentChoices -JsonResponse $response
                    Write-Host -ForegroundColor Cyan "Enter the index of the component to select:"
                    $selectedComponentIndex = Read-Host
                    $selectedComponent = $jsonObject.items[$selectedComponentIndex]
                    $componentUrls += @{ $moduleName = $selectedComponent.component }
                } else {
                    $componentUrls += @{ $moduleName = $jsonObject.items[0].variant }
                }
            } catch {
                if ($_.Exception.Message -eq "ZeroCount") {
                    Write-Host -ForegroundColor Red "Failed to retrieve component information: $moduleName, Version: $versionName, Arch: $arch"

                    $errMsg = "Module: $moduleName, Version: $versionName; Exists: False; Error: Failed to retrieve component info"
                    Add-Content -Path "$exists" -Value $errMsg
                    
                } else {
                    $ExceptionMessage = $_.Exception.Message
                    Write-Host -ForegroundColor Red "An error occurred while querying component: $moduleName, Version: $version. Error: $ExceptionMessage"
                    
                    $errMsg = "Module: $mouleName, Version: $version; Exists: False; Error: $ExceptionMessage"
                    Add-Content -Path "$logfile" -Value $errMsg
                }
            }
        } else {
            Write-Host -ForegroundColor Red "Failed to match pattern for line: $line"
        }
    }

    return $componentUrls
}

# Function to scan GitHub modules
function Scan-GitHubModules {
    param (
        [string]$FileName,
        [string]$Token,
        [string]$ServerUrl
    )

    $componentUrls = @()
    $moduleData = Get-Content $FileName

    foreach ($line in $moduleData) {
        $repoName, $version = $line -split '\W{1,}\|\W{1,}|\|'
        $repoName = $repoName.Trim("https://gtihub.com/")
        $moduleQuery = "github:$repoName`:$version"
        $queryUrl = "$ServerUrl/api/components?q=$moduleQuery"
        $headers = @{
            "Accept" = "application/vnd.blackducksoftware.component-detail-4+json"
            "Authorization" = "Bearer $Token"
        }

        try {
            $response = Invoke-RestMethod -Uri $queryUrl -Method Get -Headers $headers | ConvertTo-Json -Depth 100      
            $jsonObject = ConvertFrom-Json $response
            $totalCount = $jsonObject.totalCount

            if ($totalCount -eq 0) {
                throw "ZeroCount"
            }

            if ($totalCount -gt 1) {
                Display-ComponentChoices -JsonResponse $response
                Write-Host -ForegroundColor Cyan "Enter the index of the component to select:"
                $selectedComponentIndex = Read-Host
                $selectedComponent = $jsonObject.items[$selectedComponentIndex]
                $componentUrls += @{ $moduleName = $selectedComponent.component }
            } else {
                $componentUrls += @{ $moduleName = $jsonObject.items[0].variant }
            }
        } catch {
            if ($_.Exception.Message -eq "ZeroCount") {
                Write-Host -ForegroundColor Red "Failed to retrieve component information: $repoName, Version: $version"

                $errMsg = "Module: $repoName, Version: $version; Exists: False; Error: Failed to retrieve component info"
                Add-Content -Path "$exists" -Value $errMsg

            } else {
                $ExceptionMessage = $_.Exception.Message
                Write-Host -ForegroundColor Red "An error occurred while querying component: $repoName, Version: $version. Error: $ExceptionMessage"
                
                $errMsg = "Module: $repoName, Version: $version; Exists: False; Error: $ExceptionMessage"
                Add-Content -Path "$logfile" -Value $errMsg

            }
        }
    }

    return $componentUrls
}

# Function to scan Maven modules
function Scan-MavenModules {
    param (
        [string]$FileName,
        [string]$Token,
        [string]$ServerUrl
    )

    $componentUrls = @()
    $moduleData = Get-Content $FileName

    foreach ($line in $moduleData) {
        $moduleName, $version = $line -split '\s*={1,}\s*'
        $moduleQuery = "maven:$moduleName`:`:$version"
        $queryUrl = "$ServerUrl/api/components?q=$moduleQuery"
        $headers = @{
            "Accept" = "application/vnd.blackducksoftware.component-detail-4+json"
            "Authorization" = "Bearer $Token"
        }

        try {
            $response = Invoke-RestMethod -Uri $queryUrl -Method Get -Headers $headers | ConvertTo-Json -Depth 100      
            $jsonObject = ConvertFrom-Json $response
            $totalCount = $jsonObject.totalCount

            if ($totalCount -eq 0) {
                throw "ZeroCount"
            }

            if ($totalCount -gt 1) {
                Display-ComponentChoices -JsonResponse $response
                Write-Host -ForegroundColor Cyan "Enter the index of the component to select:"
                $selectedComponentIndex = Read-Host
                $selectedComponent = $jsonObject.items[$selectedComponentIndex]
                $componentUrls += @{ $moduleName = $selectedComponent.component }
            } else {
                $componentUrls += @{ $moduleName = $jsonObject.items[0].variant }
            }
        } catch {
            if ($_.Exception.Message -eq "ZeroCount") {
                Write-Host -ForegroundColor Red "Failed to retrieve component information: $moduleName, Version: $version"
            } else {
                $ExceptionMessage = $_.Exception.Message
                Write-Host -ForegroundColor Red "An error occurred while querying component: $moduleName, Version: $version. Error: $ExceptionMessage"
            }
        }
    }

    return $componentUrls
}

# Function to scan modules
function Scan-Modules {
    param (
        [string]$ComponentUrl,
        [hashtable[]]$ComponentIds,
        [string]$Token
    )

    foreach ($componentIdHash in $ComponentIds) {
        foreach ($moduleName in $componentIdHash.Keys) {
            $componentId = $componentIdHash[$moduleName]
            $headers = @{
                "Content-Type" = "application/json"
                "Authorization" = "Bearer $Token"
            }
            $queryParams = @{
                component = $componentId
            }
            $jsonData = $queryParams | ConvertTo-Json

            try {
                $response = Invoke-RestMethod -Uri $ComponentUrl -Method Post -Headers $headers -Body $jsonData
            } catch {
                $StatusCode = $_.Exception.Response.StatusCode.value__
                $ExceptionMessage = $_.Exception.Message
                $scan_error = ''

                if ($StatusCode -eq 412) {
                    Write-Host -ForegroundColor Red "Component Already Exists! Name: $moduleName"

                    $errMsg = "Module: $moduleName; Exists: True"

                    Add-Content -Path "$exists" -Value $errMsg
                    
                } else {
                    Write-Host -ForegroundColor Red "An error occurred while starting the scan: $ExceptionMessage"
                    
                    $errMsg = "Module: $moduleName; Exists: False; Error: $ExceptionMessage"

                    Add-Content -Path $logfile -Value $errMsg
                }

            }
        }
    }

    Write-Host -ForegroundColor DarkCyan "Please refer to scan_errors.log and exists.log for list of errors and modules, that weren't scanned."
}

# Main script execution
$config = Read-Config

$serverUrl = $config.server_url
$projectGroupId = $config.project_group_id
$token = $config.token
$modules = $config.modules
$bearerToken = Get-BearerToken -Token $token -ServerUrl $serverUrl

$bearerToken | Out-File -FilePath "./bearer.txt"

# Create or query a project
Write-Host -ForegroundColor Cyan "Enter '1' to create a new project or '2' to query an existing project:"
$action = Read-Host

if ($action -eq '1') {
    Write-Host -ForegroundColor Cyan "Enter the project name:"
    $projectName = Read-Host
    Write-Host -ForegroundColor Cyan "Enter the version name:"
    $versionName = Read-Host
    $createProjectResponse = Create-Project -ProjectName $projectName -VersionName $versionName -Token $bearerToken -ServerUrl $serverUrl -ProjectGroupId $projectGroupId
} elseif ($action -eq '2') {
    Write-Host -ForegroundColor Cyan "Enter the project name to query:"
    $projectName = Read-Host
    $queryProjectResponse = Query-ProjectName -Token $bearerToken -ProjectName $projectName -ServerUrl $serverUrl
    $projectLink = Get-ProjectLink -JsonResponse ($queryProjectResponse | ConvertTo-Json -Depth 100)
    if ($projectLink -ne $null) {
        $componentsLink = Get-ProjectVersionLink -JsonResponse (Send-GetRequest -Url $projectLink -Token $bearerToken)
    }
} else {
    Write-Host -ForegroundColor Red "Invalid input. Please enter '1' or '2'."
    exit
}

foreach ($moduleName in $modules.PSObject.Properties.Name) {
    $module = $modules.$moduleName

    if ($module.scan -and $module.filepath) {
        $filepath = $module.filepath

        if (Test-Path $filepath) {
            Write-Host -ForegroundColor Yellow "Scanning $moduleName modules from $filepath..."

            switch ($moduleName) {
                "pypi" { $componentUrls = Scan-PyPIModules -FileName $filepath -Token $bearerToken -ServerUrl $serverUrl }
                "redhat" { $componentUrls = Scan-RedHatModules -FileName $filepath -Token $bearerToken -ServerUrl $serverUrl }
                "maven" { $componentUrls = Scan-MavenModules -FileName $filepath -Token $bearerToken -ServerUrl $serverUrl }
                "github" { $componentUrls = Scan-GitHubModules -FileName $filepath -Token $bearerToken -ServerUrl $serverUrl }
                default { Write-Host -ForegroundColor Red "Unknown module type: $moduleName" }
            }

            if ($null -ne $componentsLink -and $componentUrls.Count -gt 0) {
                Scan-Modules -ComponentUrl $componentsLink -ComponentIds $componentUrls -Token $bearerToken
            } else {
                Write-Host -ForegroundColor Red "No valid component URLs found for scanning."
            }
        } else {
            Write-Host -ForegroundColor Red "File not found: $filepath"
        }
    }
}

$ending="*************************************************"
Add-Content -Path $logfile -Value $ending
Add-Content -Path $exists -Value $ending
