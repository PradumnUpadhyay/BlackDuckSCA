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

$config=Read-Config
$serverUrl=$config.server_url
$token=$config.token

[Net.ServicePointManager]::SecurityProtocol = 'tls12'; $Env:DETECT_EXIT_CODE_PASSTHRU=1; irm https://detect.synopsys.com/detect9.ps1?$(Get-Random) | iex; detect --blackduck.url="$serverUrl" --blackduck.api.token="$token" --detect.project.name=testing_7890 --detect.project.version.name=redhat --detect.blackduck.signature.scanner.paths=D:\Pradumn\APPSEC-2826\definitionservice-py3-v7.0.78+6.1.10.tar --detect.tools=CONTAINER_SCAN --detect.project.version.phase=PLANNING --detect.project.version.distribution=EXTERNAL