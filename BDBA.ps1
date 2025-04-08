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

[Net.ServicePointManager]::SecurityProtocol = 'tls12'; $Env:DETECT_EXIT_CODE_PASSTHRU=1; irm https://detect.synopsys.com/detect9.ps1?$(Get-Random) | iex; detect `
 --blackduck.url="$serverUrl" `
 --blackduck.api.token=$token `
 --detect.project.name=<BlackDuck_Project_name> `
 --detect.project.version.name=<BlackDuck_Version_name> `
 --detect.source.path=<path/to/scan/folder> `
 --detect.binary.scan.file.path=<path/to/binary/file> `
 --detect.tools.excluded=SIGNATURE_SCAN `
 --detect.project.version.phase=PLANNING `
 --detect.project.version.distribution=EXTERNAL