# Black Duck Automation Script for Creating SBOM

This repository contains PowerShell scripts designed to automate the creation of a Software Bill of Materials (SBOM) using Black Duck. The scripts currently support scanning Python, RedHat, Nodejs, Maven, and GitHub modules.

## Supported Scans

<span style="color:green;">&#x2705;</span> **Python (PyPI)** <br>
<span style="color:green;">&#x2705;</span> **RedHat (rpm)** <br>
<span style="color:green;">&#x2705;</span> **Nodejs (npm)** <br>
<span style="color:red;">&#x274C;</span> **Maven (mvn)** <br>
<span style="color:red;">&#x274C;</span> **GitHub Repositories** 

## Files in the Repository

- **`BDBA.ps1`**: Script for performing Binary Analysis.
- **`BDSA.ps1`**: Script for performing Signature Analysis.
- **`main.ps1`**: The main script that creates the SBOM for the specified modules.

## Usage

### Step 1: Clone the Repository

```sh
git clone https://github.com/PradumnUpadhyay/BlackDuckSCA.git
cd BlackDuckSCA
```
#### Step 2: Edit the `config.json` File

- Add your Black Duck account token in the `config.json` file.
- Configure the modules you want to scan by setting the `scan` value to `true` for the desired modules.
- Ensure the `filepath` field points to the correct `.bd` files for each module.

Example `config.json` structure:

```json
{
    "modules": {
        "pypi": {
            "scan": false,
            "filepath": "./Module-Files/python.pypi.bd"
        },
        "redhat": {
            "scan": true,
            "filepath": "./Module-Files/redhat.rpm.bd"
        },
        "maven": {
            "scan": false,
            "filepath": "./Module-Files/java.maven.bd"
        },
        "github": {
            "scan": false,
            "filepath": "./Module-Files/github.repos.bd"
        }
    }
}
```

### Step 3: Add Modules to `.bd` Files

- Navigate to the `Module-Files` folder in the repository.
- Add or update the `.bd` files for each module you want to scan according to the paths specified in the `config.json` file.
- Ensure that each file matches the `filepath` field in the `config.json`. For example, if `config.json` has `"filepath": "./Module-Files/redhat.rpm.bd"`, make sure there is a `redhat.rpm.bd` file in the `Module-Files` folder with the required content.

### Step 4: Execute the `main.ps1` Script

- Open a PowerShell terminal.
- Navigate to the directory containing the scripts.
- Run the `main.ps1` script by executing the following command:

  ```powershell
  .\main.ps1

- The script will process the modules as per the configuration in config.json and generate the SBOM based on the provided .bd files.

**NOTE:** Ensure that you have configured the **`config.json`** file correctly and have placed all necessary `.bd` files before running the script.