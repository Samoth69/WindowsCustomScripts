param (
    # Enable verbose output
    [switch]$verbose = $false
)

# --- Utils ---

function Write-CustomDebug() {
    if ($verbose) {
        Write-Host "[D]" $args -ForegroundColor DarkGray
    }
}

function Write-CustomInfo() {
    Write-Host "[I]" $args
}

function Write-CustomWarn() {
    Write-Host "[W]" $args -ForegroundColor DarkYellow
}

function Write-CustomError() {
    Write-Host "[E]" $args -ForegroundColor DarkRed
}

function Test-RegistryValue {
    param(
        [Alias("PSPath")]
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [String]$Path
        ,
        [Parameter(Position = 1, Mandatory = $true)]
        [String]$Name
        ,
        [Switch]$PassThru
    ) 

    process {
        $ret = $false
        if (Test-Path $Path) {
            $Key = Get-Item -LiteralPath $Path
            if ($Key.GetValue($Name, $null) -ne $null) {
                if ($PassThru) {
                    Get-ItemProperty $Path $Name
                }
                else {
                    $ret = $true
                }
            } 
        } 
        if ($ret) {
            Write-CustomDebug $Path $Name "Exists"
        }
        else {
            Write-CustomDebug $Path $Name "DOESN'T Exists"
        }
        $ret
    }
}

# --- Preflight checks ---

# Ensure the script runs with elevated privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-CustomError "You do not have Administrator rights to run this script!`nPlease re-run this script as an Administrator!"
    Break
}

# --- Secure boot ---

try {
    $secureBootStatus = Confirm-SecureBootUEFI

    if ($secureBootStatus) {
        Write-CustomInfo "Secure Boot is enabled."
    }
    else {
        Write-CustomWarn "Secure Boot is not enabled or not supported by the system."
    }
}
catch {
    Write-CustomError "Error occurred while checking Secure Boot status: $_"
}

# --- TPM ---

try {
    $tpm = Powershell Get-WmiObject -Namespace root/cimv2/security/microsofttpm -Class Win32_TPM

    if (($tpm | Select-String "IsActivated_InitialValue").line.contains("True")) {
        Write-CustomInfo "TPM is activated."
    }
    else {
        Write-CustomWarn "TPM isn't activated."
    }

    if (($tpm | Select-String "IsEnabled_InitialValue").line.contains("True")) {
        Write-CustomInfo "TPM is enabled."
    }
    else {
        Write-CustomWarn "TPM isn't enabled."
    }

    $reg = ($tpm | Select-String "SpecVersion").ToString() -match "SpecVersion\s+:.(?<tpmVersion>.*)"
    if ($reg) {
        $tpmVersion = $matches["tpmVersion"]
        if ($tpmVersion.contains("2.0")) {
            Write-CustomInfo "TPM Version is $tpmVersion."
        }
        else {
            Write-CustomWarn "TPM Version is $tpmVersion."
        }
    }
}
catch {
    Write-CustomError "Error occurred while checking TPM status: $_"
}

# --- Memory Integrity ---

try {
    $res = Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled"
    if ($res) {
        Write-CustomInfo "Core Isolation is disabled."
    }
    else {
        Write-CustomWarn "Core Isolation is enabled."
    }
}
catch {
    Write-CustomError "Error occurred while checking Core Isolation: $_"
}