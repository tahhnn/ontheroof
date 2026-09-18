<#
.SYNOPSIS
  Cai Wazuh agent 4.9.2 len may Windows theo muc 4.3.2 cua docs/bao-cao-trien-khai.md.

.DESCRIPTION
  Tai goi MSI (hoac dung file co san), cai im lang kem dia chi manager,
  khoi dong dich vu WazuhSvc va kiem tra ket noi ve manager.
  Phai chay PowerShell voi quyen Administrator.

.EXAMPLE
  .\install-agent-windows.ps1 -Manager 192.168.1.10 -AgentName pc-ketoan

.EXAMPLE
  # Cai offline tu goi MSI da copy san
  .\install-agent-windows.ps1 -Manager 192.168.1.10 -MsiPath C:\temp\wazuh-agent.msi
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, HelpMessage = 'IP may chu Wazuh trong mang noi bo, vi du 192.168.1.10')]
  [string]$Manager,

  [string]$AgentName = $env:COMPUTERNAME,

  [string]$AgentGroup = 'default',

  # Duong dan goi MSI co san (cai offline); bo trong thi tu tai tu kho Wazuh
  [string]$MsiPath = ''
)

$ErrorActionPreference = 'Stop'
$WazuhVersion = '4.9.2-1'
$MsiUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WazuhVersion.msi"
$AgentDir = "${env:ProgramFiles(x86)}\ossec-agent"

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }

# Bat buoc quyen Administrator (msiexec va NET START can quyen nay)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  Write-Error 'Phai chay PowerShell voi quyen Administrator.'
  exit 1
}

# Tai goi MSI neu chua co
if ([string]::IsNullOrEmpty($MsiPath)) {
  $MsiPath = Join-Path $env:TEMP 'wazuh-agent.msi'
  if (-not (Test-Path $MsiPath)) {
    Write-Step "Tai goi cai dat: $MsiUrl"
    try {
      Invoke-WebRequest -Uri $MsiUrl -OutFile $MsiPath -UseBasicParsing
    } catch {
      Write-Error "Tai that bai ($($_.Exception.Message)). May khong co Internet? Copy MSI sang va dung -MsiPath."
      exit 1
    }
  }
}
if (-not (Test-Path $MsiPath)) {
  Write-Error "Khong tim thay file MSI: $MsiPath"
  exit 1
}

# Cai im lang — cac property WAZUH_* duoc installer ghi thang vao ossec.conf
Write-Step "Cai agent (manager=$Manager, name=$AgentName, group=$AgentGroup)"
$msiArgs = @(
  '/i', "`"$MsiPath`"", '/q',
  "WAZUH_MANAGER=`"$Manager`"",
  "WAZUH_AGENT_NAME=`"$AgentName`"",
  "WAZUH_AGENT_GROUP=`"$AgentGroup`""
)
$proc = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
if ($proc.ExitCode -ne 0) {
  Write-Error "msiexec tra ve ma loi $($proc.ExitCode). Xem log: msiexec /i ... /l*v install.log"
  exit 1
}

# Khoi dong dich vu
Write-Step 'Khoi dong dich vu WazuhSvc'
Start-Service -Name WazuhSvc
Set-Service -Name WazuhSvc -StartupType Automatic

# Kiem tra ket noi (cho toi 30 giay)
Write-Step "Kiem tra ket noi ve manager $Manager (cong 1514/tcp)"
$ossecLog = Join-Path $AgentDir 'ossec.log'
$connected = $false
for ($i = 0; $i -lt 6; $i++) {
  if ((Test-Path $ossecLog) -and (Select-String -Path $ossecLog -Pattern 'Connected to the server' -Quiet)) {
    $connected = $true
    break
  }
  Start-Sleep -Seconds 5
}

& (Join-Path $AgentDir 'bin\wazuh-control.exe') status

if ($connected) {
  Write-Host "`nOK: agent da ket noi manager." -ForegroundColor Green
  Write-Host 'Xac nhan phia manager:'
  Write-Host '  docker exec siem-raw-wazuh.manager-1 /var/ossec/bin/agent_control -l'
  exit 0
} else {
  Write-Warning "CHUA thay dong 'Connected to the server' trong $ossecLog."
  Write-Warning 'Kiem tra: manager da mo cong 1514/tcp va 1515/tcp chua? IP dung chua? Firewall Windows chan outbound?'
  exit 1
}
