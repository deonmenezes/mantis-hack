# One-line Mantis installer for Windows (PowerShell 5.1+ / pwsh 7+).
#
#   irm https://raw.githubusercontent.com/deonmenezes/mantishack/main/install.ps1 | iex
#
# Mirrors install.sh: installs Rust toolchain if missing, clones the repo,
# builds `mantis-daemon` + `mantis` with cargo, drops them under
# %USERPROFILE%\.local\bin, wires Mantis as a plugin for any detected AI CLI
# (claude, codex, opencode), and prepends the bin dir to the user PATH.
#
# Env overrides (set before invoking the script):
#   $env:MANTIS_PREFIX       install prefix       (default: $HOME\.local)
#   $env:MANTIS_REPO         git URL              (default: github.com/deonmenezes/mantishack)
#   $env:MANTIS_REF          branch / tag / sha   (default: main)
#   $env:MANTIS_BUILD_DIR    build dir            (default: $env:LOCALAPPDATA\mantis-build)
#   $env:MANTIS_SKIP_RUSTUP  set to 1 to fail instead of auto-installing Rust
#   $env:MANTIS_SKIP_PATH    set to 1 to skip PATH wiring

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

function Write-Log  { param([string]$Msg) Write-Host "[mantis] $Msg" -ForegroundColor Cyan }
function Write-Warn { param([string]$Msg) Write-Host "[mantis] warn: $Msg" -ForegroundColor Yellow }
function Die        { param([string]$Msg) Write-Host "[mantis] error: $Msg" -ForegroundColor Red; exit 1 }

$Prefix    = if ($env:MANTIS_PREFIX)    { $env:MANTIS_PREFIX }    else { Join-Path $HOME ".local" }
$BinDir    = Join-Path $Prefix "bin"
$Repo      = if ($env:MANTIS_REPO)      { $env:MANTIS_REPO }      else { "https://github.com/deonmenezes/mantishack" }
$Ref       = if ($env:MANTIS_REF)       { $env:MANTIS_REF }       else { "main" }
$BuildDir  = if ($env:MANTIS_BUILD_DIR) { $env:MANTIS_BUILD_DIR } else { Join-Path $env:LOCALAPPDATA "mantis-build" }

Write-Log "host: Windows $([System.Environment]::OSVersion.Version) ($($env:PROCESSOR_ARCHITECTURE))"

# 1. Toolchain check ---------------------------------------------------------
$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $HOME ".cargo" }
$cargoBin  = Join-Path $cargoHome "bin"
if ((Test-Path (Join-Path $cargoBin "cargo.exe")) -and ($env:PATH -notlike "*$cargoBin*")) {
    $env:PATH = "$cargoBin;$env:PATH"
}
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    if ($env:MANTIS_SKIP_RUSTUP -eq "1") {
        Die "cargo not found and MANTIS_SKIP_RUSTUP=1. Install Rust from https://rustup.rs and rerun."
    }
    Write-Log "cargo not found — installing Rust toolchain via rustup (non-interactive, minimal profile)"
    $rustupInit = Join-Path $env:TEMP "rustup-init.exe"
    Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $rustupInit -UseBasicParsing
    & $rustupInit -y --default-toolchain stable --profile minimal --no-modify-path
    if (Test-Path (Join-Path $cargoBin "cargo.exe")) {
        $env:PATH = "$cargoBin;$env:PATH"
    }
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Die "rustup install ran but cargo is still not on PATH."
    }
    Write-Log "rustup installed: $(cargo --version)"
}
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Die "git not found. Install git (https://git-scm.com/download/win) and rerun."
}

New-Item -ItemType Directory -Force -Path $BinDir, $BuildDir | Out-Null

# 2. Source checkout ---------------------------------------------------------
if (Test-Path (Join-Path $BuildDir ".git")) {
    Write-Log "updating existing checkout at $BuildDir"
    git -C $BuildDir fetch --depth=1 origin $Ref
    git -C $BuildDir checkout -f FETCH_HEAD
} else {
    Write-Log "cloning $Repo@$Ref -> $BuildDir"
    Remove-Item -Recurse -Force $BuildDir -ErrorAction SilentlyContinue
    git clone --depth=1 --branch $Ref $Repo $BuildDir
}

# 3. Build binaries ----------------------------------------------------------
Write-Log "building mantis-daemon + mantis (release)"
Push-Location $BuildDir
try {
    cargo build --release --bin mantis-daemon --bin mantis
    if ($LASTEXITCODE -ne 0) { Die "cargo build failed (exit $LASTEXITCODE)" }
} finally {
    Pop-Location
}

Copy-Item -Force (Join-Path $BuildDir "target\release\mantis-daemon.exe") (Join-Path $BinDir "mantis-daemon.exe")
Copy-Item -Force (Join-Path $BuildDir "target\release\mantis.exe")        (Join-Path $BinDir "mantis.exe")
Write-Log "installed: $BinDir\mantis-daemon.exe"
Write-Log "installed: $BinDir\mantis.exe"

# 4. AI-CLI plugin installation ---------------------------------------------
$PluginSource = Join-Path $BuildDir "plugin"
$InstalledFor = @()

function Install-Plugin {
    param([string]$Name, [string]$Source, [string]$Target, [string]$Probe)
    if (-not (Get-Command $Probe -ErrorAction SilentlyContinue) -and -not (Test-Path (Split-Path $Target))) {
        return
    }
    if (Test-Path $Target) { Remove-Item -Recurse -Force $Target }
    New-Item -ItemType Directory -Force -Path (Split-Path $Target) | Out-Null
    Copy-Item -Recurse -Force $Source $Target
    Write-Log "installed plugin for $Name at $Target"
    $script:InstalledFor += $Name
}

Install-Plugin -Name "claude-code" -Source (Join-Path $PluginSource "claude-code") -Target (Join-Path $HOME ".claude\plugins\mantis")    -Probe "claude"
Install-Plugin -Name "codex"       -Source (Join-Path $PluginSource "codex")       -Target (Join-Path $HOME ".codex\plugins\mantis")     -Probe "codex"
Install-Plugin -Name "opencode"    -Source (Join-Path $PluginSource "opencode")    -Target (Join-Path $env:APPDATA "opencode\plugins\mantis") -Probe "opencode"

# 5. PATH wiring -------------------------------------------------------------
if ($env:MANTIS_SKIP_PATH -ne "1") {
    $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($null -eq $userPath) { $userPath = "" }
    $segments = $userPath -split ";" | Where-Object { $_ -ne "" }
    if ($segments -notcontains $BinDir) {
        $newPath = (@($BinDir) + $segments) -join ";"
        [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
        Write-Log "added $BinDir to user PATH (open a new terminal to pick it up)"
    }
}
if (($env:PATH -split ";") -notcontains $BinDir) {
    $env:PATH = "$BinDir;$env:PATH"
}

# 6. Summary -----------------------------------------------------------------
Write-Log "done."
if ($InstalledFor.Count -gt 0) {
    Write-Log "AI CLIs configured: $($InstalledFor -join ', ')"
    Write-Log "try:    mantis daemon   # start the daemon"
    Write-Log "or in your AI CLI:    /mantis-scan <target>"
} else {
    Write-Warn "no claude/codex/opencode CLI detected — the binaries are installed but no plugin was wired."
    Write-Warn "install the CLI you want and rerun this script."
}
