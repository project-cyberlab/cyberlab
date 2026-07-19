# ============================================================================
# LAB-WINDOWS provisioner
#
# DECISION (user, 2026-07-19): the LAB-WINDOWS base image is the DFIR project's
# Packer-built VM — **Windows 10 Enterprise (Evaluation)**, from project-dfir/dfir-vm.
# Reuse that Packer pipeline (license-clean: downloads the free MS eval ISO at build,
# never redistributes Windows) and SWAP the provisioning step: DFIR toolset -> FLARE-VM.
# Same lean, reproducible base image; different toolset.
#
# TODO (provisioning-step build, not yet wired):
#   1. Pull DFIR's packer/ template from project-dfir/dfir-vm (Win10 Enterprise Eval base, unchanged).
#   2. Replace the DFIR tool-provisioner with the FLARE-VM install.ps1 step (below).
#   3. Emit a one-liner Packer build -> VMware .vmx + .vmdk, offline-by-design finished VM.
#
# INTERIM (manual): run the FLARE install on an existing clean Win10 Enterprise Eval VM.
# ============================================================================
$ErrorActionPreference = "Stop"
Write-Host "[lab-windows] INTERIM: FLARE-VM onto a clean Windows 10 Enterprise Eval VM."
Write-Host "[lab-windows] (Target end-state: DFIR Packer base image + FLARE provisioner — see header.)"
$dst = "$env:USERPROFILE\Desktop\flare-install.ps1"
(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1', $dst)
Unblock-File $dst
Set-ExecutionPolicy Unrestricted -Scope CurrentUser -Force
Write-Host "[lab-windows] installing default 136-package FLARE profile (Chocolatey)..."
& $dst
Write-Host "[lab-windows] done. Capture: choco list | Out-File installed.txt"
