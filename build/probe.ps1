$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
Write-Output ("ELEVATED: " + $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
$p = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue
if ($null -ne $p) { Write-Output ("RunAsPPL: " + $p.RunAsPPL) } else { Write-Output 'RunAsPPL: (not set)' }
$edge = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge' -ErrorAction SilentlyContinue
if ($edge) { Write-Output ("Edge: " + $edge.DisplayVersion) }
$chrome = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome' -ErrorAction SilentlyContinue
if ($chrome) { Write-Output ("Chrome: " + $chrome.DisplayVersion) }
