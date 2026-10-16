$keys = @(
  'HKLM:\SOFTWARE\Classes\CLSID\{70886030-AD97-4F55-BCEE-0975ABC7490E}',
  'HKLM:\SOFTWARE\Classes\CLSID\{708860E0-F641-4611-8895-7D867DD3675B}',
  'HKLM:\SOFTWARE\Classes\CLSID\{1FCBE96C-1697-43AF-9140-2897C7C69767}',
  'HKLM:\SOFTWARE\Classes\CLSID\{576B31AF-6369-4B6B-8560-E4B203A97A8B}'
)
foreach ($k in $keys) {
  if (Test-Path $k) {
    $name = (Get-Item $k).GetValue('')
    Write-Output ("FOUND: " + $k + " => " + $name)
  } else {
    Write-Output ("MISSING: " + $k)
  }
}
# Also check LocalServer32 for elevation service
foreach ($k in $keys) {
  $ls = $k + '\LocalServer32'
  if (Test-Path $ls) {
    Write-Output ("  LocalServer32: " + (Get-Item $ls).GetValue(''))
  }
}
