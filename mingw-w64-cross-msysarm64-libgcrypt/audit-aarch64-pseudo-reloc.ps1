[CmdletBinding()]
param(
  [Parameter(Mandatory, Position = 0)]
  [string] $Image,

  [string] $Nm = "aarch64-w64-mingw32-nm.exe",
  [string] $Objdump = "aarch64-w64-mingw32-objdump.exe",
  [string] $Objcopy = "aarch64-w64-mingw32-objcopy.exe"
)

$ErrorActionPreference = "Stop"

function Fail-Malformed([string] $Message) {
  [Console]::Error.WriteLine("MALFORMED $Message")
  exit 2
}

function Get-Sha256([byte[]] $Bytes) {
  $sha = [Security.Cryptography.SHA256]::Create()
  try {
    return ([Convert]::ToHexString($sha.ComputeHash($Bytes))).ToLowerInvariant()
  }
  finally {
    $sha.Dispose()
  }
}

try {
  $imagePath = (Resolve-Path -LiteralPath $Image).Path
  foreach ($tool in @($Nm, $Objdump, $Objcopy)) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
      Fail-Malformed "tool-not-found=$tool"
    }
  }

  $symbols = @{}
  & $Nm -n $imagePath 2>&1 | ForEach-Object {
    if ($_ -match "^\s*([0-9a-fA-F]+)\s+\S+\s+(__RUNTIME_PSEUDO_RELOC_LIST(?:_END)?__)\s*$") {
      $symbols[$Matches[2]] = [Convert]::ToUInt64($Matches[1], 16)
    }
  }
  if ($LASTEXITCODE -ne 0) {
    Fail-Malformed "nm-exit=$LASTEXITCODE"
  }

  $startName = "__RUNTIME_PSEUDO_RELOC_LIST__"
  $endName = "__RUNTIME_PSEUDO_RELOC_LIST_END__"
  if (-not $symbols.ContainsKey($startName) -or -not $symbols.ContainsKey($endName)) {
    Fail-Malformed "missing-list-symbols; audit the unstripped image before packaging"
  }

  [UInt64] $start = $symbols[$startName]
  [UInt64] $end = $symbols[$endName]
  if ($end -lt $start) {
    Fail-Malformed ("negative-table-range start=0x{0:x} end=0x{1:x}" -f $start, $end)
  }

  $section = $null
  [UInt64] $sectionVma = 0
  [UInt64] $sectionSize = 0
  & $Objdump -h $imagePath 2>&1 | ForEach-Object {
    if ($_ -match "^\s*\d+\s+(\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+") {
      [UInt64] $size = [Convert]::ToUInt64($Matches[2], 16)
      [UInt64] $vma = [Convert]::ToUInt64($Matches[3], 16)
      if ($start -ge $vma -and $end -le ($vma + $size)) {
        $section = $Matches[1]
        $sectionVma = $vma
        $sectionSize = $size
      }
    }
  }
  if ($LASTEXITCODE -ne 0) {
    Fail-Malformed "objdump-exit=$LASTEXITCODE"
  }
  if (-not $section) {
    Fail-Malformed ("table-not-contained-in-one-section start=0x{0:x} end=0x{1:x}" -f $start, $end)
  }

  $temp = Join-Path ([IO.Path]::GetTempPath()) ("pseudo-reloc-" + [Guid]::NewGuid() + ".bin")
  try {
    & $Objcopy "--dump-section=$section=$temp" $imagePath 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $temp)) {
      Fail-Malformed "objcopy-exit=$LASTEXITCODE section=$section"
    }

    [byte[]] $sectionBytes = [IO.File]::ReadAllBytes($temp)
    [UInt64] $offset = $start - $sectionVma
    [UInt64] $length = $end - $start
    if ($offset + $length -gt $sectionBytes.LongLength -or $offset + $length -gt $sectionSize) {
      Fail-Malformed "table-range-outside-dumped-section"
    }

    [byte[]] $table = [byte[]]::new([int] $length)
    if ($length -ne 0) {
      [Array]::Copy($sectionBytes, [int] $offset, $table, 0, [int] $length)
    }
  }
  finally {
    Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
  }

  $imageHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $imagePath).Hash.ToLowerInvariant()
  $tableHash = Get-Sha256 $table

  if ($table.Length -eq 0) {
    "PASS image_sha256=$imageHash table_sha256=$tableHash records=0 ambiguous=0"
    exit 0
  }
  if ($table.Length -lt 12 -or (($table.Length - 12) % 12) -ne 0) {
    Fail-Malformed "invalid-v2-size=$($table.Length)"
  }

  $magic1 = [BitConverter]::ToUInt32($table, 0)
  $magic2 = [BitConverter]::ToUInt32($table, 4)
  $version = [BitConverter]::ToUInt32($table, 8)
  if ($magic1 -ne 0 -or $magic2 -ne 0 -or $version -ne 1) {
    Fail-Malformed ("invalid-v2-header={0:x8},{1:x8},{2:x8}" -f $magic1, $magic2, $version)
  }

  $recordCount = ($table.Length - 12) / 12
  $ambiguous = 0
  for ($index = 0; $index -lt $recordCount; $index++) {
    $recordOffset = 12 + 12 * $index
    $sym = [BitConverter]::ToUInt32($table, $recordOffset)
    $target = [BitConverter]::ToUInt32($table, $recordOffset + 4)
    $flags = [BitConverter]::ToUInt32($table, $recordOffset + 8)
    $bitSize = $flags -band 0xff
    if ($bitSize -eq 12 -or $bitSize -eq 21) {
      $ambiguous++
      "AMBIGUOUS index=$($index + 1) sym=0x$($sym.ToString("x8")) target=0x$($target.ToString("x8")) flags=0x$($flags.ToString("x8")) bits=$bitSize"
    }
  }

  if ($ambiguous -ne 0) {
    "FAIL image_sha256=$imageHash table_sha256=$tableHash records=$recordCount ambiguous=$ambiguous"
    exit 1
  }

  "PASS image_sha256=$imageHash table_sha256=$tableHash records=$recordCount ambiguous=0"
  exit 0
}
catch {
  Fail-Malformed $_.Exception.Message
}
