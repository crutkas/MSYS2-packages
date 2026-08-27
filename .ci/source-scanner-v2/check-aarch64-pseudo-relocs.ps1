[CmdletBinding(DefaultParameterSetName = 'Pe')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Pe')]
    [string] $PePath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Table')]
    [string] $TablePath,

    [Parameter(Mandatory = $true)]
    [string] $OutputPath,

    [Parameter(ParameterSetName = 'Pe')]
    [string] $Objdump = 'aarch64-pc-cygwin-objdump.exe',

    [Parameter(ParameterSetName = 'Pe')]
    [string] $Nm = 'aarch64-pc-cygwin-nm.exe'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$allowedFlags = @(8, 16, 32, 64)
$rejectedFlags = @(12, 21)
$findings = [ordered]@{
    schema = 1
    input_kind = $PSCmdlet.ParameterSetName.ToLowerInvariant()
    input_path = $null
    table_present = $false
    table_start_va = $null
    table_end_va = $null
    byte_length = 0
    header = $null
    record_count = 0
    flags = @()
    records = @()
    allowed_flags = $allowedFlags
    rejected_flags = $rejectedFlags
    policy_violations = @()
    result = 'error'
    error = $null
}

function Write-Findings {
    $parent = Split-Path -Parent $OutputPath
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $findings | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding utf8
}

function Resolve-Tool {
    param([Parameter(Mandatory = $true)][string] $Name)

    if (Test-Path -LiteralPath $Name -PathType Leaf) {
        return (Resolve-Path -LiteralPath $Name).Path
    }
    $command = Get-Command $Name -CommandType Application -ErrorAction Stop
    return $command.Source
}

function Invoke-Tool {
    param(
        [Parameter(Mandatory = $true)][string] $FilePath,
        [Parameter(Mandatory = $true)][string[]] $Arguments
    )

    $output = @(& $FilePath @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE`: $($output -join [Environment]::NewLine)"
    }
    return @($output | ForEach-Object { $_.ToString() })
}

function Convert-HexUInt64 {
    param([Parameter(Mandatory = $true)][string] $Value)
    return [Convert]::ToUInt64(($Value -replace '^0x', ''), 16)
}

function Read-Table {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]] $Bytes
    )

    if ($Bytes.Length -eq 0) {
        return [ordered]@{
            header = $null
            records = @()
        }
    }
    if ($Bytes.Length -lt 12) {
        throw "Pseudo-reloc table is shorter than the 12-byte v2 header: $($Bytes.Length)"
    }
    if ((($Bytes.Length - 12) % 12) -ne 0) {
        throw "Pseudo-reloc table length is not header plus 12-byte records: $($Bytes.Length)"
    }

    $magic1 = [BitConverter]::ToUInt32($Bytes, 0)
    $magic2 = [BitConverter]::ToUInt32($Bytes, 4)
    $version = [BitConverter]::ToUInt32($Bytes, 8)
    if ($magic1 -ne 0 -or $magic2 -ne 0 -or $version -ne 1) {
        throw "Invalid pseudo-reloc v2 header: magic1=$magic1 magic2=$magic2 version=$version"
    }

    $records = @()
    for ($offset = 12; $offset -lt $Bytes.Length; $offset += 12) {
        $records += [ordered]@{
            index = (($offset - 12) / 12) + 1
            sym_rva = [BitConverter]::ToUInt32($Bytes, $offset)
            target_rva = [BitConverter]::ToUInt32($Bytes, $offset + 4)
            flags = [BitConverter]::ToUInt32($Bytes, $offset + 8)
        }
    }
    return [ordered]@{
        header = [ordered]@{
            magic1 = $magic1
            magic2 = $magic2
            version = $version
        }
        records = $records
    }
}

try {
    [byte[]] $tableBytes = @()

    if ($PSCmdlet.ParameterSetName -eq 'Table') {
        $resolved = (Resolve-Path -LiteralPath $TablePath).Path
        $findings.input_path = $resolved
        $tableBytes = [IO.File]::ReadAllBytes($resolved)
        $findings.table_present = $true
        $findings.byte_length = $tableBytes.Length
    }
    else {
        $resolved = (Resolve-Path -LiteralPath $PePath).Path
        $findings.input_path = $resolved
        $objdumpPath = Resolve-Tool -Name $Objdump
        $nmPath = Resolve-Tool -Name $Nm

        $fileOutput = Invoke-Tool -FilePath $objdumpPath -Arguments @('-f', $resolved)
        if ($fileOutput -notcontains "$resolved`:     file format pei-aarch64-little" -and
            -not ($fileOutput -match 'file format pei-aarch64-little')) {
            throw 'Input is not a pei-aarch64-little image'
        }
        if (-not ($fileOutput -match 'architecture: aarch64')) {
            throw 'Input does not report AArch64 architecture'
        }

        $nmOutput = Invoke-Tool -FilePath $nmPath -Arguments @('-an', $resolved)
        $startLines = @($nmOutput | Where-Object { $_ -match '\s__RUNTIME_PSEUDO_RELOC_LIST__$' })
        $endLines = @($nmOutput | Where-Object { $_ -match '\s__RUNTIME_PSEUDO_RELOC_LIST_END__$' })

        if ($startLines.Count -eq 0 -and $endLines.Count -eq 0) {
            $findings.result = 'pass'
            Write-Findings
            exit 0
        }
        if ($startLines.Count -ne 1 -or $endLines.Count -ne 1) {
            throw "Expected exactly one pseudo-reloc start/end symbol, got $($startLines.Count)/$($endLines.Count)"
        }

        $start = Convert-HexUInt64 -Value (($startLines[0] -split '\s+')[0])
        $end = Convert-HexUInt64 -Value (($endLines[0] -split '\s+')[0])
        if ($end -lt $start) {
            throw "Pseudo-reloc end precedes start: 0x$($end.ToString('x')) < 0x$($start.ToString('x'))"
        }

        $sections = Invoke-Tool -FilePath $objdumpPath -Arguments @('-h', $resolved)
        $containing = @()
        foreach ($line in $sections) {
            if ($line -notmatch '^\s*\d+\s+(?<name>\S+)\s+(?<size>[0-9a-fA-F]+)\s+(?<vma>[0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+(?<offset>[0-9a-fA-F]+)') {
                continue
            }
            $sectionVma = Convert-HexUInt64 -Value $Matches.vma
            $sectionSize = Convert-HexUInt64 -Value $Matches.size
            $sectionEnd = $sectionVma + $sectionSize
            if ($start -ge $sectionVma -and $end -le $sectionEnd) {
                $containing += [ordered]@{
                    name = $Matches.name
                    vma = $sectionVma
                    size = $sectionSize
                    file_offset = Convert-HexUInt64 -Value $Matches.offset
                }
            }
        }
        if ($containing.Count -ne 1) {
            throw "Expected one section containing the pseudo-reloc range, got $($containing.Count)"
        }

        $section = $containing[0]
        $tableLength = $end - $start
        if ($tableLength -gt [int]::MaxValue) {
            throw "Pseudo-reloc table is too large: $tableLength"
        }
        $fileOffset = $section.file_offset + ($start - $section.vma)
        $fileBytes = [IO.File]::ReadAllBytes($resolved)
        if ($fileOffset -gt $fileBytes.Length -or
            $tableLength -gt ($fileBytes.Length - $fileOffset)) {
            throw "Pseudo-reloc range exceeds the PE file: offset=$fileOffset length=$tableLength file=$($fileBytes.Length)"
        }

        $tableBytes = [byte[]]::new([int] $tableLength)
        [Array]::Copy($fileBytes, [int64] $fileOffset, $tableBytes, 0, [int] $tableLength)
        $findings.table_present = $true
        $findings.table_start_va = '0x{0:x16}' -f $start
        $findings.table_end_va = '0x{0:x16}' -f $end
        $findings.byte_length = $tableBytes.Length
    }

    $decoded = Read-Table -Bytes $tableBytes
    $records = @($decoded.records)
    $flags = @($records | ForEach-Object { $_.flags })
    $violations = @(
        $flags |
            Where-Object { $_ -notin $allowedFlags } |
            Sort-Object -Unique
    )

    $findings.header = $decoded.header
    $findings.records = $records
    $findings.record_count = $records.Count
    $findings.flags = $flags
    $findings.policy_violations = $violations
    $findings.result = if ($violations.Count -eq 0) { 'pass' } else { 'fail' }
    Write-Findings

    if ($violations.Count -ne 0) {
        [Console]::Error.WriteLine("Rejected pseudo-reloc flags: $($violations -join ',')")
        exit 1
    }
    exit 0
}
catch {
    $findings.result = 'error'
    $findings.error = $_.Exception.Message
    Write-Findings
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 2
}
