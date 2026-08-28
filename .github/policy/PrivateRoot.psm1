Set-StrictMode -Version Latest

function Assert-PolicyNfc {
    param(
        [Parameter(Mandatory)]
        [string] $Value,

        [Parameter(Mandatory)]
        [string] $Label
    )

    $normalized = $Value.Normalize([Text.NormalizationForm]::FormC)
    if (-not [String]::Equals($Value, $normalized, [StringComparison]::Ordinal)) {
        throw "$Label must use Unicode NFC."
    }
}

function Assert-PolicyIdentifier {
    param(
        [Parameter(Mandatory)]
        [string] $Value,

        [Parameter(Mandatory)]
        [string] $Label,

        [Parameter(Mandatory)]
        [string] $Pattern
    )

    Assert-PolicyNfc -Value $Value -Label $Label
    if ($Value -cnotmatch $Pattern) {
        throw "$Label contains unsupported characters."
    }
}

function Assert-PolicyLexicalPath {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Label
    )

    Assert-PolicyNfc -Value $Path -Label $Label
    if ($Path.Contains('/')) {
        throw "$Label must use Windows separators."
    }
    if (
        $Path.StartsWith('\\') -or
        $Path.StartsWith('\??\') -or
        $Path.StartsWith('\\?\') -or
        $Path.StartsWith('\\.\')
    ) {
        throw "$Label cannot be a UNC, device, or extended path."
    }
    if (-not [IO.Path]::IsPathFullyQualified($Path)) {
        throw "$Label must be absolute."
    }

    $root = [IO.Path]::GetPathRoot($Path)
    if ($root -cnotmatch '^[A-Z]:\\$') {
        throw "$Label must use a canonical local drive root."
    }

    $withoutRoot = $Path.Substring($root.Length)
    foreach ($component in $withoutRoot.Split('\', [StringSplitOptions]::RemoveEmptyEntries)) {
        if ($component -in '.', '..') {
            throw "$Label cannot contain dot traversal."
        }
        Assert-PolicyNfc -Value $component -Label "$Label component"
    }

    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if (-not [String]::Equals($full, $Path.TrimEnd('\'), [StringComparison]::Ordinal)) {
        throw "$Label is not lexically canonical."
    }
    return $full
}

function Assert-PolicyExistingDirectory {
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [string] $Label = 'directory'
    )

    $full = Assert-PolicyLexicalPath -Path $Path -Label $Label
    if (-not [IO.Directory]::Exists($full)) {
        throw "$Label does not exist."
    }

    $root = [IO.Path]::GetPathRoot($full)
    $current = $root.TrimEnd('\')
    $remaining = $full.Substring($root.Length)
    foreach ($component in $remaining.Split('\', [StringSplitOptions]::RemoveEmptyEntries)) {
        $children = @(
            Get-ChildItem -LiteralPath "$current\" -Force -ErrorAction Stop |
                Where-Object { $_.Name -ieq $component }
        )
        if ($children.Count -ne 1) {
            throw "$Label has an ambiguous or short-name component."
        }
        if (-not [String]::Equals($children[0].Name, $component, [StringComparison]::Ordinal)) {
            throw "$Label has a noncanonical case or short-name component."
        }
        if (-not $children[0].PSIsContainer) {
            throw "$Label traverses a non-directory component."
        }
        if (($children[0].Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label traverses a reparse point."
        }
        $current = $children[0].FullName.TrimEnd('\')
    }

    if (-not [String]::Equals($current, $full, [StringComparison]::Ordinal)) {
        throw "$Label did not resolve to its exact canonical spelling."
    }
    return $full
}

function Get-PolicyMatrixDigest {
    param(
        [Parameter(Mandatory)]
        [string] $MatrixDiscriminator
    )

    Assert-PolicyNfc -Value $MatrixDiscriminator -Label 'matrix discriminator'
    if ($MatrixDiscriminator.Length -lt 1 -or $MatrixDiscriminator.Length -gt 4096) {
        throw 'matrix discriminator length is invalid.'
    }
    $bytes = [Text.Encoding]::UTF8.GetBytes($MatrixDiscriminator)
    $digest = [Security.Cryptography.SHA256]::HashData($bytes)
    return [Convert]::ToHexString($digest).ToLowerInvariant()
}

function Get-PolicyPrivateRootPath {
    param(
        [Parameter(Mandatory)]
        [string] $RunnerTemp,

        [Parameter(Mandatory)]
        [string] $RepositoryId,

        [Parameter(Mandatory)]
        [string] $RunId,

        [Parameter(Mandatory)]
        [string] $RunAttempt,

        [Parameter(Mandatory)]
        [string] $JobName,

        [Parameter(Mandatory)]
        [string] $MatrixDiscriminator
    )

    $canonicalTemp = Assert-PolicyExistingDirectory -Path $RunnerTemp -Label 'runner.temp'
    Assert-PolicyIdentifier -Value $RepositoryId -Label 'repository id' -Pattern '^[1-9][0-9]{0,19}$'
    Assert-PolicyIdentifier -Value $RunId -Label 'run id' -Pattern '^[1-9][0-9]{0,19}$'
    Assert-PolicyIdentifier -Value $RunAttempt -Label 'run attempt' -Pattern '^[1-9][0-9]{0,9}$'
    Assert-PolicyIdentifier -Value $JobName -Label 'job name' -Pattern '^[A-Za-z_][A-Za-z0-9_-]{0,63}$'
    $matrixDigest = Get-PolicyMatrixDigest -MatrixDiscriminator $MatrixDiscriminator

    return [IO.Path]::Combine(
        $canonicalTemp,
        'copilot-policy',
        "repo-$RepositoryId",
        "run-$RunId",
        "attempt-$RunAttempt",
        "job-$JobName",
        "matrix-$matrixDigest"
    )
}

function New-PolicyPrivateAcl {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $rights = [Security.AccessControl.FileSystemRights]::FullControl
    $identities = @(
        [Security.Principal.WindowsIdentity]::GetCurrent().User,
        [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
        [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    )
    foreach ($identity in $identities) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            $rights,
            $inheritance,
            $propagation,
            $allow
        )
        [void] $acl.AddAccessRule($rule)
    }
    return $acl
}

function Set-PolicyPrivateAcl {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    Set-Acl -LiteralPath $Path -AclObject (New-PolicyPrivateAcl) -ErrorAction Stop
}

function New-PolicyPrivateDirectory {
    <#
        Creates the private root with its protected, non-inherited ACL applied by
        the create call itself. FileSystemAclExtensions::Create passes the
        security descriptor to the underlying CreateDirectory, so the directory
        never exists with inherited permissions -- there is no window in which a
        less privileged principal could open or populate it.

        If the platform does not expose that overload the function falls back to
        create-then-protect and the caller reverifies. That residual window is
        only reachable on a non-Windows or trimmed runtime; the policy job pins
        windows-2025, where the atomic path is always taken.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $acl = New-PolicyPrivateAcl
    $directory = [IO.DirectoryInfo]::new($Path)
    $extensions = [Type]::GetType(
        'System.IO.FileSystemAclExtensions, System.IO.FileSystem.AccessControl'
    )
    $create = $null
    if ($null -ne $extensions) {
        $create = $extensions.GetMethod(
            'Create',
            [Type[]]@([IO.DirectoryInfo], [Security.AccessControl.DirectorySecurity])
        )
    }
    if ($null -eq $create) {
        [void] [IO.Directory]::CreateDirectory($Path)
        Set-PolicyPrivateAcl -Path $Path
        return $false
    }

    [void] $create.Invoke($null, @($directory, $acl))
    if (-not [IO.Directory]::Exists($Path)) {
        throw 'private root was not created atomically.'
    }
    return $true
}

function Assert-PolicyPrivateAcl {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    if (-not $acl.AreAccessRulesProtected) {
        throw 'private root inherits access rules.'
    }
    $expected = [Collections.Generic.HashSet[string]]::new(
        [string[]]@(
            [Security.Principal.WindowsIdentity]::GetCurrent().User.Value,
            'S-1-5-18',
            'S-1-5-32-544'
        ),
        [StringComparer]::Ordinal
    )
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $rules = @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw 'private root carries a non-allow access rule.'
        }
        $identity = $rule.IdentityReference.Value
        if (-not $expected.Contains($identity)) {
            throw 'private root grants an unexpected principal.'
        }
        $full = [Security.AccessControl.FileSystemRights]::FullControl
        if (($rule.FileSystemRights -band $full) -ne $full) {
            throw 'private root grants a principal less than full control.'
        }
        [void] $seen.Add($identity)
    }
    if ($seen.Count -ne $expected.Count) {
        throw 'private root is missing a required principal.'
    }
    if (@($acl.GetAccessRules($false, $true, [Security.Principal.SecurityIdentifier])).Count -ne 0) {
        throw 'private root still resolves inherited access rules.'
    }
}

function New-PolicyPrivateRoot {
    param(
        [Parameter(Mandatory)]
        [string] $RunnerTemp,

        [Parameter(Mandatory)]
        [string] $RepositoryId,

        [Parameter(Mandatory)]
        [string] $RunId,

        [Parameter(Mandatory)]
        [string] $RunAttempt,

        [Parameter(Mandatory)]
        [string] $JobName,

        [Parameter(Mandatory)]
        [string] $MatrixDiscriminator
    )

    $root = Get-PolicyPrivateRootPath @PSBoundParameters
    if ([IO.Directory]::Exists($root) -or [IO.File]::Exists($root)) {
        throw 'private root already exists.'
    }

    $parent = [IO.Path]::GetDirectoryName($root)
    $segments = [Collections.Generic.Stack[string]]::new()
    while (-not [IO.Directory]::Exists($parent)) {
        $segments.Push([IO.Path]::GetFileName($parent))
        $parent = [IO.Path]::GetDirectoryName($parent)
    }
    [void] (Assert-PolicyExistingDirectory -Path $parent -Label 'private root ancestor')
    while ($segments.Count -gt 0) {
        $parent = [IO.Path]::Combine($parent, $segments.Pop())
        [void] [IO.Directory]::CreateDirectory($parent)
        [void] (Assert-PolicyExistingDirectory -Path $parent -Label 'private root ancestor')
    }

    $atomic = New-PolicyPrivateDirectory -Path $root
    if (-not $atomic) {
        Set-PolicyPrivateAcl -Path $root
    }
    $canonicalRoot = Assert-PolicyExistingDirectory -Path $root -Label 'private root'
    Assert-PolicyPrivateAcl -Path $canonicalRoot

    $claim = [IO.Path]::Combine($canonicalRoot, '.policy-root')
    $stream = [IO.File]::Open($claim, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $record = [ordered]@{
            repository_id = $RepositoryId
            run_id = $RunId
            run_attempt = $RunAttempt
            job = $JobName
            matrix_sha256 = Get-PolicyMatrixDigest -MatrixDiscriminator $MatrixDiscriminator
        } | ConvertTo-Json -Compress
        $content = [Text.Encoding]::UTF8.GetBytes($record)
        $stream.Write($content, 0, $content.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }

    return $canonicalRoot
}

function Assert-PolicyBaseCheckout {
    param(
        [Parameter(Mandatory)]
        [string] $Workspace,

        [Parameter(Mandatory)]
        [string] $Repository,

        [Parameter(Mandatory)]
        [string] $ExpectedCommit
    )

    if ($Repository -cnotmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') {
        throw 'repository identity is invalid.'
    }
    if ($ExpectedCommit -cnotmatch '^[0-9a-f]{40}$') {
        throw 'expected base commit is invalid.'
    }
    $canonicalWorkspace = Assert-PolicyExistingDirectory -Path $Workspace -Label 'protected base checkout'

    $actualCommit = (& git -C $canonicalWorkspace rev-parse --verify HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $actualCommit -cne $ExpectedCommit) {
        throw 'protected base checkout HEAD does not match the event base.'
    }
    $actualTree = (& git -C $canonicalWorkspace rev-parse --verify 'HEAD^{tree}').Trim()
    if ($LASTEXITCODE -ne 0 -or $actualTree -cnotmatch '^[0-9a-f]{40}$') {
        throw 'protected base checkout tree is invalid.'
    }
    $origin = (& git -C $canonicalWorkspace remote get-url origin).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw 'protected base checkout has no readable origin.'
    }
    $allowedOrigins = @(
        "https://github.com/$Repository",
        "https://github.com/$Repository.git"
    )
    if ($origin -cnotin $allowedOrigins) {
        throw 'protected base checkout origin is not the bound repository.'
    }
    $porcelain = & git -C $canonicalWorkspace status --porcelain=v2 --untracked-files=all
    if ($LASTEXITCODE -ne 0 -or $porcelain) {
        throw 'protected base checkout is not clean.'
    }
    return $actualTree
}

Export-ModuleMember -Function @(
    'Assert-PolicyLexicalPath',
    'Assert-PolicyExistingDirectory',
    'Assert-PolicyPrivateAcl',
    'Get-PolicyMatrixDigest',
    'Get-PolicyPrivateRootPath',
    'New-PolicyPrivateDirectory',
    'New-PolicyPrivateRoot',
    'Assert-PolicyBaseCheckout'
)
