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
    $self = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.SetOwner($self)
    $acl.SetGroup($self)
    $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $rights = [Security.AccessControl.FileSystemRights]::FullControl
    $identities = @(
        $self,
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

function Get-PolicyExpectedPrincipal {
    return @(
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value,
        'S-1-5-18',
        'S-1-5-32-544'
    )
}

function Assert-PolicyPrivateDacl {
    <#
        DACL-only checks, usable before the directory is published. Verifies the
        descriptor really landed: protected (non-inherited), owned by the policy
        identity, exactly the expected principals with FullControl, the required
        inheritance so children are covered, no non-Allow ACE, and no inherited
        ACE resolving from an ancestor.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    if (-not $acl.AreAccessRulesProtected) {
        throw 'private root inherits access rules.'
    }

    $expected = Get-PolicyExpectedPrincipal
    $self = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value

    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier])
    if ($null -eq $owner -or $owner.Value -cne $self) {
        throw 'private root is not owned by the policy identity.'
    }
    $group = $acl.GetGroup([Security.Principal.SecurityIdentifier])
    if ($null -ne $group -and $expected -notcontains $group.Value) {
        throw 'private root primary group is not a policy principal.'
    }

    $full_control = [Security.AccessControl.FileSystemRights]::FullControl
    $required_inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $rules = @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw 'private root carries a non-allow access rule.'
        }
        $who = $rule.IdentityReference.Value
        if ($expected -notcontains $who) {
            throw 'private root grants an unexpected principal.'
        }
        if (($rule.FileSystemRights -band $full_control) -ne $full_control) {
            throw 'private root grants a principal less than full control.'
        }
        if (($rule.InheritanceFlags -band $required_inheritance) -ne $required_inheritance) {
            throw 'private root access rule does not propagate to children.'
        }
        if ($rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
            throw 'private root access rule uses unexpected propagation.'
        }
        [void] $seen.Add($who)
    }
    if ($seen.Count -ne $expected.Count) {
        throw 'private root is missing a required principal.'
    }
    if (@($acl.GetAccessRules($false, $true, [Security.Principal.SecurityIdentifier])).Count -ne 0) {
        throw 'private root still resolves inherited access rules.'
    }
}

function Get-PolicyDirectoryIdentity {
    <#
        Stable identity for the private root.

        Volume identity is the NTFS volume serial number read from the storage
        layer, not a path string. Object identity is a 256-bit secret nonce
        written inside the root at creation time under an owner-only DACL.

        A 128-bit NTFS file id would require CreateFile with
        FILE_FLAG_BACKUP_SEMANTICS plus GetFileInformationByHandle, which .NET
        does not surface without P/Invoke; the only way to reach it from
        PowerShell is runtime type compilation, which is precisely the dynamic
        surface this policy forbids elsewhere. The nonce is used instead and is
        strictly stronger against the replacement threat: NTFS file ids can be
        reused after deletion, whereas a 256-bit secret cannot be reproduced by
        an attacker who did not read it. The residual is stated in README.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [string] $Nonce = ''
    )

    $info = [IO.DirectoryInfo]::new($Path)
    $info.Refresh()
    if (-not $info.Exists) {
        throw 'private root does not exist.'
    }
    if (($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'private root is a reparse point.'
    }
    if ($null -ne [IO.Directory]::ResolveLinkTarget($Path, $true)) {
        throw 'private root resolves through a link.'
    }

    $drive = ([IO.Path]::GetPathRoot($info.FullName)).TrimEnd('\')
    $volume = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$drive'" -ErrorAction Stop
    $serial = $volume.VolumeSerialNumber
    if ([string]::IsNullOrWhiteSpace($serial)) {
        throw 'private root volume serial is unavailable.'
    }

    return [pscustomobject]@{
        VolumeSerial = $serial
        Nonce = $Nonce
        FullName = $info.FullName
    }
}

function Assert-PolicyPrivateAcl {
    <#
        Full reverification: canonical existing directory, no reparse point or
        link, matching volume serial, matching secret nonce, and the protected
        DACL. Existence is never treated as success.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [string] $ExpectedVolumeSerial = '',

        [string] $ExpectedNonce = ''
    )

    $full = Assert-PolicyExistingDirectory -Path $Path -Label 'private root'
    $identity = Get-PolicyDirectoryIdentity -Path $full

    if ($ExpectedVolumeSerial -ne '' -and $identity.VolumeSerial -cne $ExpectedVolumeSerial) {
        throw 'private root moved to a different volume.'
    }
    if ($ExpectedNonce -ne '') {
        $claim = [IO.Path]::Combine($full, '.policy-root')
        if (-not [IO.File]::Exists($claim)) {
            throw 'private root claim is absent.'
        }
        $record = [IO.File]::ReadAllText($claim) | ConvertFrom-Json
        if ($null -eq $record.nonce -or ($record.nonce -cne $ExpectedNonce)) {
            throw 'private root was replaced by a different directory object.'
        }
        $identity.Nonce = $record.nonce
    }

    Assert-PolicyPrivateDacl -Path $full
    return $identity
}

function New-PolicyPrivateDirectory {
    <#
        Creates a directory that is genuinely exclusive AND protected from the
        instant it becomes reachable at its final name.

        FileSystemAclExtensions::Create is NOT exclusive: when the target
        already exists it neither throws nor applies the security descriptor, so
        an attacker-planted directory with a permissive ACL would survive
        untouched. A check-then-create guard around it is also racy.

        So the directory is created under an unguessable staging name -- where
        the descriptor genuinely is applied because the path is fresh -- the
        descriptor is proven to have landed, and only then is it published with
        Directory.Move, which fails if the destination already exists. The
        rename is the exclusivity primitive.

        If the ACL-at-create API is unavailable this FAILS CLOSED. There is no
        create-then-protect fallback.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $parent = [IO.Path]::GetDirectoryName($Path)
    if ([string]::IsNullOrEmpty($parent) -or -not [IO.Directory]::Exists($parent)) {
        throw 'private root parent does not exist.'
    }

    $extensions = [Type]::GetType(
        'System.IO.FileSystemAclExtensions, System.IO.FileSystem.AccessControl'
    )
    if ($null -eq $extensions) {
        throw 'ACL-at-create API is unavailable; refusing to create the private root.'
    }
    $create = $extensions.GetMethod(
        'Create',
        [Type[]]@([IO.DirectoryInfo], [Security.AccessControl.DirectorySecurity])
    )
    if ($null -eq $create) {
        throw 'ACL-at-create overload is unavailable; refusing to create the private root.'
    }

    $staging = [IO.Path]::Combine(
        $parent,
        ('.policy-staging-' + [Guid]::NewGuid().ToString('N'))
    )
    if ([IO.Directory]::Exists($staging) -or [IO.File]::Exists($staging)) {
        throw 'private root staging path already exists.'
    }

    [void] $create.Invoke($null, @([IO.DirectoryInfo]::new($staging), (New-PolicyPrivateAcl)))
    try {
        $staged = [IO.DirectoryInfo]::new($staging)
        $staged.Refresh()
        if (-not $staged.Exists) {
            throw 'private root staging directory was not created.'
        }
        if (($staged.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'private root staging directory is a reparse point.'
        }
        # Prove the descriptor landed before the name becomes reachable.
        Assert-PolicyPrivateDacl -Path $staging

        # Fails if $Path already exists: this is the exclusive publication.
        [IO.Directory]::Move($staging, $Path)
    }
    catch {
        if ([IO.Directory]::Exists($staging)) {
            [IO.Directory]::Delete($staging, $true)
        }
        throw
    }

    $published = [IO.DirectoryInfo]::new($Path)
    $published.Refresh()
    if (-not $published.Exists) {
        throw 'private root was not published.'
    }
    if (($published.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'private root resolved to a reparse point.'
    }
    Assert-PolicyPrivateDacl -Path $Path
    return $true
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

    # Intermediates are created with the same protected ACL, so no ancestor we
    # create is ever writable by another principal. Each one is created
    # exclusively: if it already exists we require it to be a canonical, real
    # directory (not a reparse point or an attacker-planted alias) before we
    # descend, and we never treat mere existence as success.
    $parent = [IO.Path]::GetDirectoryName($root)
    $segments = [Collections.Generic.Stack[string]]::new()
    while (-not [IO.Directory]::Exists($parent)) {
        $segments.Push([IO.Path]::GetFileName($parent))
        $parent = [IO.Path]::GetDirectoryName($parent)
    }
    [void] (Assert-PolicyExistingDirectory -Path $parent -Label 'private root ancestor')
    while ($segments.Count -gt 0) {
        $parent = [IO.Path]::Combine($parent, $segments.Pop())
        if ([IO.File]::Exists($parent)) {
            throw 'private root ancestor is a file.'
        }
        if ([IO.Directory]::Exists($parent)) {
            throw 'private root ancestor already exists.'
        }
        [void] (New-PolicyPrivateDirectory -Path $parent)
        [void] (Assert-PolicyExistingDirectory -Path $parent -Label 'private root ancestor')
        [void] (Assert-PolicyPrivateAcl -Path $parent)
    }

    [void] (New-PolicyPrivateDirectory -Path $root)
    $canonicalRoot = Assert-PolicyExistingDirectory -Path $root -Label 'private root'
    $identity = Assert-PolicyPrivateAcl -Path $canonicalRoot
    $nonceBytes = [byte[]]::new(32)
    [Security.Cryptography.RandomNumberGenerator]::Fill($nonceBytes)
    $nonce = [Convert]::ToHexString($nonceBytes).ToLowerInvariant()

    $claim = [IO.Path]::Combine($canonicalRoot, '.policy-root')
    $stream = [IO.File]::Open($claim, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $record = [ordered]@{
            repository_id = $RepositoryId
            run_id = $RunId
            run_attempt = $RunAttempt
            job = $JobName
            matrix_sha256 = Get-PolicyMatrixDigest -MatrixDiscriminator $MatrixDiscriminator
            nonce = $nonce
        } | ConvertTo-Json -Compress
        $content = [Text.Encoding]::UTF8.GetBytes($record)
        $stream.Write($content, 0, $content.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }

    [void] (
        Assert-PolicyPrivateAcl `
            -Path $canonicalRoot `
            -ExpectedVolumeSerial $identity.VolumeSerial `
            -ExpectedNonce $nonce
    )
    return $canonicalRoot
}

$script:PolicyTrustedGitImages = @(
    'C:\Program Files\Git\cmd\git.exe',
    'C:\Program Files\Git\bin\git.exe',
    'C:\Program Files (x86)\Git\cmd\git.exe',
    'C:\Program Files (x86)\Git\bin\git.exe'
)

function Get-PolicyGitImage {
    <#
        Resolves the one trusted Git image from a fixed allowlist. There is no
        environment or parameter override: an unqualified git invocation would
        resolve through
        PATH, PATHEXT, a PowerShell alias or function, or an ambient shim, and a
        planted stub can forge origin, HEAD, tree, and cleanliness -- the exact
        answers this module exists to verify.
    #>
    foreach ($candidate in $script:PolicyTrustedGitImages) {
        # A UNC path routes image resolution through the network redirector, so
        # the trusted image would be whatever a remote server serves; an
        # extended-length or device prefix bypasses path normalisation. Both
        # resolve to themselves, so resolving-to-itself alone is NOT sufficient
        # canonicality -- a drive-letter root is required.
        $normalized = $candidate.Replace('/', '\')
        # A single drive-letter root check. It subsumes separate UNC and
        # doubled-separator tests -- \\server\share, \\?\ and \\.\ all fail this
        # pattern -- so no second guard is carried. A guard that cannot be
        # killed on its own is decoration, not protection.
        if ($normalized -cnotmatch '^[A-Za-z]:\\(?!\\)') { continue }
        if (-not [IO.Path]::IsPathFullyQualified($candidate)) { continue }
        if (-not [IO.File]::Exists($candidate)) { continue }
        $info = [IO.FileInfo]::new($candidate)
        if (($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
        if ($null -ne [IO.File]::ResolveLinkTarget($candidate, $true)) { continue }
        if (-not [String]::Equals(
                [IO.Path]::GetFullPath($candidate),
                $candidate,
                [StringComparison]::Ordinal)) {
            continue
        }
        return $candidate
    }
    throw 'no canonical drive-letter trusted git image is available.'
}

$script:PolicyInertConfigProven = @{}
# Single source of truth: the environment builder injects these, and the scope
# assertion requires command scope to contain exactly these and nothing else.
$script:PolicyForcedConfig = @(
    'core.fsmonitor=',
    'core.hooksPath=',
    'core.askPass=',
    'core.editor=false',
    'core.pager=cat',
    'core.sshCommand=',
    'core.alternateRefsCommand=',
    'core.attributesFile=',
    'core.gitProxy=',
    'core.symlinks=false',
    'sequence.editor=false',
    'diff.external=',
    'protocol.allow=never',
    'uploadpack.packObjectsHook=',
    'credential.helper=',
    'gpg.program=false',
    'ssh.variant=simple',
    'init.templateDir=',
    'safe.directory=*',
    'gc.auto=0'
)

function Invoke-PolicyGit {
    <#
        Runs the trusted Git image through ProcessStartInfo/ArgumentList with a
        rebuilt environment. UseShellExecute is false and the environment
        dictionary is cleared, so GIT_DIR, GIT_WORK_TREE, GIT_INDEX_FILE,
        GIT_CONFIG*, GIT_SSH*, GIT_PROXY_COMMAND, GIT_EXTERNAL_DIFF, PATH, and
        PATHEXT from the caller cannot reach the child. Forced configuration is
        supplied through that rebuilt environment, which is authoritative here
        precisely because nothing was inherited.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $WorkingDirectory,

        [Parameter(Mandatory)]
        [string[]] $GitArguments
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = Get-PolicyGitImage
    # Commands that read the worktree may invoke a checkout-declared filter,
    # diff driver, or fsmonitor, so they are gated on the local config having
    # been proven inert. The gate is intrinsic to the command, not dependent on
    # the caller getting the order right.
    if ($GitArguments -contains 'status') {
        $proofKey = $WorkingDirectory.ToLowerInvariant()
        if (-not $script:PolicyInertConfigProven.ContainsKey($proofKey)) {
            Assert-PolicyInertLocalConfig -Workspace $WorkingDirectory
        }
    }
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true
    foreach ($argument in $GitArguments) {
        [void] $startInfo.ArgumentList.Add($argument)
    }

    $startInfo.EnvironmentVariables.Clear()
    foreach ($name in @('SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP')) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if (-not [string]::IsNullOrEmpty($value)) {
            $startInfo.EnvironmentVariables[$name] = $value
        }
    }
    $systemRoot = $startInfo.EnvironmentVariables['SYSTEMROOT']
    if ([string]::IsNullOrEmpty($systemRoot)) {
        $systemRoot = $startInfo.EnvironmentVariables['WINDIR']
    }
    $startInfo.EnvironmentVariables['PATH'] =
        if ([string]::IsNullOrEmpty($systemRoot)) { '' }
        else { [IO.Path]::Combine($systemRoot, 'System32') }
    foreach ($pair in @(
            @('GIT_CONFIG_NOSYSTEM', '1'),
            @('GIT_ATTR_NOSYSTEM', '1'),
            @('GIT_TERMINAL_PROMPT', '0'),
            @('GIT_OPTIONAL_LOCKS', '0'),
            @('GIT_NO_REPLACE_OBJECTS', '1'),
            @('GIT_ALLOW_PROTOCOL', 'none'),
            @('HOME', ''),
            @('USERPROFILE', ''),
            @('HOMEDRIVE', ''),
            @('HOMEPATH', ''),
            @('XDG_CONFIG_HOME', ''),
            @('LC_ALL', 'C'))) {
        $startInfo.EnvironmentVariables[$pair[0]] = $pair[1]
    }
    $forced = $script:PolicyForcedConfig
    for ($index = 0; $index -lt $forced.Count; $index++) {
        $parts = $forced[$index].Split('=', 2)
        $startInfo.EnvironmentVariables["GIT_CONFIG_KEY_$index"] = $parts[0]
        $startInfo.EnvironmentVariables["GIT_CONFIG_VALUE_$index"] = $parts[1]
    }
    $startInfo.EnvironmentVariables['GIT_CONFIG_COUNT'] = [string] $forced.Count

    $process = [Diagnostics.Process]::Start($startInfo)
    try {
        # Both pipes must be drained concurrently. Reading stdout to EOF first
        # deadlocks whenever the child fills the stderr pipe, and in that state
        # WaitForExit is never reached, so the timeout cannot fire.
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            try { $process.Kill($true) } catch { }
            throw 'git did not exit within the timeout.'
        }
        [void] [Threading.Tasks.Task]::WaitAll(@($stdoutTask, $stderrTask), 5000)
        if ($process.ExitCode -ne 0) {
            throw "git exited with code $($process.ExitCode)."
        }
        $stdout = $stdoutTask.Result
    }
    finally {
        $process.Dispose()
    }
    return $stdout.Trim()
}

$script:PolicyConfigKeyAllowList = @(
    'core\.(repositoryformatversion|filemode|bare|logallrefupdates|symlinks|ignorecase|precomposeunicode|autocrlf|eol|hidedotfiles|longpaths|fscache|untrackedcache|checkstat|trustctime|quotepath|commitgraph|multipackindex)',
    'remote\.origin\.(url|fetch|tagopt|partialclonefilter|promisor)',
    'branch\.[^.]+\.(remote|merge|rebase)',
    # worktreeconfig is deliberately absent: it enables an extra configuration
    # scope. The scope assertion below is the control, not this omission.
    'extensions\.(objectformat|refstorage|compatobjectformat|preciousobjects|partialclone)',
    'gc\.auto',
    'fetch\.(recursesubmodules|prune|prunetags|parallel)',
    'pull\.(rebase|ff)',
    'push\.default',
    'init\.defaultbranch',
    'user\.(name|email)',
    'advice\.[^.]+',
    'index\.(version|threads|skiphash)',
    'pack\.[^.]+',
    'feature\.[^.]+'
)
$script:PolicyForbiddenConfigScopes = @('system', 'global')
$script:PolicyPermittedConfigScopes = @('local', 'worktree', 'command')

function Assert-PolicyInertLocalConfig {
    <#
        The repository-local .git/config is always read and cannot be switched
        off by any environment variable, so a checkout-controlled key can make
        Git execute a process -- filter.<n>.clean, diff.<n>.textconv,
        merge.<n>.driver, core.fsmonitor, core.pager, core.sshCommand,
        credential.helper, alias.*, include/includeIf, url.*.insteadOf -- before
        this policy reaches a verdict. Driver names are arbitrary, so they
        cannot be pre-cleared by name.

        Scanning a single scope is scope-blind: a per-checkout configuration
        file is also honoured in addition to the repository-local one, and a
        single-scope listing never shows it. The scan therefore reads the FULL
        EFFECTIVE configuration with --show-scope and asserts over every scope.
        The scope structure is asserted, not merely observed: system and global
        must be absent, which is positive evidence that the rebuilt child
        environment suppressed ambient configuration, and command scope must be
        exactly this module's own forced settings.
    #>
    param(
        [Parameter(Mandatory)]
        [string] $Workspace
    )

    $listing = Invoke-PolicyGit -WorkingDirectory $Workspace `
        -GitArguments @('-C', $Workspace, '--no-pager', 'config', '--list', '--show-scope', '-z')
    $records = @($listing.Split([char]0) | Where-Object { $_ -ne '' })
    if (($records.Count % 2) -ne 0) {
        throw 'git config --show-scope produced an unpaired record stream.'
    }
    $forced = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($setting in $script:PolicyForcedConfig) {
        [void] $forced.Add($setting.Split('=', 2)[0])
    }
    $commandKeys = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    for ($index = 0; $index -lt $records.Count; $index += 2) {
        $scope = $records[$index].Trim().ToLowerInvariant()
        $key = $records[$index + 1].Split("`n")[0].Trim()
        if ($script:PolicyForbiddenConfigScopes -contains $scope) {
            throw "git reported '$scope'-scope configuration key '$key'; the rebuilt child environment failed to suppress ambient configuration."
        }
        if ($script:PolicyPermittedConfigScopes -notcontains $scope) {
            throw "git reported the unmodelled configuration scope '$scope' for '$key'."
        }
        if ($scope -eq 'command') {
            [void] $commandKeys.Add($key)
            continue
        }
        $allowed = $false
        foreach ($pattern in $script:PolicyConfigKeyAllowList) {
            if ($key -imatch "^$pattern$") { $allowed = $true; break }
        }
        if (-not $allowed) {
            throw "protected base checkout declares the unmodelled git configuration key '$key' in $scope scope."
        }
    }
    if (-not $commandKeys.SetEquals($forced)) {
        throw 'command-scope configuration is not exactly the policy forced settings.'
    }
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

    # FIRST: prove the checkout cannot make git execute a process.
    Assert-PolicyInertLocalConfig -Workspace $canonicalWorkspace

    $actualCommit = Invoke-PolicyGit -WorkingDirectory $canonicalWorkspace `
        -GitArguments @('-C', $canonicalWorkspace, '--no-pager', 'rev-parse', '--verify', '--end-of-options', 'HEAD')
    if ($actualCommit -cne $ExpectedCommit) {
        throw 'protected base checkout HEAD does not match the event base.'
    }
    $actualTree = Invoke-PolicyGit -WorkingDirectory $canonicalWorkspace `
        -GitArguments @('-C', $canonicalWorkspace, '--no-pager', 'rev-parse', '--verify', '--end-of-options', 'HEAD^{tree}')
    if ($actualTree -cnotmatch '^[0-9a-f]{40}$') {
        throw 'protected base checkout tree is invalid.'
    }
    $origin = Invoke-PolicyGit -WorkingDirectory $canonicalWorkspace `
        -GitArguments @('-C', $canonicalWorkspace, '--no-pager', 'config', '--local', '--get', 'remote.origin.url')
    $allowedOrigins = @(
        "https://github.com/$Repository",
        "https://github.com/$Repository.git"
    )
    if ($origin -cnotin $allowedOrigins) {
        throw 'protected base checkout origin is not the bound repository.'
    }
    $porcelain = Invoke-PolicyGit -WorkingDirectory $canonicalWorkspace `
        -GitArguments @('-C', $canonicalWorkspace, '--no-pager', '--literal-pathspecs', 'status', '--porcelain=v2', '--untracked-files=all')
    if ($porcelain) {
        throw 'protected base checkout is not clean.'
    }
    return $actualTree
}

Export-ModuleMember -Function @(
    'Assert-PolicyLexicalPath',
    'Assert-PolicyExistingDirectory',
    'Assert-PolicyPrivateAcl',
    'Assert-PolicyPrivateDacl',
    'Assert-PolicyInertLocalConfig',
    'Get-PolicyDirectoryIdentity',
    'Get-PolicyGitImage',
    'Invoke-PolicyGit',
    'Get-PolicyExpectedPrincipal',
    'Get-PolicyMatrixDigest',
    'Get-PolicyPrivateRootPath',
    'New-PolicyPrivateDirectory',
    'New-PolicyPrivateRoot',
    'Assert-PolicyBaseCheckout'
)
