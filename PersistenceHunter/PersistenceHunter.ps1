<#
.SYNOPSIS
    r4dl3 | Persistence Hunter

.DESCRIPTION
    Read-only Windows persistence scanner. It collects autostart locations, works out
    which file really runs behind every command line, checks the Authenticode signature
    and the location of that file, assigns a risk score and writes a compact HTML report.

    Sources : Run/RunOnce keys (HKLM, HKCU, Wow6432Node), Scheduled Tasks (exec actions),
              Services (non-disabled), Startup folders, WMI Event Subscriptions (admin only).
    Scoring : unsigned +3 | signature hash mismatch +5 | suspicious location +3 |
              file missing +3 | LOLBin launcher +2 | suspicious arguments +4 |
              WMI consumer +5 | valid Microsoft signature -2
    Levels  : High >= 6, Medium 3-5, Low < 3

    The script never changes anything on the system.

.PARAMETER OutputPath
    Path of the HTML report. Default: current directory, timestamped name.

.PARAMETER ShowAll
    Also list Low entries in the report (default: only Medium and High are listed).

.PARAMETER OpenReport
    Open the report in the default browser when finished.

.EXAMPLE
    .\r4dl3_PersistenceHunter.ps1 -OpenReport
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path (Get-Location).Path ('r4dl3_PersistenceHunter_{0}.html' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))),
    [switch]$ShowAll,
    [switch]$OpenReport
)

# ----------------------------------------------------------------------------
#  Banner
# ----------------------------------------------------------------------------
Write-Host ''
Write-Host '  ======================================' -ForegroundColor DarkGray
Write-Host '   r4dl3  |  Persistence Hunter'            -ForegroundColor Cyan
Write-Host '  ======================================' -ForegroundColor DarkGray
Write-Host ''

if ($env:OS -ne 'Windows_NT') {
    Write-Error 'This tool works on Windows only.'
    exit 1
}

# ----------------------------------------------------------------------------
#  Admin check (script keeps running without admin, admin-only parts are skipped)
# ----------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    Write-Host '[+] Running elevated, full scan.' -ForegroundColor Green
}
else {
    Write-Warning 'Not elevated. Admin-only sources will be skipped; other results may be incomplete.'
}

# ----------------------------------------------------------------------------
#  Shared state and constants
# ----------------------------------------------------------------------------
$script:Findings = [System.Collections.Generic.List[object]]::new()
$script:Skipped  = [System.Collections.Generic.List[string]]::new()
$script:Errors   = [System.Collections.Generic.List[string]]::new()
$script:SigCache = @{}

$script:ExtRx     = '\.(exe|dll|bat|cmd|com|scr|ps1|vbs|vbe|js|jse|wsf|hta|sct|ocx|msi|cpl|sys|lnk)$'
$script:SuspPathRx = '(?i)\\(AppData|Temp|Users\\Public|ProgramData|Downloads|\$Recycle\.Bin)\\'
$script:Lolbins   = @('rundll32','regsvr32','mshta','wscript','cscript','powershell','powershell_ise',
                      'pwsh','cmd','msiexec','certutil','bitsadmin','wmic','installutil','regasm',
                      'regsvcs','msbuild','cmstp','forfiles','odbcconf')

$script:SuspiciousPatterns = @(
    @{ Rx = '(?i)\s-e(nc\w*|c)?\s+[A-Za-z0-9+/=]{16,}';  Why = 'encoded PowerShell command' },
    @{ Rx = '(?i)-w(indowstyle)?\s+hidden';               Why = 'hidden window' },
    @{ Rx = '(?i)-(ep|executionpolicy)\s+bypass';         Why = 'execution policy bypass' },
    @{ Rx = '(?i)downloadstring|downloadfile|invoke-webrequest|net\.webclient|\biex\b|invoke-expression|frombase64string'; Why = 'download/exec pattern' },
    @{ Rx = '(?i)https?://';                              Why = 'URL in command' },
    @{ Rx = '(?i)(javascript|vbscript):';                 Why = 'script protocol' }
)

# ----------------------------------------------------------------------------
#  Finding object
# ----------------------------------------------------------------------------
function New-Finding {
    param(
        [Parameter(Mandatory)][string]$Category,
        [string]$Name = '',
        [string]$Location = '',
        [string]$Command = '',
        [int]$BaseScore = 0,
        [string]$Note = '',
        [bool]$Parse = $true
    )
    [pscustomobject]@{
        Category  = $Category
        Name      = $Name
        Location  = $Location
        Command   = $Command
        BaseScore = $BaseScore
        Note      = $Note
        Parse     = $Parse
        ImagePath = ''
        Target    = ''
        Signature = ''
        Publisher = ''
        Score     = 0
        Level     = 'Low'
        Reasons   = ''
    }
}

# ----------------------------------------------------------------------------
#  Collectors
# ----------------------------------------------------------------------------
function Get-RunKeyPersistence {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($path in $keys) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        try {
            $key = Get-Item -LiteralPath $path -ErrorAction Stop
            foreach ($valueName in $key.GetValueNames()) {
                if (-not $valueName) { continue }
                $value = $key.GetValue($valueName)
                if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)) { continue }
                $value = $value -replace '^[!*]+', ''      # RunOnce prefixes
                New-Finding -Category 'Run key' -Name $valueName -Location $path -Command $value
            }
        }
        catch {
            $script:Errors.Add(('Run key {0}: {1}' -f $path, $_.Exception.Message))
        }
    }
}

function Get-TaskPersistence {
    # Only tasks with an executable action are listed (COM handler actions have no command line).
    foreach ($task in @(Get-ScheduledTask -ErrorAction Stop)) {
        foreach ($action in @($task.Actions)) {
            if (-not $action.Execute) { continue }
            $exe = [string]$action.Execute
            if ($exe -match '\s' -and $exe -notmatch '^"') { $exe = '"' + $exe + '"' }
            $cmdLine = ('{0} {1}' -f $exe, $action.Arguments).Trim()
            New-Finding -Category 'Task' -Name $task.TaskName `
                -Location ('{0} [{1}]' -f $task.TaskPath, $task.State) -Command $cmdLine
        }
    }
}

function Get-ServicePersistence {
    # Disabled services cannot start, so they are skipped.
    foreach ($svc in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
        if (-not $svc.PathName -or $svc.StartMode -eq 'Disabled') { continue }
        New-Finding -Category 'Service' -Name $svc.Name `
            -Location ('{0} | {1} | {2}' -f $svc.DisplayName, $svc.StartMode, $svc.StartName) `
            -Command $svc.PathName
    }
}

function Get-StartupFolderPersistence {
    $dirs = @(
        (Join-Path $env:APPDATA     'Microsoft\Windows\Start Menu\Programs\Startup'),
        (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup')
    )
    $shell = New-Object -ComObject WScript.Shell
    foreach ($dir in $dirs) {
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $dir -Force -File -ErrorAction SilentlyContinue)) {
            if ($file.Name -ieq 'desktop.ini') { continue }
            $cmd = '"{0}"' -f $file.FullName
            if ($file.Extension -ieq '.lnk') {
                try {
                    $lnk = $shell.CreateShortcut($file.FullName)
                    if ($lnk.TargetPath) { $cmd = ('"{0}" {1}' -f $lnk.TargetPath, $lnk.Arguments).Trim() }
                }
                catch { }
            }
            New-Finding -Category 'Startup folder' -Name $file.Name -Location $dir -Command $cmd
        }
    }
}

function Get-RefName {
    param($Ref)
    if ($null -eq $Ref) { return '' }
    if ($Ref.PSObject.Properties['Name'] -and $Ref.Name) { return [string]$Ref.Name }
    if (([string]$Ref) -match 'Name\s*=\s*"([^"]+)"') { return $Matches[1] }
    return ''
}

function Get-WmiPersistence {
    $ns       = 'root\subscription'
    $filters  = @{}
    $bindings = @{}

    foreach ($f in @(Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction Stop)) {
        $filters[[string]$f.Name] = [string]$f.Query
    }
    foreach ($b in @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction Stop)) {
        $consumerName = Get-RefName $b.Consumer
        if (-not $consumerName) { continue }
        if (-not $bindings.ContainsKey($consumerName)) {
            $bindings[$consumerName] = [System.Collections.Generic.List[string]]::new()
        }
        $bindings[$consumerName].Add((Get-RefName $b.Filter))
    }

    $describe = {
        param($consumerName)
        if (-not $bindings.ContainsKey($consumerName)) { return 'filter: none (unbound)' }
        $parts = foreach ($fn in $bindings[$consumerName]) {
            if ($filters.ContainsKey($fn)) { '{0} => {1}' -f $fn, $filters[$fn] } else { $fn }
        }
        'filter: ' + ($parts -join ' ; ')
    }

    foreach ($c in @(Get-CimInstance -Namespace $ns -ClassName CommandLineEventConsumer -ErrorAction Stop)) {
        $cmd = if ($c.CommandLineTemplate) { [string]$c.CommandLineTemplate } else { [string]$c.ExecutablePath }
        New-Finding -Category 'WMI' -Name $c.Name `
            -Location ('CommandLineEventConsumer | ' + (& $describe $c.Name)) `
            -Command $cmd -BaseScore 5 -Note 'WMI CommandLine consumer'
    }

    foreach ($c in @(Get-CimInstance -Namespace $ns -ClassName ActiveScriptEventConsumer -ErrorAction Stop)) {
        $inline = $false
        if ($c.ScriptFileName) {
            $cmd = [string]$c.ScriptFileName
        }
        else {
            $text = (([string]$c.ScriptText) -replace '\s+', ' ').Trim()
            $cmd  = '[{0} inline] {1}' -f $c.ScriptingEngine, $text
            $inline = $true
        }
        if ($cmd.Length -gt 400) { $cmd = $cmd.Substring(0, 400) }
        New-Finding -Category 'WMI' -Name $c.Name `
            -Location ('ActiveScriptEventConsumer | ' + (& $describe $c.Name)) `
            -Command $cmd -BaseScore 5 -Note 'WMI ActiveScript consumer' -Parse (-not $inline)
    }
}

# ----------------------------------------------------------------------------
#  Command parser: which file really runs?
# ----------------------------------------------------------------------------
function Resolve-FileCandidate {
    # Returns @{Path; Exists} or $null when the location cannot be determined.
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    try {
        $p = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim([char]34))
        if ($p -match '^(?:[A-Za-z]:\\|\\\\)') {
            return [pscustomobject]@{ Path = $p; Exists = [bool](Test-Path -LiteralPath $p -PathType Leaf) }
        }
        foreach ($dir in @((Join-Path $env:SystemRoot 'System32'), $env:SystemRoot)) {
            $c = Join-Path $dir $p
            if (Test-Path -LiteralPath $c -PathType Leaf) {
                return [pscustomobject]@{ Path = $c; Exists = $true }
            }
        }
        $app = Get-Command $p -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($app -and $app.Source) {
            return [pscustomobject]@{ Path = $app.Source; Exists = $true }
        }
    }
    catch { }
    return $null
}

function Get-State {
    param($Resolved)
    if (-not $Resolved)    { return 'Unknown' }
    if ($Resolved.Exists)  { return 'Found' }
    return 'Missing'
}

function Find-ArgTarget {
    # First argument that looks like a file (handles rundll32 "dll,Entry" and quoted paths).
    param([string]$Arguments)
    foreach ($m in [regex]::Matches($Arguments, '"[^"]*"|''[^'']*''|\S+')) {
        $t = $m.Value.Trim([char]34, [char]39)
        if ($t -match '^[/-]') { continue }
        $t = ($t -split ',')[0]
        if ($t -match $script:ExtRx) { return $t }
    }
    return ''
}

function Resolve-CommandLine {
    param([string]$Command, [switch]$NoParse)

    $out = [pscustomobject]@{
        Exe = ''; ExeState = 'Unknown'; Target = ''; TargetState = 'Unknown'
        IsLolbin = $false; LolbinName = ''
    }
    if ($NoParse -or [string]::IsNullOrWhiteSpace($Command)) { return $out }

    $cmd = [Environment]::ExpandEnvironmentVariables($Command.Trim())
    $cmd = $cmd -replace '^\\\?\?\\', ''                                   # \??\ prefix
    if ($cmd -match '^\\SystemRoot\\') { $cmd = $env:SystemRoot + $cmd.Substring(11) }

    $exeText = ''
    $argText = ''

    if ($cmd.StartsWith('"')) {
        $end = $cmd.IndexOf('"', 1)
        if ($end -gt 0) {
            $exeText = $cmd.Substring(1, $end - 1)
            $argText = $cmd.Substring($end + 1).Trim()
        }
        else { $exeText = $cmd.Trim('"') }
    }
    else {
        # Unquoted: find the shortest leading part that is an existing file.
        $tokens = @($cmd -split '\s+' | Where-Object { $_ })
        $limit  = [Math]::Min($tokens.Count, 8)
        $found  = -1
        $extHit = -1
        for ($i = 1; $i -le $limit; $i++) {
            $cand = $tokens[0..($i - 1)] -join ' '
            if ($extHit -lt 0 -and $cand -match $script:ExtRx) { $extHit = $i }
            $r = Resolve-FileCandidate $cand
            if ($r -and $r.Exists) { $found = $i; break }
        }
        if ($found -lt 0) { $found = if ($extHit -gt 0) { $extHit } else { 1 } }
        if ($tokens.Count -eq 0) { return $out }
        $exeText = $tokens[0..($found - 1)] -join ' '
        $argText = if ($found -lt $tokens.Count) { $tokens[$found..($tokens.Count - 1)] -join ' ' } else { '' }
    }

    if (-not $exeText) { return $out }

    $r = Resolve-FileCandidate $exeText
    $out.Exe      = if ($r) { $r.Path } else { $exeText }
    $out.ExeState = Get-State $r

    $leaf = ''
    try { $leaf = [IO.Path]::GetFileNameWithoutExtension($exeText) } catch { }

    if ($leaf -and ($script:Lolbins -contains $leaf)) {
        $out.IsLolbin   = $true
        $out.LolbinName = $leaf
        $t = Find-ArgTarget $argText
        if ($t) {
            $tr = Resolve-FileCandidate $t
            if ($tr) {
                $out.Target      = $tr.Path
                $out.TargetState = Get-State $tr
            }
        }
    }
    return $out
}

# ----------------------------------------------------------------------------
#  Verification: signature (cached)
# ----------------------------------------------------------------------------
function Get-SigInfo {
    param([string]$Path)
    $key = $Path.ToLowerInvariant()
    if ($script:SigCache.ContainsKey($key)) { return $script:SigCache[$key] }

    $info = [pscustomobject]@{ Status = 'Unknown'; Publisher = ''; IsMicrosoft = $false }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $info.Status = [string]$sig.Status
        if ($sig.SignerCertificate) {
            $subject = $sig.SignerCertificate.Subject
            if     ($subject -match 'CN="([^"]+)"') { $info.Publisher = $Matches[1] }
            elseif ($subject -match 'CN=([^,]+)')   { $info.Publisher = $Matches[1].Trim() }
            $info.IsMicrosoft = ($sig.Status -eq 'Valid') -and ($subject -match 'O=Microsoft Corporation')
        }
    }
    catch { $info.Status = 'Error' }

    $script:SigCache[$key] = $info
    return $info
}

# ----------------------------------------------------------------------------
#  Risk scoring
# ----------------------------------------------------------------------------
function Add-Analysis {
    param($F)

    $score   = [int]$F.BaseScore
    $reasons = [System.Collections.Generic.List[string]]::new()
    if ($F.Note) { $reasons.Add($F.Note) }

    $p = Resolve-CommandLine -Command $F.Command -NoParse:(-not $F.Parse)
    $F.ImagePath = $p.Exe
    $F.Target    = $p.Target

    if ($p.IsLolbin) {
        $score += 2
        $reasons.Add('LOLBin launcher (' + $p.LolbinName + ')')
    }

    $hits = @()
    foreach ($pat in $script:SuspiciousPatterns) {
        if ($F.Command -match $pat.Rx) { $hits += $pat.Why }
    }
    if ($hits.Count -gt 0) {
        $score += 4
        $reasons.Add('suspicious arguments: ' + ($hits -join ', '))
    }

    foreach ($x in @($p.Exe, $p.Target)) {
        if ($x -and $x -match $script:SuspPathRx) {
            $score += 3
            $reasons.Add('runs from a user-writable / suspicious location')
            break
        }
    }

    # Which file is judged: the payload if one was found, otherwise the executable itself.
    # A LOLBin without a resolvable payload is not judged by the launcher's signature.
    $checkPath  = ''
    $checkState = 'Unknown'
    $label      = 'file'
    if ($p.Target) {
        $checkPath = $p.Target; $checkState = $p.TargetState; $label = 'target'
    }
    elseif ($p.Exe -and -not $p.IsLolbin) {
        $checkPath = $p.Exe; $checkState = $p.ExeState
    }

    if ($checkState -eq 'Missing') {
        $score += 3
        $reasons.Add($label + ' not found on disk')
    }
    elseif ($checkState -eq 'Found') {
        $sig = Get-SigInfo $checkPath
        $F.Signature = $sig.Status
        $F.Publisher = $sig.Publisher
        switch ($sig.Status) {
            'Valid'        { if ($sig.IsMicrosoft) { $score -= 2 } }
            'NotSigned'    { $score += 3; $reasons.Add('unsigned') }
            'HashMismatch' { $score += 5; $reasons.Add('signature hash mismatch (file modified after signing)') }
            { $_ -in 'NotTrusted', 'UnknownError', 'Incompatible' } {
                $score += 3
                $reasons.Add('signature status: ' + $sig.Status)
            }
        }
    }

    $F.Score   = [Math]::Max(0, $score)
    $F.Level   = if ($F.Score -ge 6) { 'High' } elseif ($F.Score -ge 3) { 'Medium' } else { 'Low' }
    $F.Reasons = $reasons -join '; '
}

# ----------------------------------------------------------------------------
#  HTML report (compact)
# ----------------------------------------------------------------------------
function Format-Cell {
    param($Text, [int]$Max = 0)
    $s = [string]$Text
    if ($Max -gt 0 -and $s.Length -gt $Max) { $s = $s.Substring(0, $Max) + '...' }
    [System.Net.WebUtility]::HtmlEncode($s)
}

function Export-HtmlReport {
    param([object[]]$All, [string]$Path)

    $nHigh = @($All | Where-Object { $_.Level -eq 'High' }).Count
    $nMed  = @($All | Where-Object { $_.Level -eq 'Medium' }).Count
    $nLow  = @($All | Where-Object { $_.Level -eq 'Low' }).Count
    $cats  = (@($All | Group-Object Category | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })) -join ' | '

    $rows = @($All | Where-Object { $ShowAll -or $_.Level -ne 'Low' } |
              Sort-Object @{ Expression = 'Score'; Descending = $true }, Category, Name)

    $L = [System.Collections.Generic.List[string]]::new()
    $L.Add('<!DOCTYPE html><html><head><meta charset="utf-8"><title>r4dl3 | Persistence Hunter</title><style>')
    $L.Add('body{font:13px "Segoe UI",Arial,sans-serif;margin:16px;color:#222}')
    $L.Add('table{border-collapse:collapse;width:100%}')
    $L.Add('th,td{border:1px solid #ccc;padding:3px 6px;text-align:left;vertical-align:top;word-break:break-word}')
    $L.Add('th{background:#eee}small{color:#666}')
    $L.Add('tr.high td:first-child{color:#c00;font-weight:bold}tr.medium td:first-child{color:#b60;font-weight:bold}')
    $L.Add('</style></head><body>')
    $L.Add('<h2>r4dl3 | Persistence Hunter</h2>')
    $L.Add(('<p>Host: <b>{0}</b> | User: <b>{1}</b> | Admin: <b>{2}</b> | Date: {3}</p>' -f
        (Format-Cell $env:COMPUTERNAME), (Format-Cell ($env:USERDOMAIN + '\' + $env:USERNAME)), $isAdmin,
        (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')))
    $L.Add(('<p>Total: {0} | High: <b>{1}</b> | Medium: <b>{2}</b> | Low: {3}</p>' -f $All.Count, $nHigh, $nMed, $nLow))
    $L.Add(('<p>By category: {0}</p>' -f (Format-Cell $cats)))

    if ($script:Skipped.Count -gt 0 -or $script:Errors.Count -gt 0) {
        $L.Add('<p><b>Skipped / errors (results are incomplete for these):</b></p><ul>')
        foreach ($s in $script:Skipped) { $L.Add('<li>Skipped: ' + (Format-Cell $s) + '</li>') }
        foreach ($e in $script:Errors)  { $L.Add('<li>Error: '   + (Format-Cell $e) + '</li>') }
        $L.Add('</ul>')
    }

    $L.Add('<table><tr><th>Level</th><th>Score</th><th>Category</th><th>Name / Location</th><th>Command</th><th>File</th><th>Signature</th><th>Reasons</th></tr>')
    foreach ($r in $rows) {
        $file = if ($r.Target) { $r.Target } else { $r.ImagePath }
        $sig  = [string]$r.Signature
        if ($r.Publisher) { $sig = ($sig + ' / ' + $r.Publisher).Trim(' /') }
        $L.Add(('<tr class="{0}"><td>{1}</td><td>{2}</td><td>{3}</td><td><b>{4}</b><br><small>{5}</small></td><td>{6}</td><td>{7}</td><td>{8}</td><td>{9}</td></tr>' -f
            $r.Level.ToLower(), $r.Level, $r.Score, (Format-Cell $r.Category),
            (Format-Cell $r.Name 120), (Format-Cell $r.Location 200), (Format-Cell $r.Command 250),
            (Format-Cell $file 200), (Format-Cell $sig 100), (Format-Cell $r.Reasons)))
    }
    $L.Add('</table>')

    $hidden = $All.Count - $rows.Count
    if ($hidden -gt 0) {
        $L.Add(('<p><small>{0} low-risk entries not listed (run with -ShowAll to list everything).</small></p>' -f $hidden))
    }
    $L.Add('</body></html>')

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    [IO.File]::WriteAllText($Path, ($L -join "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
}

# ----------------------------------------------------------------------------
#  Collector runner (one failing collector never stops the others)
# ----------------------------------------------------------------------------
function Invoke-Collector {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][scriptblock]$Block,
        [switch]$NeedsAdmin
    )
    if ($NeedsAdmin -and -not $isAdmin) {
        $script:Skipped.Add($Label + ' (admin required)')
        Write-Host ('[-] {0}: skipped (admin required)' -f $Label) -ForegroundColor Yellow
        return
    }
    try {
        $items = @(& $Block)
        if ($items.Count -gt 0) { $script:Findings.AddRange([object[]]$items) }
        Write-Host ('[+] {0}: {1} entries' -f $Label, $items.Count)
    }
    catch {
        $script:Errors.Add(('{0}: {1}' -f $Label, $_.Exception.Message))
        Write-Warning ('{0} failed: {1}' -f $Label, $_.Exception.Message)
    }
}

# ----------------------------------------------------------------------------
#  Main
# ----------------------------------------------------------------------------
Invoke-Collector -Label 'Run / RunOnce keys'        -Block { Get-RunKeyPersistence }
Invoke-Collector -Label 'Scheduled Tasks'           -Block { Get-TaskPersistence }
Invoke-Collector -Label 'Services'                  -Block { Get-ServicePersistence }
Invoke-Collector -Label 'Startup folders'           -Block { Get-StartupFolderPersistence }
Invoke-Collector -Label 'WMI Event Subscriptions'   -Block { Get-WmiPersistence } -NeedsAdmin

$total = $script:Findings.Count
for ($i = 0; $i -lt $total; $i++) {
    if ($i % 20 -eq 0) {
        Write-Progress -Activity 'r4dl3 | Analyzing entries' -Status ('{0} / {1}' -f $i, $total) -PercentComplete (($i / $total) * 100)
    }
    try   { Add-Analysis $script:Findings[$i] }
    catch { $script:Errors.Add(('Analysis of "{0}": {1}' -f $script:Findings[$i].Name, $_.Exception.Message)) }
}
Write-Progress -Activity 'r4dl3 | Analyzing entries' -Completed

$OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
try {
    Export-HtmlReport -All $script:Findings.ToArray() -Path $OutputPath
    Write-Host ('[+] Report: {0}' -f $OutputPath) -ForegroundColor Green
}
catch {
    Write-Error ('Could not write report: ' + $_.Exception.Message)
}

$high = @($script:Findings | Where-Object { $_.Level -eq 'High' } | Sort-Object Score -Descending)
$med  = @($script:Findings | Where-Object { $_.Level -eq 'Medium' })
Write-Host ''
Write-Host ('[=] Total {0} | High {1} | Medium {2} | Low {3}' -f $total, $high.Count, $med.Count, ($total - $high.Count - $med.Count))
foreach ($h in $high) {
    Write-Host ('    [HIGH {0}] {1} | {2} | {3}' -f $h.Score, $h.Category, $h.Name, $h.Reasons) -ForegroundColor Red
}

if ($OpenReport -and (Test-Path -LiteralPath $OutputPath)) { Start-Process $OutputPath }
