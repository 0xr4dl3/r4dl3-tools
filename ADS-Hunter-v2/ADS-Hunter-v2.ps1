<#
.SYNOPSIS
    ADS-Hunter v2 - one-command hunter for NTFS Alternate Data Streams (ADS).

.DESCRIPTION
    Just run:   .\ADS-Hunter.ps1

    With no parameters it will:
      * offer to relaunch itself as Administrator (full coverage),
      * scan EVERY local NTFS/ReFS drive (fixed + removable), all folders,
      * use a compiled multi-threaded engine (FindFirstStreamW), so a whole drive
        takes minutes instead of hours,
      * inspect the CONTENT of every hidden stream (executable / archive / script /
        shortcut signatures, script keywords, entropy, size, name tricks),
      * score each finding CRITICAL / HIGH / MEDIUM / LOW and ignore known-benign
        Windows streams (Zone.Identifier etc.) - unless they are abnormal,
      * print a colour console report and write + open an HTML report.

    Nothing is ever deleted or modified. No internet, no external database.

    Optional switches (never required):
      -SelfTest    build test streams, scan them, verify detection, clean up
      -Path        scan only specific folders instead of all drives
      -OutHtml     custom path for the HTML report
      -NoElevate   do not offer to relaunch as Administrator
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [string[]]$Path,
    [string]$OutHtml,
    [switch]$SelfTest,
    [switch]$NoElevate
)

# ---------------------------------------------------------------------------
# Console helpers
# ---------------------------------------------------------------------------
function Write-Info { Write-Host "[*] $($args[0])" -ForegroundColor Cyan }
function Write-Good { Write-Host "[+] $($args[0])" -ForegroundColor Green }
function Write-Bad  { Write-Host "[X] $($args[0])" -ForegroundColor Red }
function Write-Warn { Write-Host "[!] $($args[0])" -ForegroundColor Yellow }

# ---------------------------------------------------------------------------
# Native scan engine (C#). Walks the tree on several threads and asks Windows
# directly for the stream list of each file - far faster than Get-Item -Stream.
# Written in C# 5 syntax so it also compiles on Windows PowerShell 5.1.
# ---------------------------------------------------------------------------
$AdsEngineSource = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading;
using Microsoft.Win32.SafeHandles;

public class AdsFinding
{
    public string Path;
    public string Stream;
    public long Size;
    public bool IsDirectory;
}

public static class AdsScanner
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WIN32_FIND_STREAM_DATA
    {
        public long StreamSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
        public string cStreamName;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr FindFirstStreamW(string lpFileName, int infoLevel, out WIN32_FIND_STREAM_DATA lpFindStreamData, uint dwFlags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool FindNextStreamW(IntPtr hFindStream, out WIN32_FIND_STREAM_DATA lpFindStreamData);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FindClose(IntPtr hFindFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    private static readonly IntPtr INVALID_HANDLE = new IntPtr(-1);

    public static long FilesScanned;
    public static long DirsScanned;
    public static long Errors;
    public static volatile string Current = "";
    public static volatile bool Done = true;
    public static volatile bool Cancel;
    public static readonly List<AdsFinding> Findings = new List<AdsFinding>();

    private static readonly Stack<string> dirs = new Stack<string>();
    private static long pending;
    private static int active;

    public static int FindingCount
    {
        get { lock (Findings) { return Findings.Count; } }
    }

    public static void Start(string[] roots, int threads)
    {
        FilesScanned = 0; DirsScanned = 0; Errors = 0; pending = 0;
        Cancel = false; Current = "";
        lock (Findings) { Findings.Clear(); }
        lock (dirs) { dirs.Clear(); }
        foreach (string r in roots)
        {
            Interlocked.Increment(ref pending);
            lock (dirs) { dirs.Push(r); }
        }
        if (threads < 1) threads = 1;
        active = threads;
        Done = false;
        for (int i = 0; i < threads; i++)
        {
            Thread t = new Thread(Worker);
            t.IsBackground = true;
            t.Start();
        }
    }

    private static bool TryPop(out string d)
    {
        lock (dirs)
        {
            if (dirs.Count > 0) { d = dirs.Pop(); return true; }
        }
        d = null;
        return false;
    }

    private static void Worker()
    {
        try
        {
            while (!Cancel)
            {
                string d;
                if (TryPop(out d))
                {
                    try { ProcessDir(d); }
                    catch (Exception) { Interlocked.Increment(ref Errors); }
                    Interlocked.Decrement(ref pending);
                }
                else
                {
                    if (Interlocked.Read(ref pending) == 0) break;
                    Thread.Sleep(2);
                }
            }
        }
        finally
        {
            if (Interlocked.Decrement(ref active) == 0) Done = true;
        }
    }

    private static void ProcessDir(string dir)
    {
        Current = dir;
        Interlocked.Increment(ref DirsScanned);
        CheckPath(dir, true);

        DirectoryInfo di = new DirectoryInfo(dir);
        try
        {
            foreach (FileSystemInfo fsi in di.EnumerateFileSystemInfos())
            {
                if (Cancel) return;
                FileAttributes a = fsi.Attributes;
                bool isDir = (a & FileAttributes.Directory) != 0;
                if (isDir)
                {
                    // never follow junctions/symlinks (avoids loops and double scanning)
                    if ((a & FileAttributes.ReparsePoint) != 0) continue;
                    Interlocked.Increment(ref pending);
                    lock (dirs) { dirs.Push(fsi.FullName); }
                }
                else
                {
                    // skip cloud placeholders (OneDrive etc.) so nothing gets downloaded
                    if ((a & (FileAttributes)(0x1000 | 0x40000 | 0x400000)) != 0) continue;
                    Interlocked.Increment(ref FilesScanned);
                    CheckPath(fsi.FullName, false);
                }
            }
        }
        catch (Exception) { Interlocked.Increment(ref Errors); }
    }

    private static string ToLong(string p)
    {
        if (p.StartsWith(@"\\?\", StringComparison.Ordinal)) return p;
        if (p.StartsWith(@"\\", StringComparison.Ordinal)) return @"\\?\UNC\" + p.Substring(2);
        return @"\\?\" + p;
    }

    private static void CheckPath(string path, bool isDir)
    {
        WIN32_FIND_STREAM_DATA data;
        IntPtr h = FindFirstStreamW(ToLong(path), 0, out data, 0);
        if (h == INVALID_HANDLE)
        {
            int err = Marshal.GetLastWin32Error();
            // 38 = no more streams, 1 = filesystem has no stream support: both are normal
            if (err != 38 && err != 1) Interlocked.Increment(ref Errors);
            return;
        }
        try
        {
            do
            {
                string n = data.cStreamName;
                if (n == null || n.Length <= 7) continue;          // "::$DATA" = the normal file body
                if (!n.EndsWith(":$DATA", StringComparison.Ordinal)) continue;
                AdsFinding f = new AdsFinding();
                f.Path = path;
                f.Stream = n.Substring(1, n.Length - 7);
                f.Size = data.StreamSize;
                f.IsDirectory = isDir;
                lock (Findings) { Findings.Add(f); }
            }
            while (FindNextStreamW(h, out data));
        }
        finally { FindClose(h); }
    }

    // ---------------- helpers used by the PowerShell side ----------------

    private static FileStream OpenStream(string path, string stream, bool write)
    {
        string full = ToLong(path) + ":" + stream;
        uint access = write ? 0x40000000u : 0x80000000u;   // GENERIC_WRITE / GENERIC_READ
        uint disp = write ? 2u : 3u;                       // CREATE_ALWAYS / OPEN_EXISTING
        SafeFileHandle h = CreateFileW(full, access, 7u, IntPtr.Zero, disp, 0x02000000u, IntPtr.Zero);
        if (h.IsInvalid)
        {
            int err = Marshal.GetLastWin32Error();
            throw new IOException("Cannot open stream (Win32 error " + err + ")");
        }
        return new FileStream(h, write ? FileAccess.Write : FileAccess.Read, 4096, false);
    }

    public static byte[] ReadHead(string path, string stream, int max)
    {
        try
        {
            using (FileStream fs = OpenStream(path, stream, false))
            {
                byte[] buf = new byte[max];
                int total = 0;
                while (total < max)
                {
                    int n = fs.Read(buf, total, max - total);
                    if (n <= 0) break;
                    total += n;
                }
                byte[] res = new byte[total];
                Array.Copy(buf, res, total);
                return res;
            }
        }
        catch (Exception) { return null; }
    }

    public static string HashStream(string path, string stream)
    {
        try
        {
            using (FileStream fs = OpenStream(path, stream, false))
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(fs);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }
        catch (Exception) { return ""; }
    }

    public static void WriteStream(string path, string stream, byte[] data)
    {
        using (FileStream fs = OpenStream(path, stream, true))
        {
            fs.Write(data, 0, data.Length);
        }
    }

    public static double Entropy(byte[] data)
    {
        if (data == null || data.Length == 0) return 0.0;
        int[] c = new int[256];
        for (int i = 0; i < data.Length; i++) c[data[i]]++;
        double e = 0.0;
        double n = data.Length;
        for (int i = 0; i < 256; i++)
        {
            if (c[i] == 0) continue;
            double p = c[i] / n;
            e -= p * Math.Log(p, 2.0);
        }
        return e;
    }

    public static double PrintableRatio(byte[] data)
    {
        if (data == null || data.Length == 0) return 0.0;
        int ok = 0;
        for (int i = 0; i < data.Length; i++)
        {
            byte b = data[i];
            if (b == 9 || b == 10 || b == 13 || (b >= 32 && b < 127)) ok++;
        }
        return (double)ok / data.Length;
    }
}
'@

# ---------------------------------------------------------------------------
# Knowledge base
# ---------------------------------------------------------------------------

# Streams that Windows / common apps create themselves. "Max" is the largest size
# that is still considered normal; anything bigger or with odd content is escalated.
$script:KnownStreams = @(
    @{ Pattern = 'Zone.Identifier';     Max = 1024 }
    @{ Pattern = 'SmartScreen';         Max = 1024 }
    @{ Pattern = '$CI.CATALOGHINT';     Max = 16384 }
    @{ Pattern = '$KERNEL.PURGE.*';     Max = 16384 }
    @{ Pattern = 'encryptable';         Max = 1024 }
    @{ Pattern = 'OECustomProperty';    Max = 16384 }
    @{ Pattern = 'favicon';             Max = 65536 }
    @{ Pattern = 'AFP_AfpInfo';         Max = 1024 }
    @{ Pattern = 'AFP_Resource';        Max = 5242880 }
    @{ Pattern = 'com.dropbox.attrs';   Max = 8192 }
    @{ Pattern = 'com.apple.*';         Max = 16384 }
    @{ Pattern = '*SummaryInformation'; Max = 131072 }
)

# File-type signatures (magic bytes) and how suspicious each is inside a hidden stream.
$script:Signatures = @(
    @{ Magic = [byte[]](0x4D,0x5A);                               Name = 'Windows executable (PE/MZ)';                 Score = 100 }
    @{ Magic = [byte[]](0x7F,0x45,0x4C,0x46);                     Name = 'ELF executable';                             Score = 80 }
    @{ Magic = [byte[]](0x4C,0x00,0x00,0x00,0x01,0x14,0x02,0x00); Name = 'Windows shortcut (.lnk)';                    Score = 70 }
    @{ Magic = [byte[]](0xCA,0xFE,0xBA,0xBE);                     Name = 'Java class file';                            Score = 60 }
    @{ Magic = [byte[]](0x50,0x4B,0x03,0x04);                     Name = 'ZIP-based archive (zip/docx/jar/apk)';       Score = 50 }
    @{ Magic = [byte[]](0x37,0x7A,0xBC,0xAF,0x27,0x1C);           Name = '7-Zip archive';                              Score = 50 }
    @{ Magic = [byte[]](0x52,0x61,0x72,0x21);                     Name = 'RAR archive';                                Score = 50 }
    @{ Magic = [byte[]](0x4D,0x53,0x43,0x46);                     Name = 'Cabinet (CAB) archive';                      Score = 50 }
    @{ Magic = [byte[]](0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1); Name = 'OLE2 document (legacy Office, may hold macros)'; Score = 50 }
    @{ Magic = [byte[]](0x1F,0x8B);                               Name = 'gzip archive';                               Score = 40 }
    @{ Magic = [byte[]](0x23,0x21);                               Name = 'script with #! header';                      Score = 40 }
    @{ Magic = [byte[]](0x25,0x50,0x44,0x46);                     Name = 'PDF document';                               Score = 30 }
)

$script:ScriptPattern = '(?i)(powershell|pwsh|cmd\.exe|cmd\s+/c|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|schtasks|msiexec|FromBase64String|Invoke-Expression|\biex\b|DownloadString|DownloadFile|Invoke-WebRequest|Net\.WebClient|<script|eval\(|CreateObject|WScript\.Shell|-enc(odedcommand)?\s|\[Reflection\.Assembly\]|VirtualAlloc|CreateRemoteThread|LoadLibrary)'
$script:UrlPattern    = '(?i)(https?|ftp)://'
$script:ExeNamePattern = '(?i)\.(exe|dll|sys|scr|com|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|lnk|msi|jar|cpl|pif)$'
$script:RiskyFolderPattern = '(?i)\\(Startup|Temp|AppData\\Roaming|ProgramData|Users\\Public|Downloads)\\'
$script:SpoofPattern  = '[\u202A-\u202E\u2066-\u2069]'

# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

# Escapes control / invisible / direction-override characters so a hostile file or
# stream name can never mess with the console or the HTML report.
$script:SafeEval = [System.Text.RegularExpressions.MatchEvaluator]{
    param($m)
    $c = [int][char]$m.Value
    if ($c -lt 256) { '\x{0:X2}' -f $c } else { '\u{0:X4}' -f $c }
}
function Format-Safe {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return [regex]::Replace($Text, '[\x00-\x1F\x7F-\x9F\u200B-\u200F\u202A-\u202E\u2066-\u2069]', $script:SafeEval)
}

function ConvertTo-SafeHtml {
    param($Value)
    return [System.Net.WebUtility]::HtmlEncode((Format-Safe ([string]$Value)))
}

function Format-Size {
    param([int64]$Bytes)
    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N2} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N1} KB' -f ($Bytes / 1KB)) }
    return "$Bytes B"
}

function Limit-Text {
    param([string]$Text, [int]$Max = 100)
    $t = Format-Safe $Text
    if ($t.Length -gt $Max) { return '...' + $t.Substring($t.Length - $Max) }
    return $t
}

function Test-Admin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Get-TextFromBytes {
    param([byte[]]$Bytes, [int]$Max = 4096)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return '' }
    $n = [Math]::Min($Bytes.Length, $Max)
    if ($n -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) { return [Text.Encoding]::Unicode.GetString($Bytes, 2, $n - 2) }
    if ($n -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) { return [Text.Encoding]::UTF8.GetString($Bytes, 3, $n - 3) }
    return [Text.Encoding]::UTF8.GetString($Bytes, 0, $n)
}

function Test-Magic {
    param([byte[]]$Head, [byte[]]$Magic)
    if ($Head.Length -lt $Magic.Length) { return $false }
    for ($i = 0; $i -lt $Magic.Length; $i++) { if ($Head[$i] -ne $Magic[$i]) { return $false } }
    return $true
}

function Get-Preview {
    param([byte[]]$Head, [bool]$IsText)
    if ($null -eq $Head -or $Head.Length -eq 0) { return '' }
    if ($IsText) {
        $t = (Get-TextFromBytes $Head 400)
        $t = ($t -replace '\s+', ' ').Trim()
        if ($t.Length -gt 160) { $t = $t.Substring(0, 160) + '...' }
        return (Format-Safe $t)
    }
    $n = [Math]::Min(24, $Head.Length)
    $hex = for ($i = 0; $i -lt $n; $i++) { $Head[$i].ToString('X2') }
    return ($hex -join ' ')
}

function New-BenignVerdict {
    param([string]$Pattern)
    return [PSCustomObject]@{ Severity = 'BENIGN'; KnownName = $Pattern }
}

# ---------------------------------------------------------------------------
# Verdict engine: looks at name, size, location AND content of one stream
# ---------------------------------------------------------------------------
function Get-StreamVerdict {
    param($F)

    $name  = [string]$F.Stream
    $path  = [string]$F.Path
    $size  = [int64]$F.Size
    $score = 0
    $reasons = New-Object System.Collections.Generic.List[string]

    $known = $null
    foreach ($k in $script:KnownStreams) { if ($name -like $k.Pattern) { $known = $k; break } }

    $readLen = 65536
    if ($null -ne $known) { $readLen = 4096 }
    $head = $null
    if ($size -gt 0) { $head = [AdsScanner]::ReadHead($path, $name, $readLen) }
    $hasHead = ($null -ne $head -and $head.Length -gt 0)

    # A known stream we cannot read is not worth alarming about
    if ($null -ne $known -and $size -gt 0 -and -not $hasHead) { return (New-BenignVerdict $known.Pattern) }

    # --- Zone.Identifier: normal = tiny "[ZoneTransfer]" text block ----------
    if ($name -eq 'Zone.Identifier') {
        $zoneHeader = $false
        if ($hasHead) { $zoneHeader = ((Get-TextFromBytes $head 512) -match '^\s*\[ZoneTransfer\]') }
        if ($zoneHeader -and $size -le 1024) { return (New-BenignVerdict 'Zone.Identifier') }
        if ($zoneHeader) {
            $score += 60
            $reasons.Add(('Zone.Identifier carries extra data ({0}; a real one is under 1 KB)' -f (Format-Size $size)))
        } elseif ($hasHead) {
            $score += 60
            $reasons.Add('Zone.Identifier does not contain a valid [ZoneTransfer] block')
        }
    }
    elseif ($null -ne $known -and $size -gt $known.Max) {
        $score += 40
        $reasons.Add(('larger than normal for a "{0}" stream ({1}; usual max {2})' -f $known.Pattern, (Format-Size $size), (Format-Size $known.Max)))
    }

    # --- baseline for unknown streams ---------------------------------------
    if ($null -eq $known) {
        $score += 10
        $reasons.Add('non-standard stream name (not a known Windows/app stream)')
        if ($F.IsDirectory) { $score += 10; $reasons.Add('stream is attached to a folder') }
        if ($path -match $script:RiskyFolderPattern) { $score += 10; $reasons.Add('located in a commonly abused folder') }
        if ($size -gt 1MB) { $score += 20; $reasons.Add(('large hidden stream ({0})' -f (Format-Size $size))) }
        if ($size -eq 0)   { $reasons.Add('empty stream (marker/placeholder)') }
        if ($size -gt 0 -and -not $hasHead) { $score += 10; $reasons.Add('stream is locked or unreadable - content could not be inspected') }
    }

    # --- name tricks ----------------------------------------------------------
    if ($name -match $script:ExeNamePattern) { $score += 40; $reasons.Add('stream name looks like an executable/script file') }
    if (($name -match $script:SpoofPattern) -or ($path -match $script:SpoofPattern)) {
        $score += 30; $reasons.Add('name contains Unicode direction-override characters (spoofing trick)')
    }

    # --- content analysis -------------------------------------------------------
    $sigName = $null
    $isText = $false
    if ($hasHead) {
        foreach ($s in $script:Signatures) {
            if (Test-Magic $head $s.Magic) { $sigName = $s.Name; $score += $s.Score; $reasons.Add(('content is a ' + $s.Name)); break }
        }

        $bom = ($head.Length -ge 2 -and (($head[0] -eq 0xFF -and $head[1] -eq 0xFE) -or ($head.Length -ge 3 -and $head[0] -eq 0xEF -and $head[1] -eq 0xBB -and $head[2] -eq 0xBF)))
        $isText = ($bom -or ([AdsScanner]::PrintableRatio($head) -ge 0.85))

        # script / command keywords (checked as UTF-8 and as UTF-16)
        $txt = Get-TextFromBytes $head 16384
        $hits = [regex]::Matches($txt, $script:ScriptPattern)
        if ($hits.Count -eq 0 -and $head.Length -ge 4) {
            $even = [Math]::Min(16384, $head.Length - ($head.Length % 2))
            $hits = [regex]::Matches([Text.Encoding]::Unicode.GetString($head, 0, $even), $script:ScriptPattern)
        }
        if ($hits.Count -gt 0) {
            $kw = @($hits | ForEach-Object { $_.Value.ToLower().Trim() } | Select-Object -Unique -First 4)
            $score += 60
            $reasons.Add('script/command keywords inside stream: ' + (Format-Safe ($kw -join ', ')))
        }
        if ($null -eq $known -and $txt -match $script:UrlPattern) { $score += 10; $reasons.Add('contains a URL') }

        # packed / encrypted payloads
        if ($null -eq $known -and $null -eq $sigName -and $size -ge 512) {
            $ent = [AdsScanner]::Entropy($head)
            if ($ent -gt 7.2) { $score += 30; $reasons.Add(('high-entropy data ({0:N2}/8) - looks encrypted, packed or compressed' -f $ent)) }
        }
    }

    if ($null -ne $known -and $score -eq 0) { return (New-BenignVerdict $known.Pattern) }

    $sev = 'LOW'
    if     ($score -ge 100) { $sev = 'CRITICAL' }
    elseif ($score -ge 60)  { $sev = 'HIGH' }
    elseif ($score -ge 30)  { $sev = 'MEDIUM' }

    $kind = 'Unreadable'
    if     ($null -ne $sigName) { $kind = $sigName }
    elseif ($isText)            { $kind = 'Text' }
    elseif ($hasHead)           { $kind = 'Binary data' }
    elseif ($size -eq 0)        { $kind = 'Empty' }

    $sha = ''
    if ($score -ge 30 -and $size -gt 0 -and $size -le 536870912) { $sha = [AdsScanner]::HashStream($path, $name) }

    return [PSCustomObject]@{
        Path        = $path
        Stream      = $name
        Size        = $size
        IsDirectory = [bool]$F.IsDirectory
        Severity    = $sev
        Score       = $score
        Reasons     = $reasons.ToArray()
        Kind        = $kind
        Sha256      = $sha
        Preview     = (Get-Preview $head $isText)
        KnownName   = $null
    }
}

# ---------------------------------------------------------------------------
# Run the scan engine, then classify everything it found
# ---------------------------------------------------------------------------
function Invoke-AdsScan {
    param([string[]]$Roots, [switch]$Quiet)

    $threads = [Math]::Min(8, [Math]::Max(2, [Environment]::ProcessorCount))
    $sw = [Diagnostics.Stopwatch]::StartNew()
    [AdsScanner]::Start($Roots, $threads)
    try {
        while (-not [AdsScanner]::Done) {
            Start-Sleep -Milliseconds 250
            if (-not $Quiet) {
                $status = '{0:N0} files | {1:N0} folders | {2:N0} streams found | {3:hh\:mm\:ss}' -f [AdsScanner]::FilesScanned, [AdsScanner]::DirsScanned, [AdsScanner]::FindingCount, $sw.Elapsed
                Write-Progress -Activity 'Hunting alternate data streams' -Status $status -CurrentOperation (Limit-Text ([AdsScanner]::Current) 100)
            }
        }
    }
    finally {
        if (-not [AdsScanner]::Done) { [AdsScanner]::Cancel = $true }
        if (-not $Quiet) { Write-Progress -Activity 'Hunting alternate data streams' -Completed }
    }

    $raw = [AdsScanner]::Findings.ToArray()
    $list = New-Object System.Collections.Generic.List[object]
    $benign = @{}
    $i = 0
    foreach ($f in $raw) {
        $i++
        if (-not $Quiet -and ($i % 200) -eq 0) {
            Write-Progress -Activity 'Analysing stream contents' -Status ("{0:N0} / {1:N0}" -f $i, $raw.Count) -PercentComplete ([int](100 * $i / $raw.Count))
        }
        $v = Get-StreamVerdict $f
        if ($v.Severity -eq 'BENIGN') { $benign[$v.KnownName] = 1 + [int]$benign[$v.KnownName] }
        else { $list.Add($v) }
    }
    if (-not $Quiet) { Write-Progress -Activity 'Analysing stream contents' -Completed }
    $sw.Stop()

    $sorted = @($list | Sort-Object -Property @{ Expression = 'Score'; Descending = $true }, @{ Expression = 'Path'; Descending = $false })
    return [PSCustomObject]@{
        Findings     = $sorted
        Benign       = $benign
        BenignTotal  = ($benign.Values | Measure-Object -Sum).Sum
        TotalStreams = $raw.Count
        Files        = [AdsScanner]::FilesScanned
        Dirs         = [AdsScanner]::DirsScanned
        Skipped      = [AdsScanner]::Errors
        Elapsed      = $sw.Elapsed
        Cancelled    = [AdsScanner]::Cancel
    }
}

# ---------------------------------------------------------------------------
# Console report
# ---------------------------------------------------------------------------
function Show-Findings {
    param($Result)
    $colors = @{ CRITICAL = 'Red'; HIGH = 'Red'; MEDIUM = 'Yellow'; LOW = 'Cyan' }
    $lowSeen = 0
    foreach ($f in $Result.Findings) {
        if ($f.Severity -eq 'LOW') { $lowSeen++; if ($lowSeen -gt 20) { continue } }
        $c = $colors[$f.Severity]
        Write-Host ''
        Write-Host ('  [{0}] {1}' -f $f.Severity, (Format-Safe $f.Path)) -ForegroundColor $c
        Write-Host ('      Stream : {0}   ({1}, {2})' -f (Format-Safe $f.Stream), (Format-Size $f.Size), $f.Kind) -ForegroundColor Gray
        Write-Host ('      Why    : {0}' -f (Format-Safe ($f.Reasons -join '; '))) -ForegroundColor Gray
        if ($f.Sha256)   { Write-Host ('      SHA-256: {0}' -f $f.Sha256) -ForegroundColor Gray }
        if ($f.Preview)  { Write-Host ('      Preview: {0}' -f $f.Preview) -ForegroundColor Gray }
        if (($f.Path + $f.Stream) -notmatch '[\x00-\x1F\u200B-\u200F\u202A-\u202E\u2066-\u2069]') {
            $pq = "'" + ($f.Path -replace "'", "''") + "'"
            $sq = "'" + ($f.Stream -replace "'", "''") + "'"
            Write-Host ('      Inspect: Get-Content -LiteralPath {0} -Stream {1} -Raw' -f $pq, $sq) -ForegroundColor DarkGray
            Write-Host ('      Remove : Remove-Item -LiteralPath {0} -Stream {1}' -f $pq, $sq) -ForegroundColor DarkGray
        }
    }
    if ($lowSeen -gt 20) {
        Write-Host ''
        Write-Host ('  ... plus {0} more LOW findings (all are in the HTML report)' -f ($lowSeen - 20)) -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------------------------
# HTML report (every value is escaped - file/stream names are attacker-controlled)
# ---------------------------------------------------------------------------
function New-HtmlReport {
    param($Result, [string]$OutPath, [string[]]$Targets, [bool]$IsAdmin)

    $counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
    foreach ($f in $Result.Findings) { $counts[$f.Severity]++ }

    if ($counts.CRITICAL -gt 0 -or $counts.HIGH -gt 0) { $verdict = 'Attention: high-risk hidden streams were found. Review them immediately.'; $vclass = 'bad' }
    elseif ($counts.MEDIUM -gt 0) { $verdict = 'Some hidden streams deserve a manual look.'; $vclass = 'warn' }
    else { $verdict = 'No suspicious alternate data streams found.'; $vclass = 'good' }

    $css = @'
body{font-family:"Segoe UI",Arial,sans-serif;margin:24px;color:#1b1b1b;background:#fafafa}
h1{color:#0b5cad;margin:0 0 4px}
h2{margin-top:32px;color:#333}
.meta{color:#666;font-size:13px;margin-bottom:16px}
.verdict{padding:14px 18px;border-radius:8px;font-size:17px;font-weight:600;margin:16px 0}
.verdict.bad{background:#f8d7da;color:#842029}.verdict.warn{background:#fff3cd;color:#664d03}.verdict.good{background:#d1e7dd;color:#0f5132}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin:12px 0}
.card{background:#fff;border:1px solid #ddd;border-radius:8px;padding:10px 16px;min-width:110px}
.card b{display:block;font-size:22px}
table{border-collapse:collapse;width:100%;background:#fff;font-size:13px}
th{background:#0b5cad;color:#fff;text-align:left;padding:8px;position:sticky;top:0}
td{padding:6px 8px;border-bottom:1px solid #e3e3e3;vertical-align:top;word-break:break-all}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;color:#fff;font-weight:700;font-size:12px}
.CRITICAL{background:#b02a37}.HIGH{background:#dc3545}.MEDIUM{background:#e0a800;color:#222}.LOW{background:#0dcaf0;color:#222}
tr.sev-CRITICAL{background:#fbe3e5}tr.sev-HIGH{background:#fdf0f1}tr.sev-MEDIUM{background:#fffaf0}
code{font-family:Consolas,monospace;font-size:12px}
.foot{color:#777;font-size:12px;margin-top:24px}
'@

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html><head><meta charset="utf-8"><title>ADS Hunter Report</title><style>')
    [void]$sb.AppendLine($css)
    [void]$sb.AppendLine('</style></head><body>')
    [void]$sb.AppendLine('<h1>ADS Hunter - Alternate Data Stream Report</h1>')
    [void]$sb.AppendLine(('<div class="meta">Generated: {0} | Host: {1} | User: {2} | Admin: {3} | Duration: {4:hh\:mm\:ss}<br>Scanned: {5}</div>' -f (Get-Date), (ConvertTo-SafeHtml $env:COMPUTERNAME), (ConvertTo-SafeHtml $env:USERNAME), $IsAdmin, $Result.Elapsed, (ConvertTo-SafeHtml ($Targets -join '  '))))
    [void]$sb.AppendLine(('<div class="verdict {0}">{1}</div>' -f $vclass, $verdict))
    [void]$sb.AppendLine('<div class="cards">')
    foreach ($s in 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW') { [void]$sb.AppendLine(('<div class="card"><span class="badge {0}">{0}</span><b>{1}</b></div>' -f $s, $counts[$s])) }
    [void]$sb.AppendLine(('<div class="card">Files scanned<b>{0:N0}</b></div>' -f $Result.Files))
    [void]$sb.AppendLine(('<div class="card">Folders<b>{0:N0}</b></div>' -f $Result.Dirs))
    [void]$sb.AppendLine(('<div class="card">Skipped (no access)<b>{0:N0}</b></div>' -f $Result.Skipped))
    [void]$sb.AppendLine('</div>')

    [void]$sb.AppendLine('<h2>Findings</h2>')
    if ($Result.Findings.Count -eq 0) {
        [void]$sb.AppendLine('<p>Nothing to report.</p>')
    } else {
        [void]$sb.AppendLine('<table><tr><th>Severity</th><th>File</th><th>Stream</th><th>Size</th><th>Type</th><th>Why flagged</th><th>SHA-256</th><th>Preview</th></tr>')
        foreach ($f in $Result.Findings) {
            [void]$sb.AppendLine(('<tr class="sev-{0}"><td><span class="badge {0}">{0}</span></td><td>{1}</td><td><code>{2}</code></td><td>{3}</td><td>{4}</td><td>{5}</td><td><code>{6}</code></td><td><code>{7}</code></td></tr>' -f `
                $f.Severity, (ConvertTo-SafeHtml $f.Path), (ConvertTo-SafeHtml $f.Stream), (Format-Size $f.Size), (ConvertTo-SafeHtml $f.Kind), `
                (ConvertTo-SafeHtml ($f.Reasons -join '; ')), (ConvertTo-SafeHtml $f.Sha256), (ConvertTo-SafeHtml $f.Preview)))
        }
        [void]$sb.AppendLine('</table>')
    }

    [void]$sb.AppendLine('<h2>Known-benign streams (verified by name, size and content)</h2>')
    if ($Result.Benign.Count -eq 0) {
        [void]$sb.AppendLine('<p>None.</p>')
    } else {
        [void]$sb.AppendLine('<table style="width:auto"><tr><th>Stream</th><th>Count</th></tr>')
        foreach ($e in ($Result.Benign.GetEnumerator() | Sort-Object Value -Descending)) {
            [void]$sb.AppendLine(('<tr><td><code>{0}</code></td><td>{1:N0}</td></tr>' -f (ConvertTo-SafeHtml $e.Key), $e.Value))
        }
        [void]$sb.AppendLine('</table>')
    }

    [void]$sb.AppendLine('<p class="foot">Nothing was modified by this scan. To look inside a stream: <code>Get-Content -LiteralPath &lt;file&gt; -Stream &lt;name&gt; -Raw</code>. To remove one: <code>Remove-Item -LiteralPath &lt;file&gt; -Stream &lt;name&gt;</code>. Do not run or open the payload of CRITICAL/HIGH findings; check the SHA-256 on a multi-engine scanner first.</p>')
    [void]$sb.AppendLine('</body></html>')

    [System.IO.File]::WriteAllText($OutPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($true)))
}

# ---------------------------------------------------------------------------
# Target discovery
# ---------------------------------------------------------------------------
function Get-ScanTargets {
    $roots = New-Object System.Collections.Generic.List[string]
    foreach ($d in [System.IO.DriveInfo]::GetDrives()) {
        try {
            $t = $d.DriveType.ToString()
            if (($t -eq 'Fixed' -or $t -eq 'Removable') -and $d.IsReady) {
                $fmt = $d.DriveFormat
                if ($fmt -eq 'NTFS' -or $fmt -eq 'ReFS') { $roots.Add($d.RootDirectory.FullName) }
            }
        } catch { }
    }
    return $roots.ToArray()
}

# ---------------------------------------------------------------------------
# Self-test: builds known hidden streams, scans them with the REAL pipeline,
# checks every verdict, cleans up.
# ---------------------------------------------------------------------------
function Invoke-SelfTest {
    $dir = Join-Path $env:TEMP ('ads-hunter-selftest-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $allOk = $true
    try {
        Write-Info "Building test files in: $dir"
        $utf8 = [Text.Encoding]::UTF8
        foreach ($n in 'plain.txt', 'invoice.pdf', 'readme.log', 'download.zip', 'photo.jpg', 'clean.txt') {
            Set-Content -LiteralPath (Join-Path $dir $n) -Value 'visible content'
        }

        [AdsScanner]::WriteStream((Join-Path $dir 'plain.txt'), 'note', $utf8.GetBytes('just a harmless note'))

        $fakePe = [byte[]](@(0x4D, 0x5A, 0x90, 0x00) + @($utf8.GetBytes('SELFTEST marker - this is not a real program')))
        [AdsScanner]::WriteStream((Join-Path $dir 'invoice.pdf'), 'payload.exe', $fakePe)

        [AdsScanner]::WriteStream((Join-Path $dir 'readme.log'), 'run', $utf8.GetBytes('powershell.exe -NoProfile -Command Write-Host selftest'))

        $zone = "[ZoneTransfer]`r`nZoneId=3`r`n"
        [AdsScanner]::WriteStream((Join-Path $dir 'download.zip'), 'Zone.Identifier', $utf8.GetBytes($zone))
        [AdsScanner]::WriteStream((Join-Path $dir 'photo.jpg'), 'Zone.Identifier', $utf8.GetBytes($zone + ('A' * 3000)))

        Write-Info 'Scanning test folder with the real engine...'
        $res = Invoke-AdsScan -Roots @($dir) -Quiet

        $checks = @(
            @{ Label = 'plain text stream detected (LOW)';              File = 'plain.txt';    Stream = 'note';            Expect = @('LOW') }
            @{ Label = 'fake executable in stream = CRITICAL';          File = 'invoice.pdf';  Stream = 'payload.exe';     Expect = @('CRITICAL') }
            @{ Label = 'script/command payload = HIGH or worse';        File = 'readme.log';   Stream = 'run';             Expect = @('HIGH', 'CRITICAL') }
            @{ Label = 'bloated Zone.Identifier is flagged';            File = 'photo.jpg';    Stream = 'Zone.Identifier'; Expect = @('HIGH', 'CRITICAL') }
        )
        foreach ($c in $checks) {
            $hit = $res.Findings | Where-Object { (Split-Path $_.Path -Leaf) -eq $c.File -and $_.Stream -eq $c.Stream } | Select-Object -First 1
            if ($hit -and ($c.Expect -contains $hit.Severity)) { Write-Good ('PASS  {0}  -> {1}' -f $c.Label, $hit.Severity) }
            else { Write-Bad ('FAIL  {0}  -> got: {1}' -f $c.Label, $(if ($hit) { $hit.Severity } else { 'not detected' })); $allOk = $false }
        }

        $zoneBenign = $res.Benign['Zone.Identifier']
        $zoneFalsePositive = $res.Findings | Where-Object { (Split-Path $_.Path -Leaf) -eq 'download.zip' }
        if ($zoneBenign -ge 1 -and -not $zoneFalsePositive) { Write-Good 'PASS  normal Zone.Identifier is treated as benign (no false alarm)' }
        else { Write-Bad 'FAIL  normal Zone.Identifier was not classified as benign'; $allOk = $false }

        $cleanHit = $res.Findings | Where-Object { (Split-Path $_.Path -Leaf) -eq 'clean.txt' }
        if (-not $cleanHit) { Write-Good 'PASS  file without hidden streams is not reported' }
        else { Write-Bad 'FAIL  clean file was reported'; $allOk = $false }
    }
    catch {
        Write-Bad "Self-test error: $($_.Exception.Message)"
        $allOk = $false
    }
    finally {
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Info 'Test files cleaned up.'
    }
    return $allOk
}

# ===========================================================================
# MAIN
# ===========================================================================
try { Clear-Host } catch { }
Write-Host ('=' * 64) -ForegroundColor White
Write-Host '   ADS-HUNTER v2 - Alternate Data Stream Scanner' -ForegroundColor White
Write-Host ('=' * 64) -ForegroundColor White

if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
    Write-Bad 'Alternate Data Streams exist only on NTFS/ReFS - this tool is Windows-only.'
    return
}

$isAdmin = Test-Admin
Write-Host ('Host: {0}   User: {1}   Admin: {2}   Time: {3}' -f $env:COMPUTERNAME, $env:USERNAME, $isAdmin, (Get-Date)) -ForegroundColor Gray
Write-Host ('-' * 64) -ForegroundColor DarkGray

# Offer a one-click relaunch as Administrator for complete coverage
if (-not $isAdmin -and -not $NoElevate -and -not $SelfTest -and -not $Path -and $PSCommandPath -and [Environment]::UserInteractive) {
    Write-Warn 'Not running as Administrator: system folders and other users'' profiles cannot be fully scanned.'
    $ans = Read-Host 'Relaunch as Administrator for a COMPLETE scan? [Y/n]'
    if ($ans -eq '' -or $ans -match '^\s*y(es)?\s*$') {
        try {
            $hostExe = (Get-Process -Id $PID).Path
            Start-Process -FilePath $hostExe -Verb RunAs -ArgumentList @('-NoProfile', '-NoExit', '-File', ('"{0}"' -f $PSCommandPath))
            Write-Info 'Elevated scan window opened - you can close this one.'
            return
        } catch {
            Write-Warn 'Elevation was cancelled - continuing with a limited (standard user) scan.'
        }
    }
}

# Compile the scan engine
if (-not ('AdsScanner' -as [type])) {
    try { Add-Type -TypeDefinition $AdsEngineSource -ErrorAction Stop }
    catch {
        Write-Bad "Could not compile the scan engine: $($_.Exception.Message)"
        Write-Warn 'Constrained Language Mode or security software may be blocking Add-Type.'
        return
    }
}

if ($SelfTest) {
    $ok = Invoke-SelfTest
    Write-Host ('-' * 64) -ForegroundColor DarkGray
    if ($ok) { Write-Good 'SELF-TEST PASSED: the whole pipeline works on this machine.' }
    else     { Write-Bad  'SELF-TEST FAILED: see the lines above.' }
    return
}

# Decide what to scan
$targets = @()
if ($Path) {
    foreach ($p in $Path) {
        $full = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($p)
        if (Test-Path -LiteralPath $full -PathType Container) { $targets += $full }
        else { Write-Warn "Not a folder, skipping: $p" }
    }
} else {
    $targets = @(Get-ScanTargets)
}
if ($targets.Count -eq 0) { Write-Bad 'Nothing to scan (no NTFS/ReFS drives or valid paths found).'; return }

Write-Info ('Targets : ' + ($targets -join '   '))
if ($isAdmin) { Write-Info 'Mode    : Administrator (full coverage)' }
else          { Write-Warn 'Mode    : Standard user (protected folders will be skipped)' }
Write-Info 'Scanning... (Ctrl+C stops the scan)'

$res = Invoke-AdsScan -Roots $targets

Write-Host ('-' * 64) -ForegroundColor DarkGray
$counts = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }
foreach ($f in $res.Findings) { $counts[$f.Severity]++ }

if ($res.Findings.Count -gt 0) {
    Write-Bad ('{0} hidden stream(s) need attention:' -f $res.Findings.Count)
    Show-Findings -Result $res
}

Write-Host ''
Write-Host ('-' * 64) -ForegroundColor DarkGray
Write-Host ' SUMMARY' -ForegroundColor White
Write-Host ('  Scanned   : {0:N0} files, {1:N0} folders in {2:hh\:mm\:ss}{3}' -f $res.Files, $res.Dirs, $res.Elapsed, $(if ($res.Cancelled) { '  (stopped early)' } else { '' })) -ForegroundColor Gray
Write-Host ('  Skipped   : {0:N0} items (no access / locked)' -f $res.Skipped) -ForegroundColor Gray
Write-Host ('  Benign    : {0:N0} known Windows/app streams verified and ignored' -f [int]$res.BenignTotal) -ForegroundColor Gray
Write-Host ('  Findings  : {0} CRITICAL, {1} HIGH, {2} MEDIUM, {3} LOW' -f $counts.CRITICAL, $counts.HIGH, $counts.MEDIUM, $counts.LOW) -ForegroundColor Gray

if ($counts.CRITICAL -gt 0 -or $counts.HIGH -gt 0) {
    Write-Bad 'VERDICT: high-risk hidden streams found. Do not open/run them; check the SHA-256 values and remove if malicious.'
} elseif ($counts.MEDIUM -gt 0) {
    Write-Warn 'VERDICT: some streams deserve a manual look (see details above).'
} else {
    Write-Good 'VERDICT: no suspicious alternate data streams found.'
}
if (-not $isAdmin -and $res.Skipped -gt 0) {
    Write-Warn 'Some locations were skipped - run as Administrator for a complete scan.'
}

# HTML report
if (-not $OutHtml) {
    $dirOut = [Environment]::GetFolderPath('Desktop')
    if (-not $dirOut -or -not (Test-Path -LiteralPath $dirOut)) { $dirOut = $env:TEMP }
    $OutHtml = Join-Path $dirOut ('ADS_Report_{0}.html' -f (Get-Date -Format 'yyyyMMdd_HHmm'))
}
try {
    New-HtmlReport -Result $res -OutPath $OutHtml -Targets $targets -IsAdmin $isAdmin
    Write-Good "HTML report written to: $OutHtml"
    try { Start-Process -FilePath $OutHtml } catch { }
} catch {
    Write-Warn "Could not write the HTML report: $($_.Exception.Message)"
}

Write-Host ''
Write-Host ('-' * 64) -ForegroundColor DarkGray
Write-Host 'Scan complete.' -ForegroundColor White