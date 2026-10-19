# Week 7 · Task 2 — empty the ARP table, refill it, and capture ARP on Wi-Fi.
#
#     powershell -ExecutionPolicy Bypass -File task2_capture.ps1
#
# Capture runs as the normal user (Npcap); only the cache clear needs
# Administrator, so that one command goes through a UAC prompt.
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$out = Join-Path $here "out"
$tshark = "C:\Program Files\Wireshark\tshark.exe"
$iface = "Wi-Fi"
$seconds = 75                      # >= 60 s so B4 can count one minute of ARP
$gw = (Get-NetIPConfiguration -InterfaceAlias $iface).IPv4DefaultGateway.NextHop

function Stamp($label) { "# $label  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff')" }

(Stamp "arp -a before clearing"), (arp -a) | Out-File -Encoding utf8 "$out\arp-before.txt"

$cap = Start-Process $tshark -PassThru -NoNewWindow -ArgumentList `
    "-i", $iface, "-f", "arp", "-a", "duration:$seconds", "-w", "`"$out\arp.pcapng`""
Start-Sleep -Seconds 3

Start-Process netsh -Verb RunAs -Wait -WindowStyle Hidden `
    -ArgumentList "interface", "ip", "delete", "arpcache"
(Stamp "arp -a right after clearing"), (arp -a) | Out-File -Encoding utf8 "$out\arp-cleared.txt"

$log = @((Stamp "ping -n 3 $gw"))
$log += ping -n 3 $gw
$log += Stamp "curl https://www.korea.ac.kr"
$log += curl.exe -s -o NUL -w "http %{http_code} remote %{remote_ip}`n" https://www.korea.ac.kr
$log | Out-File -Encoding utf8 "$out\arp-refill-console.txt"

(Stamp "arp -a after ping + curl"), (arp -a) | Out-File -Encoding utf8 "$out\arp-after.txt"

$cap.WaitForExit()
"capture done: $out\arp.pcapng"
