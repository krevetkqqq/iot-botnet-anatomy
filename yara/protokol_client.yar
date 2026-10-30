import "elf"

/*
   yara rules: IoT botnet artifacts (protokol-client proxy node + doorway loaders)

   Notes:
   - Strings from the protokol-client binary are decrypted at runtime, so the
     on-disk sample will NOT match rule 1. Use it against memory dumps and
     unpacked samples; rule 3 covers on-disk hunting for packed ELF.
   - Thresholds in rule 3 are heuristics: expect false positives on small
     stripped static binaries; combine with network IOCs.

   Author: krevetkqqq
*/

rule Linux_Protokol_Client_Proxy_Bot
{
    meta:
        description = "protokol-client proxy node bot (zicron/zollard/rsocks)"
        family      = "protokol"
        reference   = "https://github.com/krevetkqqq/iot-botnet-anatomy"
        confidence  = "high (memory/unpacked)"
    strings:
        $a1 = "protokol-v1-nk" ascii wide
        $a2 = "protokol-instances" ascii wide
        $a3 = "protokol.single" ascii wide
        $a4 = "protokol-client.pid" ascii wide
        $a5 = "PROXY TCP4" ascii
        $a6 = "/var/tmp/.dlr" ascii
        $a7 = "/dev/.hidden" ascii
        $a8 = "KILLATTK" ascii
        $a9 = "LOLNOGTFO" ascii
        $c1 = "socks5" ascii nocase
        $c2 = "no single" ascii nocase
    condition:
        (3 of ($a*)) or (2 of ($c*) and 2 of ($a*))
}

rule Linux_Doorway_Loader_Script
{
    meta:
        description = "shell token-loader that pulls an ELF payload from the botnet file server"
        family      = "doorway"
        reference   = "https://github.com/krevetkqqq/iot-botnet-anatomy"
        confidence  = "high"
    strings:
        $w1 = "wget http://" ascii
        $w2 = "curl -s http://" ascii
        $w3 = "busybox wget" ascii
        $c1 = "chmod 777" ascii
        $c2 = "chmod +x" ascii
        $d1 = "/dev/shm" ascii
        $o1 = " -O b" ascii
        $o2 = "-o b " ascii
    condition:
        filesize < 8KB and 1 of ($w*) and 1 of ($c*) and ($d1 or $o1 or $o2)
}

rule Linux_ELF_Static_NoSectionHeaders
{
    meta:
        description = "static ELF with section headers stripped (typical packed IoT payload)"
        confidence  = "low (heuristic)"
    condition:
        uint32(0) == 0x464c457f and
        filesize < 1MB and
        elf.number_of_sections == 0
}
