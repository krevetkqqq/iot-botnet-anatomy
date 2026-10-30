rule Linux_Protokol_Client_Proxy_Bot
{
    meta:
        description = "protokol-client — прокси-нода (zicron/zollard/rsocks)"
        author      = "krevetkqqk"
        date        = "2026-10-30"
        reference   = "analysis of botnet dump"
    strings:
        $a1 = "protokol-v1-nk" ascii
        $a2 = "protokol-instances" ascii
        $a3 = "protokol.single" ascii
        $a4 = "protokol-client.pid" ascii
        $a5 = "PROXY TCP4" ascii
        $a6 = "/var/tmp/.dlr" ascii
        $a7 = "/dev/.hidden" ascii
        $a8 = "KILLATTK" ascii
        $a9 = "LOLNOGTFO" ascii
        $b1 = { 01 00 63 20 }        // маркер порта 8291 в их логах
        $c1 = "socks4" ascii nocase
        $c2 = "socks5" ascii nocase
    condition:
        (3 of ($a*)) or (2 of ($c*) and 2 of ($a*)) or ($b1 and 2 of ($a*))
}

rule Linux_Doorway_Dropper_Loader
{
    meta:
        description = "shell-лоадер, качающий ELF с сервера ботнета"
    strings:
        $s1 = "wget http://" ascii
        $s2 = "curl -s http://" ascii
        $s3 = "chmod 777" ascii
        $s4 = "/dev/shm" ascii
        $s5 = " -O b" ascii
    condition:
        3 of them
}
