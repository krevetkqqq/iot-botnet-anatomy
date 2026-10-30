# Abuse report — инфраструктура IoT-ботнета

Готовое письмо для провайдеров/хостеров. Отправлять на abuse-адреса, указанные
ниже. К письму приложить/указать ссылку на публичный разбор:
`https://github.com/krevetkqqq/iot-botnet-anatomy`

> ВАЖНО: перед отправкой подставь свои контакты и убедись, что в тексте нет
> адресов жертв и персональных данных — только инфраструктура злоумышленников.

---

## Кому отправлять

| провайдер | адрес | за что |
|---|---|---|
| RoyaleHosting BV (NL) | `abuse@royalehosting.nl` | файловый сервер раздачи payload'ов `45.90.13.169` |
| VPSVAULT.HOST LTD (AS215925) | abuse-адрес из whois их ASN | приёмник биконов `45.205.1.10` |
| AS209630 «Company 657aeb44…» (DE) | abuse по ASN | воркеры `151.243.11.240–242` |
| AKKUMYS KADYROVA (NL) | abuse по whois | второй приёмник `176.98.182.21` |
| TechTies Inc. | `abuse@tech-ties.net` | `87.121.84.78` |
| BlueVPS (SE) | abuse по whois | выведенный узел `46.246.97.179` |
| ISP из топ-ASN | abuse-адрес ISP | скомпрометированные устройства у них |

---

## Письмо (EN)

```
Subject: Abuse report — active IoT botnet infrastructure hosted in your network

Dear Abuse Team,

I am reporting infrastructure used for mass exploitation of IoT devices
(routers, cameras, DVRs) that is hosted in your address space. The report is
based on analysis of data published by the operators themselves; no devices
were accessed during the analysis.

Affected addresses in your network:
  <IP>  — <role: payload file server / beacon receiver / worker / scan server>

Observed activity:
  * mass brute-force of MikroTik RouterOS (Winbox ports 8291-8299, API 8728/8729),
    WebFig (80/8080) and Telnet using default credentials;
  * delivery of ELF/PE payloads ("token loaders") from the file server over
    HTTP/FTP/TFTP/raw-TCP, with per-architecture variants (arm5/arm7/mips/mipsel/
    aarch64/x86);
  * exploitation of known CVEs in IoT software, including CVE-2014-8361,
    CVE-2020-8958, CVE-2023-42495, CVE-2023-41011, CVE-2024-9441,
    CVE-2023-46604, CVE-2023-32315 and others;
  * beaconing: devices are instructed to send ICMP echo requests to the
    operator's receiver as an execution check;
  * on compromised routers the operators enable a SOCKS proxy
    (/ip socks port 31281) and add firewall rules with comments
    "dw-socks", "dw-src", "doorway-temp" to reach victim LANs.

Indicators (ports, paths, strings, YARA rules) and a full technical write-up:
  https://github.com/krevetkqqq/iot-botnet-anatomy

Please consider:
  1) suspending the reported services / notifying the account holder;
  2) preserving logs for law enforcement (the same infrastructure is used for
     credential theft and proxy traffic from victim networks);
  3) notifying affected downstream ISPs if you provide transit for the
     compromised devices.

I can provide additional technical details on request.

Regards,
<имя>, <контакт>, <дата>
```

---

## Письмо (RU)

```
Тема: Abuse-репорт — действующая инфраструктура IoT-ботнета в вашей сети

Здравствуйте!

Сообщаю об инфраструктуре, используемой для массовой эксплуатации IoT-устройств
(роутеры, камеры, DVR) и размещённой в вашем адресном пространстве. Отчёт основан
на анализе данных, опубликованных самими операторами; доступ к устройствам
в ходе анализа не осуществлялся.

Адреса в вашей сети:
  <IP>  — <роль: файловый сервер раздачи / приёмник биконов / воркер / скан-сервер>

Наблюдаемая активность:
  * массовый брутфорс MikroTik RouterOS (Winbox 8291–8299, API 8728/8729),
    WebFig (80/8080) и Telnet по заводским паролям;
  * доставка ELF/PE payload'ов с файлового сервера по HTTP/FTP/TFTP/raw-TCP
    с вариантами под архитектуры (arm5/arm7/mips/mipsel/aarch64/x86);
  * эксплуатация известных CVE в IoT-ПО, в т.ч. CVE-2014-8361, CVE-2020-8958,
    CVE-2023-42495, CVE-2023-41011, CVE-2024-9441, CVE-2023-46604,
    CVE-2023-32315;
  * биконы: устройствам даётся команда отправлять ICMP echo на приёмник
    операторов как проверка выполнения;
  * на скомпрометированных роутерах включается SOCKS-прокси
    (/ip socks port 31281) и добавляются правила файрвола с комментариями
    "dw-socks", "dw-src", "doorway-temp" — через них ходят во внутренние сети
    жертв.

Индикаторы (порты, пути, строки, YARA) и полный разбор:
  https://github.com/krevetkqqq/iot-botnet-anatomy

Прошу рассмотреть:
  1) блокировку/приостановку указанных сервисов и уведомление владельца;
  2) сохранение логов для правоохранительных органов (та же инфраструктура
     используется для кражи учётных данных и прокси-трафика из сетей жертв);
  3) уведомление провайдеров скомпрометированных устройств.

Готов предоставить дополнительные технические детали.

С уважением,
<имя>, <контакт>, <дата>
```

---

## Что приложить

1. Ссылка на репозиторий с разбором и IOC.
2. Список конкретных IP из их сети с ролью (файловый сервер, бикон, воркер).
3. Хеши сэмплов (если есть) — SHA-256, без вложений с ВПО.
4. Даты активности (по логам: пики 10 и 12 октября 2026).
