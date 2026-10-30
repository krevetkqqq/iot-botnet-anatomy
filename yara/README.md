# YARA

## Правила

| правило | что ловит | уверенность |
|---|---|---|
| `Linux_Protokol_Client_Proxy_Bot` | прокси-нода `protokol-client` (zicron/zollard/rsocks) | высокая, но **только по памяти/распакованному** — строки в файле зашифрованы |
| `Linux_Doorway_Loader_Script` | shell-лоадер, качающий ELF с сервера ботнета (`wget http://` + `chmod 777` + `/dev/shm`) | высокая |
| `Linux_ELF_Static_NoSectionHeaders` | статический ELF без section headers — типичный упакованный payload | низкая (эвристика, нужна ручная проверка) |

## Проверено

Стенд: macOS, `yara 4.5.8`.

```bash
yara -r yara/protokol_client.yar /path/to/scan
```

Результаты на реальных образцах из разбора:

| образец | сработало правило |
|---|---|
| `0w36m.arm5` (ELF ARM, payload из дампа) | `Linux_ELF_Static_NoSectionHeaders` |
| `fix-jjrei.sh` (их генератор лоадера) | `Linux_Doorway_Loader_Script` |
| произвольный текстовый файл | ничего (ложных срабатываний нет) |

## Почему первое правило не срабатывает на файле

`protokol-client` хранит строки в зашифрованном виде и расшифровывает их в памяти
при старте (проверено: `strings` по бинарнику даёт мусор, а в дампе памяти видны
`protokol-v1-nk`, `protokol-instances`, `/var/tmp/.dlr`). Поэтому:

- для **памяти** процесса: `yara -p <pid> yara/protokol_client.yar` (Linux, нужен
  доступ к `/proc/<pid>/mem`) или прогон по core-дампу;
- для **файлов** используйте третье правило как хантинг-эвристику и добивайте
  вручную (проверка строк после распаковки).

## Ограничения

- `Linux_ELF_Static_NoSectionHeaders` даёт ложные срабатывания на любых мелких
  stripped-бинарниках — не используйте его как единственный критерий.
- Правила не заменяют сетевые индикаторы (порты 8291–8299, 31281, комментарии
  `dw-socks` / `doorway-temp`).
