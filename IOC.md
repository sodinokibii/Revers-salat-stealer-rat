# IOC

## Файлы

| Файл | Размер | MD5 | SHA-1 | SHA-256 |
|---|---|---|---|---|
| внешний архив (zip, пароль infected) | 7428686 | 1fae061ec8e36991f20503d69c949797 | a4ef67e1b49a8427b40b9516018d865d7145bd07 | 589c44fccd361463b566ce68fa8a066d4c8494a99a990b74e9ec076d356379dc |
| вложенный архив (zip) | 7438750 | a1271541c0098606fb05741ea2dd2ae5 | 055f7ecee82eb03a61442384610fba4fe6d2914f | 9d64e52708ab78bf5e93b06d40cb08392ef8918987c2ce9ac2f0511ede89d4aa |
| DiscordFix.exe (загрузчик, Go 1.25) | 7356856 | 61d8a273b21a32ba2bab80a50c68f3ea | b568fec1560fffb8da3f44c37ca375c04f3d3284 | 83d2faf575026b3f75446a6337f004f5d81e66d5e2bfa19c44c6ef369fd1ec1a |
| вторая стадия (Go 1.24, пакет salat) | 12309504 | 58857c9fb0b9a3619991060faddd0a83 | ffc03f39e4b3e01dfc2a6c8648b1dc4987c2eb2c | 760ea7f9f1663f8c9e5b21938a1dd20e9ca50d2822583aecdf1d9010a434b2ac |

Остальное содержимое архива (настоящие компоненты zapret и WinDivert, по ним вредоносного кода не найдено):

| Файл | Размер | MD5 | SHA-1 | SHA-256 |
|---|---|---|---|---|
| bin/winws.exe | 204288 | f94c4b0110feccd6aeca48c93b278d8b | 0148ac55f074a602d37db9031a8f33912ad427d6 | 31d68a175abebab19f7f39bf6d0845ec5c18ab653eeeea6ee830b22d799b7e55 |
| bin/WinDivert.dll | 47616 | b2014d33ee645112d5dc16fe9d9fcbff | aa69498562d350f2de06954b133e59fac1e57002 | c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2 |
| bin/WinDivert64.sys | 94144 | 89ed5be7ea83c01d0de33d3519944aa5 | 4c9b9c74529399abacc2284de1dead5f2332ee9b | 8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2 |
| bin/cygwin1.dll | 2954293 | a1c82ed072dc079dd7851f82d9aa7678 | 52f26fa1aee39476f1c13438aec8bf969c78da45 | 103104a52e5293ce418944725df19e2bf81ad9269b9a120d71d39028e821499b |

В архиве все `general*.bat` и `service.bat` содержат одну строку `start DiscordFix.exe`.
У `DiscordFix.exe` подпись скопирована с `djoin.exe` и не проходит проверку (HashMismatch).
VirusTotal по `DiscordFix.exe`: 45 из 71, метки khalesi, rnqb, salatstealer.

## Сеть

- https://websalat.top/sa1at/
- https://sa1atik.cn/sa1at/
- https://wruser.org:992/sa1at/
- https://github.com/Netkucherish46/fdsf/raw/refs/heads/main/Staem.exe

## Прочее

- Мьютекс: `WEBR_LCEPXF63PS83`
- Сертификат оператора: `CN=Resolver, O=Ebeme, OU=Kurwa bobr`, RSA-2048, 2025-04-28 до 2035-04-26, SHA-256 `4f13cddd9fd6f996fd981bdb5d735daf54c83427557607b950a625f0804b2df8`
- Скрипт загрузки третьей стадии: PowerShell `DownloadFile` в `$env:TEMP\Staem.exe` и скрытый запуск
- Ключи схемы: затравка `biba`, XOR-ключ 26 байт `d0af20d0bbd18ed0b1d0bbd18e20d181d0bed181d0b0d182d18c`
