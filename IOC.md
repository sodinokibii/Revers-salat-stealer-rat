# IOC

## Файлы

| Файл | SHA-256 |
|---|---|
| DiscordFix.exe (загрузчик, Go 1.25) | 83d2faf575026b3f75446a6337f004f5d81e66d5e2bfa19c44c6ef369fd1ec1a |
| вторая стадия (Go 1.24, пакет salat) | 760ea7f9f1663f8c9e5b21938a1dd20e9ca50d2822583aecdf1d9010a434b2ac |
| winws.exe из архива | 31d68a175abebab19f7f39bf6d0845ec5c18ab653eeeea6ee830b22d799b7e55 |

В архиве все `general*.bat` и `service.bat` содержат одну строку `start DiscordFix.exe`.
У `DiscordFix.exe` подпись скопирована с `djoin.exe` и не проходит проверку (HashMismatch).

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
