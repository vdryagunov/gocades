# gocades

Библиотека на Go для работы с КриптоПро: подписи CAdES и CryptoAPI через cgo.
Это порт [pycades](https://github.com/CryptoPro/pycades) с той же моделью
объектов; весь API лежит в одном пакете `gocades`. Порт делался под
**КриптоПро CSP 5.0 R3** (в тестовых наборах — сборка `5.0.13003`).

В репозитории есть вспомогательный код для PAdES (`internal/pdfsign`) и
утилита `cmd/pdfsign`. Они только для проверки: подписать PDF и посмотреть,
что его принимают сторонние средства вроде `pdfsig` из poppler. В публичный
API библиотеки это не входит.

Подключение:

```go
import "github.com/vdryagunov/gocades" // package gocades
```

## Оглавление

- [Соответствие pycades](#соответствие-pycades)
  - [Что уже есть](#что-уже-есть)
  - [Чем отличается от pycades](#чем-отличается-от-pycades)
- [Быстрый старт](#быстрый-старт)
  - [Что установить](#что-установить)
  - [Сборка утилит и дистрибутива](#сборка-утилит-и-дистрибутива)
- [Структура репозитория](#структура-репозитория)
- [Требования](#требования)
- [Сборка](#сборка)
- [Самопроверка (smoke)](#самопроверка-smoke)
- [Проверка в Linux-контейнере](#проверка-в-linux-контейнере)
- [Образ с установленным КриптоПро](#образ-с-установленным-криптопро)
- [Образы для GitHub Actions (GHCR)](#образы-для-github-actions-ghcr)
- [PAdES (`internal/pdfsign`)](#pades-internalpdfsign)
- [Известные ограничения](#известные-ограничения)
  - [Не поддерживается](#не-поддерживается)
  - [Поведение, о котором легко споткнуться](#поведение-о-котором-легко-споткнуться)
  - [Ограничения окружения (это не баг кода)](#ограничения-окружения-это-не-баг-кода)

## Соответствие pycades

Порт закрывает те же сценарии, что pycades, через C-интерфейс КриптоПро
(`cades.h` и CryptoAPI). Своего C++ и boost в проекте нет. Отличается в
основном синтаксис: вместо Python-свойств — обычные методы Go.

| В pycades | В gocades |
| --- | --- |
| `Store()` + `.Open(loc, name)` | `NewStore()` / `OpenStore` + `.Open` |
| свойство `obj.Name` | метод `obj.Name()` |
| присваивание `obj.Content = x` | `obj.SetContent(x)` |
| исключение | значение `error` (`*gocades.Error` для HRESULT) |
| `VARIANT` / `BSTR` / `datetime` | `[]byte`, `string`, `bool`, `time.Time` (UTC) |

### Что уже есть

| Область | Статус |
| --- | --- |
| About / Version / Algorithm | готово (`PluginVersion` на Linux не нужен) |
| Store, сертификаты, CRL | готово (`Find`/`First`, `ImportPFX`, расширения, `IsValid`/`IsValidWith`) |
| CAdES и CMS (`SignedData`, `Signer`, атрибуты, `Enhance`) | готово |
| HashedData, RawSignature, Symmetric, EnvelopedData | готово; `DiversifyKey` сознательно не делали |
| Enroll (контейнеры и ключи) | готово |
| Запрос PKCS#10 (CX509: ключ, DN, `CreateRequest`, `InstallResponse`) | готово; без CMC и полного набора расширений CertEnroll |
| XMLDSig / XAdES | готово |
| Windows | не поддерживается |

Подробная таблица «метод за методом» и список примечаний —
в [`pycades-comparison.md`](pycades-comparison.md).

### Чем отличается от pycades

- При ошибке проверки подписи возвращается `*VerifyError` (аналог исключения
  в pycades) вместе с `VerificationInfo`. Проверяются все подписанты —
  результаты в `Signers()`.
- `IsValid` по умолчанию ходит в сеть за отзывом (как CAdESCOM). Для работы
  без сети есть `IsValidWith` с нужными опциями.
- В `Store.Find` нет поиска по шаблону, расширению, имени корня и политикам —
  таких режимов нет в эмуляции CryptoAPI. Остальные критерии работают.
- В CMS по умолчанию кладётся сертификат подписанта и цепочка без корня
  (меняется через `SetOptions` / `SignOptions.Include`).
- `DiversifyKey` нет: схема диверсификации у КриптоПро не описана публично.
  Для шифрования данных используйте `EnvelopedData`.
- Полный CertEnroll (коллекции расширений, CMC) не переносили.

## Быстрый старт

```bash
make deps     # зависимости сборки под текущую ОС (Linux / macOS)
make doctor   # компилятор, SDK КриптоПро, лицензия, контейнеры ключей
make build test
SMOKE_PIN=<пин> make smoke
```

Примеры использования (как `samples` в pycades) — в [`samples/`](samples/):

```bash
GOCADES_PIN=... go run ./samples/sign_verify
go run ./samples/enum_containers
```

`make doctor` покажет, чего не хватает, и завершится с ненулевым кодом —
его удобно ставить первым шагом в CI.

Кэш сборки Go лежит в обычном каталоге пользователя и не попадает в
репозиторий. Если писать туда нельзя (песочница, контейнер), задайте
`GO_LOCAL_CACHE=1` — кэш будет в `./.gocache`.

### Что установить

| Компонент | Linux | macOS |
|---|---|---|
| Компилятор, make | `gcc`/`g++` + `libc6-dev` (Debian) или `glibc-devel` (RHEL) | Xcode Command Line Tools |
| Go ≥ 1.22 | с [go.dev/dl](https://go.dev/dl) или из пакетов дистрибутива | `brew install go` |
| SDK КриптоПро (CSP 5.0 R3) | `lsb-cprocsp-devel`, `cprocsp-pki-cades` | установщик CryptoPro ECP (`.pkg`) |

`make deps` ставит компилятор и Go (если нужно). Сам КриптоПро скрипт не
ставит — это лицензионный продукт. Он только проверяет SDK и подсказывает
команду для установки из уже распакованного вендорского набора:

```bash
sudo ./install.sh --yes kc1 lsb-cprocsp-devel cprocsp-pki-cades
```

Windows не поддерживается: библиотека рассчитана на Linux-эмуляцию CryptoAPI
и на CryptoPro ECP в macOS.

### Сборка утилит и дистрибутива

```bash
make binaries   # bin/smoke, bin/pdfsign
make dist       # dist/gocades-$(VERSION).tar.gz
```

## Структура репозитория

```
.
├── *.go, gocades.c, gocades.h   сама библиотека (package gocades)
├── cmd/smoke/                   проверка окружения на живом CSP
├── cmd/pdfsign/                 подпись PDF для внешней проверки
├── internal/pdfsign/            PAdES на чистом Go (Prepare/Assemble, штамп)
├── internal/pdfcheck/           проверка PDF через pdfinfo/pdfsig
├── docker/                      прогон в контейнерах (см. docker/README.md)
│   ├── local/                   образы для локального verify-crypto
│   ├── ghcr/                    образы для GitHub Actions / GHCR
│   └── packages/                архивы КриптоПро (*.tgz скачать и положить; в git нет)
├── samples/                     примеры (как samples в pycades)
├── scripts/                     check-deps, install-deps, gen-error-names
└── pycades-comparison.md        сравнение API с pycades
```

## Требования

- **Linux** (Debian/Ubuntu, AlmaLinux/CentOS), amd64 или arm64, с пакетами
  `lsb-cprocsp-devel`, `lsb-cprocsp-capilite`, `cprocsp-pki-cades`.
- **macOS** с установленным CryptoPro ECP (`CryptoPro_ECP.app`).
- Включённый cgo (`CGO_ENABLED=1`) и C-компилятор: `gcc` на Linux, `clang` на
  macOS.

| Платформа | Заголовки | Библиотеки |
|---|---|---|
| Linux | `/opt/cprocsp/include/{,cpcsp,pki,pki/atl,pki/cplib}` | `/opt/cprocsp/lib/{amd64,aarch64}` |
| macOS | `/Applications/CryptoPro_ECP.app/Contents/Resources/include/pki{,/cplib}`, `/opt/cprocsp/include{,/cpcsp}` | `/Applications/CryptoPro_ECP.app/Contents/MacOS/lib`, `/opt/cprocsp/lib` |

Эти пути прописаны в `#cgo` в файле `cades.go`. Библиотеки линкуются так:
`-lxades -lcades -lcapi20 -lcapi10 -lrdrsup`.

На macOS API разнесён по двум библиотекам: в `libcapi10` — провайдер
(`CryptAcquireContext`, `CryptSignHash` и т.д.), в `libcapi20` — сообщения и
сертификаты (`CryptMsg*`, `Cert*`). `GetLastError` — в `librdrsup`.

## Сборка

```bash
make doctor
CGO_ENABLED=1 go build ./...
```

Если линкер ругается на C++-символы из `libcades`, добавьте `-lstdc++` в
`LDFLAGS` в `cades.go`. Наш код на C; C++ тянется только как зависимость
вендорской библиотеки. Для XMLDSig/XAdES нужна `libxades` — она уже указана
в `#cgo` перед `-lcades`.

## Самопроверка (smoke)

Утилита `cmd/smoke` прогоняет основные сценарии на установленном КриптоПро и
печатает PASS / FAIL / SKIP / WARN. Без PIN выполняются только операции
чтения. PIN берётся из переменной окружения, чтобы не светился в `ps`.

```bash
make smoke                                   # без подписи
SMOKE_PIN=... make smoke                     # полный прогон
SMOKE_PIN=... make smoke THUMBPRINT=9f3c...  # конкретный сертификат
SMOKE_PIN=... make smoke SMOKE_TSA=http://qs.cryptopro.ru/tsp/tsp.srf
SMOKE_PFX=key.pfx SMOKE_PFX_PASSWORD=... make smoke
SMOKE_PIN_PROMPT=1 make smoke                # PIN в окне КриптоПро
```

При `SMOKE_PIN_PROMPT=1` вызывается подпись без `SetPIN`: КриптоПро сам
спросит PIN в своём окне (только GUI-сессия на macOS; вместе с `SMOKE_PIN`
не использовать). Для `SMOKE_PFX` нужен сертификат с цепочкой до
доверенного корня; ключ импортируется без сохранения контейнера на диск
(`PFXNoPersistKey`).

На macOS КриптоПро пишет кэш хранилищ на диск — запускайте smoke из обычного
терминала. В сильно ограниченной песочнице иногда бывает ошибка `0x8009001D`.

## Проверка в Linux-контейнере

Скрипт `docker/verify-linux.sh` собирает и тестирует библиотеку во временном
контейнере. Так можно проверить Linux-сборку, сидя на macOS. Компилятор и Go
ставятся внутри контейнера; пакеты КриптоПро берутся из `docker/packages`.

Архивы `*.tgz` в репозиторий не входят (лицензия КриптоПро). Перед локальным
прогоном скачайте нужный набор с сайта КриптоПро и положите файл в
`docker/packages/` — какие имена и для каких `DISTRO`/`ARCH`, см.
[`docker/packages/README.md`](docker/packages/README.md).

```bash
make verify-linux DISTRO=debian
make verify-linux DISTRO=almalinux
ARCH=arm64 make verify-linux DISTRO=debian   # нативно на Apple Silicon
```

Внутри выполняются `make doctor`, `build`, `vet`, `test`, `c-syntax`.
Параметры: `DISTRO`, `ARCH`, `GO_VERSION`, `IMAGE`, `PKGS`, `VENDOR_DIR`.

## Образ с установленным КриптоПро

Локальный прогон целиком в одном образе: `docker/local/Dockerfile.*`
(внутри уже исходники и скрипт проверки). Нужен тот же архив в
`docker/packages/`, что и для `verify-linux`.

```bash
make verify-crypto DISTRO=debian STRICT=1
make verify-crypto DISTRO=almalinux
```

В контейнере у CSP 5.0 нет нормального ГСЧ, поэтому образы собирают
вендорский плагин RNG (`src/rdk/rndm0`) на `getrandom()` / `/dev/urandom` и
регистрируют его через `cpconfig`. Для тестов создаётся одноразовый
сертификат: он попадает в `uMy` и одновременно в доверенные корни `mRoot`.

`STRICT=1` — пропуск шага подписи считается ошибкой.
`COVERDIR=/tmp/cov` — сбор покрытия. На хосте: `make cover`; только юнит-тесты —
`SKIP_INT=1 make cover`.

Чем `local/` отличается от `ghcr/` — в [`docker/README.md`](docker/README.md).

## Образы для GitHub Actions (GHCR)

В `docker/ghcr/` — образы только с CSP и RNG: без Go, без исходников и без
автозапуска тестов. В Actions Go ставит `setup-go` и монтируется в контейнер;
репозиторий монтируется в `/work`, дальше вызывается
`verify-crypto-inner.sh`.

```bash
make -C docker ghcr-push-all \
  VERSION=v1.0.1 \
  GHCR_IMAGE=ghcr.io/<owner>/gocades-test
```

Теги: `v1.0.0-debian-amd64` и ещё три варианта платформ, плюс
`gocades-test:v1.0.0` и `gocades-test:latest` (оба = debian-amd64).

В настройках репозитория: `CRYPTO_IMAGE_REPO=ghcr.io/<owner>/gocades-test` и
при желании `CRYPTO_IMAGE_VERSION=v1.0.0`. Пакет в GHCR сделайте **Private** и
дайте репозиторию доступ Read (Manage Actions access). Подробности и матрица
CI — в [`docker/README.md`](docker/README.md).

## PAdES (`internal/pdfsign`)

Вспомогательный код на чистом Go, не часть публичного API.
`Prepare` добавляет в PDF ревизию с местом под подпись.
`Assemble` записывает готовый CMS в `/Contents`. Уже записанные байты
документа не меняются.

Подпись на машине с КриптоПро:

```go
prep, err := pdfsign.Prepare(pdf, pdfsign.Options{})
cms, err := gocades.SignDetached(cert, prep.SignedContent(), gocades.SignOptions{
    Type: gocades.CadesBES,
})
signed, err := prep.Assemble(cms)
```

Если дайджест подписывает браузерный плагин: сначала `Prepare` с `NewHash`,
подпись снаружи, затем `Assemble`.

```bash
make binaries
bin/pdfsign -in contract.pdf
CRYPTOPRO_PIN=... bin/pdfsign -in contract.pdf -type T -tsa http://tsa.example/
bin/pdfsign -in contract.pdf -stamp -stamp-corner br -signer "Иванов И.И."
```

Видимый штамп рисуется шрифтом Type3 из контуров TrueType (для кириллицы
нужен подходящий `.ttf`; можно взять `pdfsign.SystemFont()`). Готовый файл
проверяют так: `VerifyDetached` по байтам `/ByteRange` и утилиты poppler
`pdfinfo` / `pdfsig` (пакет `poppler-utils`).

## Известные ограничения

### Не поддерживается

- **Windows** — не планировали; цель — Linux и macOS.
- **PAdES B-LT / LTA** (DSS, DocTimeStamp на стороне PDF) — нет. Есть B-B и
  B-T (`Prepare`/`Assemble`, при необходимости TSA).
- **`SymmetricAlgorithm.DiversifyKey`** — всегда `ErrUnsupported`: схема
  диверсификации КриптоПро не документирована, ошибочная реализация дала бы
  тихий неверный ключ. Для защиты данных используйте `EnvelopedData`.
- **Полный CertEnroll** — PKCS#10 (`CreateRequest` / `InstallResponse`) есть;
  CMC и коллекции `CX509Extension*` как в COM не переносили.
- Часть режимов **`Store.Find`** (шаблон, расширение, имя корня, политики) —
  в эмуляции CryptoAPI нет соответствующих `CERT_FIND_*`.

### Поведение, о котором легко споткнуться

- После `Certificate.SetPIN` провайдер остаётся открытым и привязан к
  сертификату. Окно PIN больше не показывается — так и задумано.
- CMS без встроенного сертификата подписанта локальный КриптоПро ещё может
  принять (находит сертификат в хранилище), а CryptoARM, Adobe или сервис ЭДО —
  нет («Certificate is empty»). Признак: CMS в сотни байт вместо примерно 1 КБ.
  По умолчанию порт встраивает сертификат и цепочку без корня.
- `Store.Add` / `AddCRL` / `Remove` сразу пишут изменения на диск. Иначе
  движок цепочек не увидит новый корень или CRL, пока хранилище не закроют.
- `CadesDefault` при проверке — не «любой CMS», а требование X Long Type 1.
  Обычный CMS проверяйте как `CadesPKCS7` (так делает `SignedData.Verify`).
- `IsValid` по умолчанию проверяет отзыв онлайн. Без доступа к CRL/OCSP
  результат будет `false`; без сети используйте `IsValidWith`.
- Хеш по умолчанию — ГОСТ Р 34.11-2012 256 (OID `1.2.643.7.1.1.2.2`).
- Целевая платформа порта — **КриптоПро CSP 5.0 R3** (`5.0.13003` в
  Linux-архивах). CAdES SDK: Linux 2.0.15003, macOS ECP 2.0.15820. Биндинг
  собран под более старый ABI, одна сборка работает с обоими.

### Ограничения окружения (это не баг кода)

- **CAdES-T / `Enhance`**: нужна действующая лицензия «КриптоПро TSP Client».
  На хосте без неё типичен `0xC2100140`. В контейнере мешает ещё и
  недоступность CRL корней (например Минцифры) с зарубежного IP. Рабочий
  тестовый TSA: `http://qs.cryptopro.ru/tsp/tsp.srf`.
- На macOS smoke лучше запускать из обычного терминала: в песочнице
  КриптоПро иногда отвечает `0x8009001D` (не удаётся открыть хранилище).
- В Docker у CSP 5.0 нет штатного ГСЧ — образы `verify-crypto` ставят
  программный плагин на `getrandom()`; без него генерация ключей падает с
  `0x80090020`.

Подробное сравнение с pycades — в
[`pycades-comparison.md`](pycades-comparison.md).
