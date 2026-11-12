# Архивы КриптоПро (только для тестов)

Файлы `*.tgz` в git **не коммитятся** (см. `.gitignore`). Для локальной
сборки контейнеров их нужно скачать самому и положить в этот каталог.

Источник: <https://www.cryptopro.ru/> → «Загрузка» → «КриптоПро CSP 5.0 R3»
(набор с CSP + CAdES SDK). Имена файлов:

| Файл | Для чего |
| --- | --- |
| `linux-amd64_deb.tgz` | Debian/Ubuntu amd64 |
| `linux-arm64_deb.tgz` | Debian/Ubuntu arm64 |
| `linux-amd64.tgz` | AlmaLinux/RHEL amd64 |
| `linux-arm64.tgz` | AlmaLinux/RHEL arm64 |

Достаточно того варианта, который будете гонять. После этого:

```bash
make verify-linux  DISTRO=debian|almalinux [ARCH=amd64|arm64]
make verify-crypto DISTRO=debian|almalinux [STRICT=1]
VERSION=v1.0.0 ./docker/publish-ghcr.sh all
```

Обычные `make build test dist` на хосте с уже установленным КриптоПро эти
архивы не требуют. Окружения описаны в [`../README.md`](../README.md).

## Как ими пользуются скрипты

| Цель | Скрипт | Роль архива |
| --- | --- | --- |
| Сборка и тесты без постоянного образа | `verify-linux.sh` | Монтируется в `/packages:ro`; CSP ставится во временном контейнере |
| Локальный smoke | `verify-crypto.sh` → `local/Dockerfile.*` | Context = **корень модуля**; `CRYPTOPRO_PKG` → `COPY` → `install.sh` |
| Образ для GHCR / Actions | `publish-ghcr.sh` → `ghcr/Dockerfile.*` | Context = **`docker/`**; при сборке каталог `packages` монтируется (в слои образа не копируется) |

Какой файл взять — решает `docker/lib.sh` (`pkg_set`):

| `DISTRO` / `ARCH` | Архив |
| --- | --- |
| `debian` / `amd64` | `linux-amd64_deb.tgz` |
| `debian` / `arm64` | `linux-arm64_deb.tgz` |
| `almalinux` / `amd64` | `linux-amd64.tgz` |
| `almalinux` / `arm64` | `linux-arm64.tgz` |

Переопределения: `VENDOR_DIR`, `PKGS`. Для `local/` путь к архиву должен быть
внутри корня модуля (build context). Для `ghcr/` достаточно файлов в этом
каталоге.

Локальный тег: `gocades-crypto:$DISTRO-$ARCH`.
GHCR: `ghcr.io/<owner>/gocades-test:v1.0.0-…` / `:latest` (см. `publish-ghcr.sh`).

## Наборы (формат внутри архива)

| Файл | Формат | Архитектура | Для чего |
| --- | --- | --- | --- |
| `linux-amd64_deb.tgz` | `.deb` | amd64 | Debian/Ubuntu |
| `linux-arm64_deb.tgz` | `.deb` | arm64 | Debian/Ubuntu |
| `linux-amd64.tgz` | `.rpm` | amd64 | AlmaLinux/RHEL/CentOS |
| `linux-arm64.tgz` | `.rpm` | aarch64 | AlmaLinux/RHEL/CentOS |

Порт и проверки рассчитаны на **КриптоПро CSP 5.0 R3**. В архивах —
сборка `5.0.13003`, CAdES SDK `2.0.15003`. Размер порядка ~136 MB на архив —
в git и в `make dist` не входят.

## Что нужно для сборки порта

Каждый набор самодостаточен. Установка:

```bash
./install.sh --yes kc1 lsb-cprocsp-devel cprocsp-pki-cades
```

| Компонент | Откуда | Что даёт |
| --- | --- | --- |
| `lsb-cprocsp-base` | зависимость | локали, маны |
| `lsb-cprocsp-kc1-64` | явно | `libcsp.so` (ядро CSP) |
| `lsb-cprocsp-capilite-64` | зависимость `kc1` | `libcapi20.so` |
| `lsb-cprocsp-rdr-64` | зависимость `kc1` | `libcapi10.so`, `librdrsup.so` |
| `lsb-cprocsp-devel` | явно | `include/cpcsp/*.h`, `include/pki/atl/`, исходники RNG-плагина `src/rdk/rndm0` |
| `cprocsp-pki-cades-64` | явно | `include/pki/{cades,xades,ades-core}.h`, `lib{cades,xades,…}.so` |

В crypto-образах у CSP 5.0 в контейнере нет штатного ГСЧ, поэтому собирают
`src/rdk/rndm0` с `getrandom()` (force-include `docker/rng/cp_getrandom.h`) и
регистрируют через `cpconfig`.

Каталог `include/pki/cplib` в наборах **отсутствует** (он есть в PHP-обвязке).
Порту он не нужен.

## Проверено

| Дистрибутив | amd64 | arm64 |
| --- | --- | --- |
| `debian:bookworm-slim` | ok | ok |
| `almalinux:9` | ok | ok |

Полный `make verify-crypto … STRICT=1` (Debian arm64, с подписью и
`SMOKE_PFX`): `passed 41, failed 0, skipped 0, warnings 0`. С `SMOKE_TSA`
шаги CAdES-T могут падать из‑за окружения (лицензия TSP / недоступный CRL).

## Лицензия

Пакеты по лицензии КриптоПро: не коммитить и не класть в дистрибутив.
Образы GHCR с CSP держите **Private**. На новой машине наборы скачивают
заново в этот каталог.
