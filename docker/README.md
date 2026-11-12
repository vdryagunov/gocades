# docker/

Два независимых окружения. Команды — в `Makefile` этого каталога:

```bash
make -C docker help
```

| | `local/` | `ghcr/` |
| --- | --- | --- |
| Назначение | локальный полный прогон | образ для GitHub Actions / GHCR |
| Context | **корень модуля** | **`docker/`** |
| Содержимое | CSP + Go + RNG + исходники | CSP + RNG (без Go, clang, poppler) |
| Go в CI | внутри образа | `actions/setup-go` → mount `/usr/local/go` |
| ENTRYPOINT | `verify-crypto-inner.sh` | нет (`CMD bash`) |
| Make | `verify-crypto` / `local-image` | `ghcr` / `ghcr-all` / `ghcr-push-all` |

Общее: `packages/` (вендорские `.tgz`), `rng/cp_getrandom.h`, `verify-*-inner.sh`.

Архивы `packages/*.tgz` в git не коммитятся. Перед локальной сборкой
скачайте набор КриптоПро и положите нужный файл в `packages/` — см.
[`packages/README.md`](packages/README.md).

## Локальные тесты

```bash
make -C docker verify-crypto DISTRO=debian STRICT=1
# или из корня:
make verify-crypto DISTRO=debian STRICT=1

# только собрать образ:
make -C docker local-image DISTRO=almalinux ARCH=arm64
```

`SKIP_PADES=1` — без секции PAdES и `cmd/pdfsign` (так же в CI).

## Образ для GHCR / CI

```bash
echo "$GITHUB_TOKEN" | docker login ghcr.io -u <github-user> --password-stdin

make -C docker ghcr-push-all \
  VERSION=v1.0.1 \
  GHCR_IMAGE=ghcr.io/<owner>/gocades-test
```

Один вариант: `make -C docker ghcr-push DISTRO=debian ARCH=amd64 VERSION=v1.0.1 ...`

Теги:

| Образ | Назначение |
| --- | --- |
| `…/gocades-test:v1.0.1-debian-amd64` (и arm64 / almalinux-*) | конкретный вариант |
| `…/gocades-test:debian-amd64` (и др.) | текущий указатель на вариант |
| `…/gocades-test:v1.0.1` | = debian-amd64 этой версии |
| `…/gocades-test:latest` | = debian-amd64 (удобный алиас для `ubuntu-latest`) |

### Пакет GHCR (чтобы CI видел образы)

Пакет: **`gocades-test`** (без `s` на конце). Ожидаемые теги:

| Тег | Платформа |
| --- | --- |
| `v1.0.0-debian-amd64` / `debian-amd64` | linux/amd64 |
| `v1.0.0-debian-arm64` / `debian-arm64` | linux/arm64 |
| `v1.0.0-almalinux-amd64` / `almalinux-amd64` | linux/amd64 |
| `v1.0.0-almalinux-arm64` / `almalinux-arm64` | linux/arm64 |
| `v1.0.0` и `latest` | = debian-amd64 |

Настройки пакета на GitHub → Packages → `gocades-test`:

1. **Private** (лицензия КриптоПро).
2. **Package settings → Manage Actions access** → добавить репозиторий gocades
   с ролью **Read**.
3. Variables репозитория:
   - `CRYPTO_IMAGE_REPO=ghcr.io/<owner>/gocades-test`
   - `CRYPTO_IMAGE_VERSION=v1.0.0` — закрепить версию; если пусто, берутся
     теги вида `debian-amd64`

Workflow `verify-crypto` — цепочка **build → test → smoke**, каждая на четырёх
платформах (`ubuntu-latest` / `ubuntu-24.04-arm`). Внутри контейнера
`STAGE=build|test|smoke` (`verify-crypto-inner.sh`). В smoke: `SKIP_PADES=1`.

Локально по-прежнему полный прогон: если `STAGE` не задан, выполняется `all`.
