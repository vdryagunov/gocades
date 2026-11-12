# Примеры (как samples в pycades)

Те же сценарии, что в [pycades/samples](https://github.com/CryptoPro/pycades/tree/main/samples),
на API `gocades`. Нужны установленный КриптоПро и сертификат с ключом в
`CurrentUser/My` (для подписи и шифрования).

PIN (если контейнер защищён):

```bash
export GOCADES_PIN=...   # или SMOKE_PIN / CRYPTOPRO_PIN
```

| Пример | Аналог pycades | Запуск |
| --- | --- | --- |
| `sign_verify` | `sign_verify.py` | `go run ./samples/sign_verify` |
| `signhash_verifyhash` | `signhash_verifyhash.py` | `go run ./samples/signhash_verifyhash` |
| `sign_verify_xml` | `sign_verify_xml.py` | `go run ./samples/sign_verify_xml` |
| `encrypt_decrypt` | `encrypt_decrypt.py` | `go run ./samples/encrypt_decrypt` |
| `enum_containers` | `enum_containers.py` | `go run ./samples/enum_containers` |

`enum_containers` PIN не требует. Все сразу: `go build ./samples/...`
