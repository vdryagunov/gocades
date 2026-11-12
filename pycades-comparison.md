# Сравнение с pycades

Порт повторяет **объектную модель pycades** через C-интерфейс КриптоПро
(`cades.h`, `libcades`, `libcapi20`), без своего C++ и boost. Целевая
версия — **КриптоПро CSP 5.0 R3**.

Поддерживаются Linux (`/opt/cprocsp`) и macOS (`CryptoPro_ECP.app`). На macOS
CryptoAPI разделён: провайдер — в `libcapi10.dylib`, сообщения — в
`libcapi20.dylib`, `GetLastError` — в `librdrsup.dylib`. Разницу закрывают
`#cgo`-директивы в `cades.go`.

pycades — CPython-расширение над `cppcades`/`cplib`. Для нас это значит:
тот же набор объектов, те же операции, та же семантика. Отличается в основном
синтаксис — методы Go вместо Python-свойств.

## Соглашения

| pycades | этот порт |
| --- | --- |
| `pycades.Store()` + `.Open(loc, name)` | `gocades.NewStore()` + `.Open(loc, name)` |
| свойство `obj.Name` | метод `obj.Name()` |
| свойство с сеттером `obj.Content = x` | `obj.SetContent(x)` |
| исключение при ошибке | возвращаемое `error` (`*gocades.Error` для HRESULT) |
| `CadesSignedData.SignCades(...)` | `gocades.SignDetached(cert, content, opts)` + объект `SignedData` |
| `VARIANT`/`BSTR` | обычные Go-типы (`[]byte`, `string`, `time.Time`, `bool`) |
| `datetime` | `time.Time` (UTC) |

Ошибки КриптоПро приходят как `*gocades.Error{Op, Code}`; `Code` — HRESULT в
знаковом виде, как `int32`. Для расшифровки есть `gocades.VerifyStatusText`.

Объекты, которые в pycades создаются пустыми и заполняются методами
(`Store`, `SignedData`), в Go создаются конструктором: `NewStore()`,
`NewSignedData()`.

## Статус

Легенда: **готово** — реализовано и собирается; **частично** — есть базовая
операция, нет полного набора; **н/п** — не имеет смысла на Linux.

### About / Version / Algorithm

| pycades | Go | Статус |
| --- | --- | --- |
| `About.CSPVersion(name, type)` | `About.CSPVersion()` (тип 75, как в pycades), `CSPVersionOf(name, type)` | готово |
| `About.MajorVersion/MinorVersion/BuildVersion` | `Version.Major/.Minor/.Build` | готово |
| `About.Version` | `Version.String()` | готово |
| `About.PluginVersion` | — | н/п (нет плагина на Linux) |
| `About.CSPName(type)` | `About.CSPName(type)` (+ константы `Prov*`) | готово |
| `ModuleVersion` | — | н/п |
| `Algorithm.Name/KeyLength` | `Algorithm{Name, KeyLength}` + enum-константы | готово |
| — | `ProviderAlgorithms()` | расширение (`PP_ENUMALGS_EX`) |

### Store / Certificates / Certificate

| pycades | Go | Статус |
| --- | --- | --- |
| `Store.Open` | `Store.Open`, `OpenStore` (+ `StoreMemory`) | готово |
| `Store.Close` | `Store.Close` | готово |
| `Store.Location` | `Store.Location()` | готово |
| `Store.Name` | `Store.Name()` | готово |
| `Store.Certificates` | `Store.Certificates()` | готово |
| `Store.Add` | `Store.Add(cert)` | готово |
| `Store.AddCRL` | `Store.AddCRL(der)` | готово |
| `Store.Remove` | `Store.Remove` | готово |
| `Store.ImportPFX` | `Store.ImportPFX(der, password, flags)` | готово (см. примечание 18) |
| `Certificates.Count` | `len(Store.Certificates())` | готово |
| `Certificates.Item(i)` | индексация слайса | готово |
| `Certificates.Find(type, value, validOnly)` | `Store.Find`, `Store.First` | готово (см. примечание 8) |
| `Certificate.SubjectName` | `SubjectName()` | готово |
| `Certificate.IssuerName` | `IssuerName()` | готово |
| `Certificate.SerialNumber` | `SerialNumber()` | готово |
| `Certificate.Thumbprint` | `Thumbprint()` | готово |
| `Certificate.Version` | `Version()` | готово |
| `Certificate.ValidFromDate` | `ValidFrom()` | готово |
| `Certificate.ValidToDate` | `ValidTo()` | готово |
| `Certificate.GetInfo(type)` | `Info(CertInfoType)` | готово |
| `Certificate.HasPrivateKey()` | `HasPrivateKey()` | готово |
| `Certificate.IsValid()` | `IsValid() (CertificateStatus, error)` | готово |
| `Certificate.KeyUsage()` | `KeyUsage()` | готово |
| `Certificate.ExtendedKeyUsage()` | `ExtendedKeyUsage()` | готово |
| `Certificate.BasicConstraints()` | `BasicConstraints()` | готово |
| `Certificate.PublicKey()` | `PublicKey()` | готово |
| `Certificate.PrivateKey` | `PrivateKey()` | готово |
| `Certificate.AdditionalStore(store)` | `AdditionalStore(store)` | готово |
| `Certificate.FindPrivateKey()` | `FindPrivateKey()` | готово |
| `Certificate.Export(encoding)` | `Export(t)`, `ExportDER()` | готово |
| `Certificate.Import(encoding)` | `Import(v, t)`, `ImportCertificateDER` | готово |
| `CertificateStatus.Result` | `CertificateStatus.Result` | готово |
| `PrivateKey.ContainerName` | `PrivateKey.ContainerName` | готово |
| `PrivateKey.UniqueContainerName` | `PrivateKey.UniqueContainerName` | готово |
| `PrivateKey.ProviderName/ProviderType/KeySpec` | те же поля | готово |
| `PrivateKey.ChangePin(old, new)` | `PrivateKey.ChangePin(old, new)` | готово |
| `PrivateKey.IsDefaultPin` | `PrivateKey.IsDefaultPin()` | готово (`PP_PIN_INFO == CRYPT_PIN_CLEAR`, как в `libcppcades`) |
| `Certificate.Extensions` → `Extensions{Count, Item}`, `Extension{OID, IsCritical, EncodedData}` | те же (+ `Extensions.Find`, `All`) | готово |
| `Certificate.PrivateKeyUsagePeriodFrom/To` | `PrivateKeyUsagePeriodFrom/To() (time.Time, error)`; нет расширения или поля — `CRYPT_E_NOT_FOUND`, как у вендора | готово |
| `Enroll*` (5 объектов, 21 член: контейнеры и ключи) | `EnrollCspInformation`, `EnrollContainers`, `EnrollContainer`, `EnrollContainerKeys`, `EnrollContainerKey` | готово (перечисление, сведения, ключи, удаление) |
| `CX509PrivateKey` / `CX500DistinguishedName` / `CX509CertificateRequestPkcs10` / `CX509Enrollment` | `X509PrivateKey`, `X500DistinguishedName`, `X509CertificateRequestPkcs10`, `X509Enrollment` (`CreateRequest`, `InstallResponse`) | готово (PKCS#10 на CryptoAPI C; без CMC/коллекций расширений CertEnroll) |

### Расширения сертификата

| pycades | Go | Статус |
| --- | --- | --- |
| `KeyUsage.IsPresent/IsCritical` | `KeyUsage.Present/.Critical` | готово |
| `KeyUsage.IsDigitalSignatureEnabled` … `IsDecipherOnlyEnabled` (9 шт.) | те же методы | готово |
| `ExtendedKeyUsage.IsPresent/IsCritical/EKUs` | те же поля | готово |
| `EKUs.Count/Item` | `Count()/Item(i)` | готово |
| `EKU.OID/Name` | `EKU.OID/.Name` | готово |
| `BasicConstraints.IsPresent/IsCritical/IsCertificateAuthority/IsPathLenConstraintPresent/PathLenConstraint` | те же поля | готово |
| `PublicKey.Algorithm/EncodedKey/EncodedParameters/Length` | методы `Algorithm()`, `EncodedKey()`, `EncodedParameters()`, `Length()` | готово |
| `OID.Value/Name/FriendlyName` | `Value`, `Name`, `FriendlyName()` | готово (см. примечания) |
| `EncodedData.Value/Format` | `Value()`, `Format(type)` | готово |

### Подпись и проверка

| pycades | Go | Статус |
| --- | --- | --- |
| `SignedData.SignCades` | `SignedData.SignCades`, `SignDetached` | готово |
| `SignedData.SignHash` | `SignedData.SignHash` | готово |
| `SignedData.Sign` (CMS без CAdES) | `SignedData.Sign` | готово |
| `SignedData.VerifyCades` | `SignedData.VerifyCades` → `VerificationInfo`, `*VerifyError` | готово (см. примечание 17) |
| `SignedData.Verify` | `SignedData.Verify` (тип `CadesPKCS7`) | готово (см. примечание 17) |
| `SignedData.VerifyHash` | `SignedData.VerifyHash` | готово (см. примечание 17) |
| `SignedData.CoSignHash` | `SignedData.CoSignHash` | готово |
| `SignedData.CoSign` / `CoSignCades` | `CoSign` (CryptMsg, без типа CAdES), `CoSignCades` | готово |
| `SignedData.EnhanceCades` | `SignedData.EnhanceCades`, `Enhance` | готово |
| `SignedData.Content` / `ContentEncoding` | `SetContent` / `Content` / `ContentEncoding` | готово |
| `SignedData.Signers` | `SignedData.Signers()` | готово |
| `SignedData.Certificates` | `SignedData.Certificates()`, `MessageCertificates(der)` | готово: сертификаты CMS, `certificate-values` подписантов и сертификаты TSA из меток времени, как `FillCertificates`; без дублей |
| `SignedData.AdditionalStore` | `SignedData.AdditionalStore` | готово (идёт в `CADES_VERIFICATION_PARA.hStore`) |
| `Signer.Certificate` | `Signer.Certificate` | готово |
| `Signer.SigningTime` | `Signer.SigningTime` | готово |
| `Signer.SignatureTimeStampTime` | `Signer.SignatureTimeStampTime` | готово |
| `Signer.SignatureStatus` → `SignatureStatus.IsValid` | `Signer.SignatureStatus.IsValid` (+ `Status`, `Err`) | готово |
| `Signer.TSAAddress` | `Signer.TSAAddress` | готово (из настроек объекта) |
| `Signer.CheckCertificate` / `Options` | `SignedData.SetCheckCertificate` (по умолчанию true → `CADES_CHECK_CERT_REQ`), `SignOptions.CheckCertificate` | готово |
| `Signer.AuthenticatedAttributes/UnauthenticatedAttributes` | `SignedData.AuthenticatedAttributes` / `UnauthenticatedAttributes` (Add при подписи); разбор DER при проверке | готово |
| `Signer.CRLs/OCSPResponses` | `Signer.CRLs`, `Signer.OCSPResponses` (`Blobs`, DER) | готово (`CadesMsgGetRevocationValues`; заполняются при проверке) |
| `Signer.Options` | `SignedData.SetOptions(CertIncludeOption)`, `SignOptions.Include` | готово (см. примечание 19) |
| `SignedData.GetMsgType/IsMsgType` | те же (+ функции пакета); принимают DER, а не base64; смотрят подписанта 0, `GetMsgType` проверяет A → X Long Type 1 → T → BES → PKCS7, как `libcppcades` | готово |
| `Signers.Count` / `Item` | `Count()` / `Item(i)` / `All()` | готово |
| `Attribute.Name/OID/Value` | `Attribute{Name, OID, Values}`, `Value()` | готово (разбор DER) |
| `Attributes.Count/Item` | `Count`, `Item`, `All`, `Find` | готово |
| `Attributes.Add/Clear/Remove`, `Attribute.ValueEncoding` | те же + `Attribute.SetName` / `SetValue` | готово (при подписи уходят в `cAuthAttr`/`cUnauthAttr`) |
| `Blobs.Count/Item` | `Blobs.Count`, `Item`, `Add`, `Clear`, `All` | готово |
| `CRL.Import/Export` | `CRL.Import(s, EncodingType)`, `Export`, `ImportCRLDER`, `ExportDER` | готово |
| `CRL.IssuerName/ThisUpdate/NextUpdate` | те же | готово (`NextUpdate` — нулевое время, если поля нет) |
| `CRL.Thumbprint/AuthKeyID` | те же | готово (hex в верхнем регистре, как в вендоре; см. примечание 20) |

Дополнительно ( сверх pycades): `VerificationInfo` возвращает `Status`,
`Valid`, `SignerCertificate`, `SigningTime`, `SignatureTimeStampTime`,
`CadesCTimeStampTime`, `ArchiveTimeStampTime` — для аудита ЭДО этого в
pycades не хватало.

### Криптография и шифрование

| pycades | Go | Статус |
| --- | --- | --- |
| `HashedData.Algorithm/DataEncoding/Key/Value` | `Algorithm()`, `SetAlgorithm`, `DataEncoding()`, `SetKey`, `Value()` | готово |
| `HashedData.Hash` | `HashedData.Hash(data)` | готово (за один вызов) |
| `HashedData.SetHashValue` | `SetHashValue` | готово |
| `RawSignature.SignHash` | `RawSignature.SignHash(cert, hashed)`, `SignDigest` | готово |
| `RawSignature.VerifyHash` | `RawSignature.VerifyHash(cert, hashed, sig)`, `VerifyDigest` | готово |
| `SymmetricAlgorithm.Encrypt/Decrypt` | `Encrypt`, `Decrypt` | готово |
| `SymmetricAlgorithm.SetMode/SetPadding` | `SetMode`, `SetPadding` | готово |
| `SymmetricAlgorithm.GenerateKey` | `GenerateKey`, `GenerateKeyBits` | готово |
| `SymmetricAlgorithm.IV` | `IV()`, `SetIV` | готово |
| `SymmetricAlgorithm.DiversData` | `DiversData`, `SetDiversData` | частично (только хранится) |
| `SymmetricAlgorithm.ExportKey/ImportKey` | `ExportKey(cert)`, `ImportKey(cert, blob)` | готово (ГОСТ: `hex(IV):hex(PUBEX):hex(SIMPLE)`, как в libcppcades) |
| `SymmetricAlgorithm.DiversifyKey` | метод есть | нет, сознательно (`ErrUnsupported`, примечание 11) |
| `EnvelopedData.Encrypt/Decrypt` | `Encrypt`, `Decrypt` | готово |
| `EnvelopedData.Content/ContentEncoding/Algorithm/Recipients` | те же | готово |
| `EnvelopedData.StreamEncrypt/StreamDecrypt` | `StreamEncrypt(io.Reader, io.Writer)`, `StreamDecrypt(io.Reader, io.Writer)` | готово (с буферизацией) |
| `Recipients.Count/Add/Clear/Item/Remove` | те же + `All` | готово |

Алгоритмы хеша: SHA-1/MD2/MD4/MD5/SHA-256/384/512, ГОСТ Р 34.11-94,
ГОСТ Р 34.11-2012 (256/512) и их HMAC-варианты (`CALG_GR3411_2012_256`, ...).

Дополнительно (сверх pycades): `NewGOST3411_2012_256()`, `NewGOST3411_2012_512()`
и `NewGOST3411()` возвращают `hash.Hash` поверх CSP. Их можно передать в
`internal/pdfsign.Options.NewHash` — это разблокирует digest-flow PAdES
(подпись через браузерный плагин) без pure-Go реализации ГОСТ.

### XML

| pycades | Go | Статус |
| --- | --- | --- |
| `SignedXML.Sign(signer, xpath)` | `SignedXML.Sign(cert)`, `SignDetached(cert)` | готово |
| `SignedXML.Verify(xml, xpath)` | `SignedXML.Verify(xml)` → `[]XMLVerificationInfo`, `*VerifyError` | готово (см. примечание 17) |
| `SignedXML.Content` | `Content()`, `SetContent` | готово |
| `SignedXML.Signers` | `Signers()` | готово |
| `SignedXML.SignatureType` | `SetSignatureType(XAdESType)` | готово (см. примечание 12) |
| `SignedXML.DigestMethod/SignatureMethod` | `SetDigestMethod`, `SetSignatureMethod` | готово |
| — | `SetXPath`, `SetTSAAddress`, `SetStore` | расширение |

Профили: `XAdESXMLDSig`, `XAdESDefault`, `XAdESBES`, `XAdEST`,
`XAdESXLongType1`, `XAdES_A`.

## Покрытие

Сверка со списком членов pycades `7c2ac83` (2026-11-10): в pycades 37 объектов
и 197 членов API. Порт закрывает используемый контур, включая PKCS#10
(`X509Enrollment.CreateRequest` / `InstallResponse`). Частично —
`SymmetricAlgorithm.DiversData` (только хранится).
`SymmetricAlgorithm.DiversifyKey` возвращает `ErrUnsupported` (примечание 11).
Полные коллекции `CX509Extension*` / CMC не портированы (CryptoAPI C, без
`libcppcades`). Краткая сводка — в `README.md`.

Поддерживаемые операции перечислены в таблицах «Статус» выше, осознанные
отличия от pycades — в разделе «Примечания».

## Примечания

1. **`OID.FriendlyName`** — CryptoAPI (`CryptFindOIDInfo`) отдаёт одно
   отображаемое имя на OID, отдельного «friendly name» нет. Поэтому
   `FriendlyName()` возвращает `Name`, а при неизвестном OID — сам `Value`.
2. **`Certificate.Export/Import`** принимают только DER. base64 — это
   `EncodedData.Format(EncodingBase64)`, дублировать в C смысла нет.
3. **`CertificateStatus.Result`** — `bool`, как в pycades. Дополнительно
   `PolicyError` отдаёт `dwError` из `CertVerifyCertificateChainPolicy`, а
   `ChainStatus` — биты `CERT_TRUST_*` построенной цепочки.
4. **`Certificate.Info`** для отсутствующего поля возвращает `("", nil)`, а не
   ошибку: в C это не ошибка, просто пустая строка.
5. **`FindPrivateKey`** не принимает критериев поиска: C-интерфейс их не
   поддерживает, контейнер берётся из самого сертификата. pycades точно так же
   игнорирует аргумент.
6. **`PrivateKey.UniqueContainerName`** требует открытия контейнера
   (`CryptAcquireContext` + `PP_UNIQUE_CONTAINER`). Если токен просит PIN,
   поле останется пустым — это не ошибка.
7. **`IsValid`** применяет `CERT_CHAIN_POLICY_BASE` и, как CAdESCOM
   (`CAPICOM_CHECK_ONLINE_ALL`), проверяет отзыв онлайн для всей цепочки,
   кроме корня; неизвестный статус отзыва (нет доступа к CRL/OCSP) даёт
   `Result == false`. pycades не даёт настроить проверку, хотя у вендорского
   `CertificateStatus` есть `CheckFlag`, `VerificationTime` и
   `UrlRetrievalTimeout`; здесь это `IsValidWith(ValidateOptions{Revocation,
   Time, URLTimeout})` (`RevocationCacheOnly` — только CRL из хранилищ и кэша,
   `RevocationNone` — без отзыва). Доверенные корни берутся из системных
   store; промежуточные сертификаты и CRL можно передать через
   `AdditionalStore` (например, `StoreMemory`). КриптоПро не проверяет отзыв
   у цепочки с недоверенным корнем.
8. **`Store.Find`** фильтрует по перечислению store, а не через
   `CertFindCertificateInStore`: `SUBJECT_NAME`/`ISSUER_NAME` — подстрока без
   учёта регистра (семантика `CERT_FIND_*_STR`), `SHA1_HASH` — точное
   сравнение hex. `TEMPLATE_NAME`, `EXTENSION`, `ROOT_NAME`,
   `APPLICATION_POLICY`, `CERTIFICATE_POLICY` недоступны: в эмуляции CryptoAPI
   нет `CERT_FIND_TEMPLATE` и `CERT_FIND_EXTENSION`. `KEY_USAGE` принимает
   битовую маску или имена через запятую (`"digitalSignature,nonRepudiation"`)
   — это расширение относительно CAPICOM, где передаётся enum.
9. **`PrivateKey.ChangePin`** использует `PP_CHANGE_PASSWORD` после установки
   старого PIN через `PP_SIGNATURE_PIN`. `PP_ADMIN_PIN` не используется:
   смена PIN администратора — отдельный сценарий.
10. **`HashedData.Hash`** считает дайджест переданных данных за один вызов и
    заменяет `Value`. Поэтапного дохеширования в этой функции нет; для него
    используйте `SetHashValue` с уже готовым дайджестом.
11. **`SymmetricAlgorithm.DiversifyKey`** возвращает `ErrUnsupported`: схема
    диверсификации CryptoPro не документирована, а неверная догадка дала бы
    **тихо неверный ключ**. Для защиты контента используйте
    `EnvelopedData.Encrypt`.
12. **Транспортные атрибуты CMS** (`Attributes`, `Attribute`) при проверке
    читаются DER-парсером (`ParseCMSSignerInfos`); значения — сырые
    content-октеты. При подписи `Add`/`Clear`/`Remove` и `ValueEncoding`
    заполняют `cAuthAttr`/`cUnauthAttr`.
13. **`SignedXML.SetSignatureType`** принимает `XAdESType`, а не
    `CADESCOM_XML_SIGNATURE_TYPE` (enveloped/enveloping/template), как в
    pycades: в C-структуре `XADES_SIGN_PARA.dwSignatureType` лежит именно
    профиль (`XADES_BES`, ...), а форма подписи выводится из документа и
    XPath.
14. **`SignedXML.Verify`** проверяет только присоединённую (enveloped)
    подпись: `XadesVerify` не принимает отдельный контент, поэтому
    `bIsDetached = FALSE`.
15. **`SymmetricAlgorithm.ExportKey`** для ГОСТ делает согласованный обмен
    как libcppcades: эфемерный `CALG_DH_GR3410_12_*_EPHEM`, `KP_DHOID`/`KP_X`,
    `PUBLICKEYBLOBEX`, `CALG_PRO12_EXPORT`, `SIMPLEBLOB`, результат —
    `hex(IV):hex(PUBEX):hex(SIMPLE)`. `ImportKey` принимает тот же формат.
    (Ранее здесь было примечание «только CMS / EnvelopedData».)
16. **Тексты ошибок.** В C-интерфейсе их нет: `CadesFormatMessage` форматирует
    только внутренние сообщения CAdES (для HRESULT возвращает 0 при любых
    флагах), а таблица, из которой печатают `csptest`/`cryptcp`, лежит в
    недокументированном каталоге `share/locale/*/LC_MESSAGES/csp_error_messages.cat`
    (формат `*nazgul*` с хеш-таблицей). pycades опирается на Win32
    `FormatMessage`, которого в Unix-эмуляции CryptoAPI нет, поэтому на Linux он
    тоже показывает только hex. В порте `gocades.ErrorText(code uint32)` отдаёт
    «ИМЯ: описание»: имя берётся из сгенерированной таблицы
    `error_names.go` (коды из `CSP_WinError.h`, а также `tspcli_e.h`,
    `ocspcli_e.h`, `cades_e.h`; генератор `scripts/gen-error-names.sh`),
    описание — из курируемого `error_text.go`. `Error.Error()` включает
    этот текст.
17. **Проверка подписи** (`VerifyCades`, `Verify`, `VerifyHash`,
    `VerifyDetached`, `SignedXML.Verify`). Как и в pycades, любая непрошедшая
    проверка — ошибка: `*VerifyError` с индексом подписанта, статусом
    `ADES_VERIFY_*` и HRESULT (`errors.As` на `*Error` тоже срабатывает).
    В отличие от pycades, вместе с ошибкой возвращается `VerificationInfo`
    со статусом и сертификатом подписанта: CAdES отдаёт их и для невалидной
    подписи. Проверяется **каждый** подписант CMS ровно один раз; ошибка —
    по первому непрошедшему, а результаты всех лежат в `Signers()`
    (`SignatureStatus.IsValid/Status/Err`). При ошибке `Status` никогда не
    равен `VerifySuccess`; если CAdES статуса не дал — `VerifyFailed` (-1).
    `Verify` проверяет обычный CMS с типом `CadesPKCS7` (`PKCS7_TYPE`):
    `CadesDefault` в CAdES означает «по умолчанию» и на проверке требует
    доказательств CAdES-X Long Type 1. `CoSign` добавляет подписанта через
    `CryptMsg*`, потому что `CadesAddHashSignature` отвергает `PKCS7_TYPE`.
    КриптоПро и в этом случае сам кладёт в подписанные атрибуты
    `contentType`, `messageDigest`, `signingTime` и `signingCertificateV2`.
18. **`Store.ImportPFX`** принимает DER-байты PFX, а не base64 (base64 —
    `EncodedData`). На неоткрытом store (`NewStore`) store становится
    in-memory хранилищем PFX, как в CAdESCOM. На открытом store вендор
    результат импорта теряет, и сертификаты в store не попадают; здесь они
    добавляются в него (`REPLACE_EXISTING`, сразу с коммитом). Ключи уходят в
    контейнеры CSP; с `PFXNoPersistKey` — только в память, тогда
    `HasPrivateKey` видит ключ по `CERT_KEY_CONTEXT_PROP_ID`. В
    `libcppcades` метод есть только с CAdES SDK 2.0.15400.
19. **`Signer.Options`** задаётся на `SignedData` (`SetOptions`) или в
    `SignOptions.Include` — у порта нет отдельного объекта-подписанта для
    подписи. Значения `CAPICOM_CERTIFICATE_INCLUDE_OPTION`: по умолчанию
    (нулевое значение) — цепочка без корня, как в CAdESCOM; `IncludeWholeChain`,
    `IncludeEndEntityOnly`, `IncludeNone`. Вендор строит цепочку строго и
    отказывается подписывать при любой ошибке доверия; здесь цепочка
    собирается без жёсткой проверки (без отзыва, только кэш URL; недоверенная или
    неполная цепочка — не ошибка), а корень отбрасывается, только если
    последний элемент самоподписан. Промежуточные сертификаты берутся и из
    `AdditionalStore`. До этой версии порт всегда встраивал только сертификат
    подписанта.
20. **`CRL`** хранит DER и разобранные поля, C-хэндла и `Close` у него нет.
    `Thumbprint` и `AuthKeyID` — hex в верхнем регистре, как в вендоре, хотя
    `Certificate.Thumbprint` порта отдаёт нижний регистр.

## Как проверяется

Код с cgo проверяется двумя шагами, оба работают без токена и без PIN:

```bash
# из корня модуля

# 1. C-слой компилируется против реальных заголовков (Linux или macOS)
make c-syntax

# 2. Go+cgo собирается и проверяется vet
make build vet

# 3. Полная сборка на Linux — в контейнере (с локальными пакетами КриптоПро)
make verify-linux DISTRO=debian
make verify-linux DISTRO=almalinux
```

`make c-syntax` подставляет правильные `-I` для текущей ОС; вручную это
выглядит так:

```bash
# Linux
clang -fsyntax-only -std=c11 -Wall -Wextra -DUNIX -DSIZEOF_VOID_P=8 \
  -I/opt/cprocsp/include -I/opt/cprocsp/include/cpcsp \
  -I/opt/cprocsp/include/pki -I/opt/cprocsp/include/pki/atl \
  -I/opt/cprocsp/include/pki/cplib gocades.c

# macOS
clang -fsyntax-only -std=c11 -Wall -Wextra -DUNIX -DSIZEOF_VOID_P=8 \
  -I/Applications/CryptoPro_ECP.app/Contents/Resources/include/pki \
  -I/Applications/CryptoPro_ECP.app/Contents/Resources/include/pki/cplib \
  -I/opt/cprocsp/include -I/opt/cprocsp/include/cpcsp gocades.c
```

Реальную проверку (живые вызовы CSP) даёт `make smoke`; с `SMOKE_PIN` он
подписывает, расшифровывает и проверяет XMLDSig/PAdES.

`make verify-linux` собирает и тестирует порт в контейнере с локальными
пакетами КриптоПро (`.deb` из `linux-*_deb.tgz` для Debian, `.rpm` из
`linux-*.tgz` для AlmaLinux). Прогнаны все комбинации дистрибутив/архитектура
с одними и теми же пакетами (CSP 5.0.13003, CAdES SDK 2.0.15003):

| Дистрибутив           | amd64 | arm64 |
| --------------------- | ----- | ----- |
| `debian:bookworm-slim` | ok    | ok    |
| `almalinux:9`          | ok    | ok    |

Шаг `go test -count=1 .` гарантирует, что тестовый бинарник реально
загрузил `libcades`, `libxades`, `libcapi20`, `libcapi10` и `librdrsup` —
проверена не только линковка, но и цепочка зависимостей во время выполнения.

Отдельно есть образ с **полноценно установленным КриптоПро**
(`make verify-crypto`, см. `docker/local/Dockerfile.*`). В нём проходят
установка CSP, сборка, линковка, загрузка библиотек и **полный smoke с
подписью**: ГОСТ-хэширование, `SignCades`/`VerifyCades` (цепочка валидна),
`CoSignCades`, `RawSignature`, симметричное шифрование, `EnvelopedData`
encrypt/decrypt, XAdES-BES, PAdES, варианты `Options` и `ImportPFX` (PFX
с экспортируемым ключом делает контейнерный скрипт через `certmgr -export
-pfx`). Итог: `passed 41, failed 0, skipped 0, warnings 0` (Debian arm64,
`STRICT=1`). Для CI без исходников в образе — `docker/ghcr/`).

PDF-часть проверяется не только своим парсером. После сборки документа:
`gocades.VerifyDetached` подтверждает, что CMS ложится ровно на байты из
`/ByteRange`; `pdfinfo` независимо перечитывает xref-цепочку и дерево страниц;
`pdfsig` находит поле подписи (`ETSI.CAdES.detached`). Оба инструмента из
`poppler-utils` и не знают про ГОСТ — важен сам факт, что документ читается
сторонним парсером. Дополнительно образ прогоняет `cmd/pdfsign` на реальном
документе из `cmd/pdfsign/testdata/sample.pdf`.

Видимый штамп (`internal/pdfsign.Stamp`) рисуется appearance-стримом с Type3-шрифтом,
собранным из контуров глифов: в файл попадают только реально использованные
символы, поэтому штамп добавляет единицы килобайт (в отличие от встраивания
шрифта целиком). Проверяется тремя способами: тест `TestGlyphBoundsMatchHeader`
сверяет декодированные контуры с границами, записанными в самих глифах шрифта;
тест `TestStampRenders` рендерит страницу через `pdftoppm` и требует, чтобы в
области штампа появились «чернила»; в smoke подпись собирается со штампом, и
`pdfinfo`/`pdfsig` подтверждают, что документ остался валидным.

Чтобы это заработало, образ собирает **плагин ДСЧ из образца вендора**
(`<cprocsp>/src/rdk/rndm0` в пакете `lsb-cprocsp-devel`), подменяя заглушку
`0xaa` на `getrandom()`/`/dev/urandom`, и регистрирует его через `cpconfig`
как единственный источник энтропии. Без этого `csptest -keyset -newkeyset`
падает с `0x80090020`: CSP 5.0 умеет брать энтропию только из пула CPSD
(который `genkpim` создаёт лишь с аппаратным ДСЧ) либо из интерактивного
«Text bio random» с клавиатуры.
