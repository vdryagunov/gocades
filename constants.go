package gocades

// CadesType mirrors the CADES_* constants from cades.h.
type CadesType int32

const (
	// CadesDefault is CADES_DEFAULT: the library chooses the type. It is not
	// a plain CMS: signing then needs a TSA and verification demands
	// CAdES-X Long Type 1 evidence. Use CadesPKCS7 for plain CMS.
	CadesDefault CadesType = 0x0

	CadesBES        CadesType = 0x1
	CadesT          CadesType = 0x5
	CadesXLongType1 CadesType = 0x5D
	CadesA          CadesType = 0xDD

	// CadesPKCS7 is PKCS7_TYPE: plain CMS without CAdES checks. Use it for
	// verification; co-signing through CAdES (CoSignCades, CoSignHash)
	// rejects it with E_INVALIDARG. SignedData.Sign and CoSign produce plain
	// CMS.
	CadesPKCS7 CadesType = 0xFFFF
)

// StoreLocation mirrors CADESCOM_*_STORE / CryptoAPI system store locations.
type StoreLocation int32

const (
	// StoreMemory is a temporary in-memory store (CADESCOM_MEMORY_STORE);
	// the name passed to Open is ignored and nothing is persisted.
	StoreMemory       StoreLocation = 0
	StoreLocalMachine StoreLocation = 1
	StoreCurrentUser  StoreLocation = 2
)

// HashGOST3411_2012_256 is the OID of GOST R 34.11-2012 (256-bit).
const HashGOST3411_2012_256 = "1.2.643.7.1.1.2.2"
