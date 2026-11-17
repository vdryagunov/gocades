// Local demo: Prepare PDF → browser SignHash → Assemble.
//
//	CGO_ENABLED=1 go run ./samples/browser_signhash
//	open http://127.0.0.1:8765/
package main

import (
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/vdryagunov/gocades"
	"github.com/vdryagunov/gocades/internal/pdfsign"
)

//go:embed index.html
var indexHTML []byte

type session struct {
	PDF       []byte
	ByteRange [4]int64
	Digest    []byte
	FieldName string
	Expires   time.Time
}

var (
	mu   sync.Mutex
	sess = map[string]*session{}
)

func main() {
	addr := envOr("ADDR", "127.0.0.1:8765")
	mux := http.NewServeMux()
	mux.HandleFunc("/", serveIndex)
	mux.HandleFunc("/api/prepare", handlePrepare)
	mux.HandleFunc("/api/assemble", handleAssemble)

	go pruneSessions()

	log.Printf("browser_signhash listening on http://%s/", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(indexHTML)
}

func handlePrepare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	const maxPDF = 32 << 20
	r.Body = http.MaxBytesReader(w, r.Body, maxPDF+1024)
	if err := r.ParseMultipartForm(maxPDF); err != nil {
		httpError(w, http.StatusBadRequest, "multipart: %v", err)
		return
	}
	f, _, err := r.FormFile("pdf")
	if err != nil {
		httpError(w, http.StatusBadRequest, "поле pdf: %v", err)
		return
	}
	defer f.Close()
	pdf, err := io.ReadAll(f)
	if err != nil {
		httpError(w, http.StatusBadRequest, "читать pdf: %v", err)
		return
	}

	opts := pdfsign.Options{
		Hash:       pdfsign.HashGOST3411_2012_256,
		NewHash:    gocades.NewGOST3411_2012_256,
		Reason:     r.FormValue("reason"),
		SignerName: r.FormValue("signer"),
	}
	// Visible stamp is opt-in via form field stamp=1 (default on in the HTML).
	wantStamp := r.FormValue("stamp") != "0"
	if wantStamp {
		font := pdfsign.SystemFont()
		if font == nil {
			httpError(w, http.StatusBadRequest,
				"штамп нужен TrueType-шрифт (DejaVu/Arial), SystemFont() ничего не нашёл; stamp=0 чтобы без штампа")
			return
		}
		st := &pdfsign.Stamp{
			Font:  font,
			Title: r.FormValue("stampTitle"),
		}
		if w, err := strconv.ParseFloat(r.FormValue("stampW"), 64); err == nil && w > 0 {
			st.Width = w
		}
		if h, err := strconv.ParseFloat(r.FormValue("stampH"), 64); err == nil && h > 0 {
			st.Height = h
		}
		// Dragged position from the browser preview (PDF points, origin bottom-left).
		if sx, err1 := strconv.ParseFloat(r.FormValue("stampX"), 64); err1 == nil {
			if sy, err2 := strconv.ParseFloat(r.FormValue("stampY"), 64); err2 == nil {
				st.Positioned = true
				st.X, st.Y = sx, sy
			}
		}
		if !st.Positioned {
			st.Corner = pdfsign.StampBottomRight
			switch r.FormValue("stampCorner") {
			case "bl":
				st.Corner = pdfsign.StampBottomLeft
			case "tl":
				st.Corner = pdfsign.StampTopLeft
			case "tr":
				st.Corner = pdfsign.StampTopRight
			}
		}
		opts.Stamp = st
	}

	prep, err := pdfsign.Prepare(pdf, opts)
	if err != nil {
		httpError(w, http.StatusBadRequest, "Prepare: %v", err)
		return
	}
	if len(prep.Digest) == 0 {
		httpError(w, http.StatusInternalServerError, "Digest пуст (нужен CSP / NewHash)")
		return
	}

	id := hex.EncodeToString(prep.Digest[:8]) + fmt.Sprintf("%d", time.Now().UnixNano()%1e6)
	mu.Lock()
	sess[id] = &session{
		PDF:       prep.PDF,
		ByteRange: prep.ByteRange,
		Digest:    append([]byte(nil), prep.Digest...),
		FieldName: prep.FieldName,
		Expires:   time.Now().Add(30 * time.Minute),
	}
	mu.Unlock()

	writeJSON(w, map[string]any{
		"sessionId": id,
		"fieldName": prep.FieldName,
		"digestHex": hex.EncodeToString(prep.Digest),
		"byteRange": prep.ByteRange,
		"pdfSize":   len(prep.PDF),
		"stamp":     opts.Stamp != nil,
	})
}

func handleAssemble(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		SessionID string `json:"sessionId"`
		CMSBase64 string `json:"cmsBase64"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "json: %v", err)
		return
	}
	cms, err := base64.StdEncoding.DecodeString(req.CMSBase64)
	if err != nil {
		cms, err = base64.RawStdEncoding.DecodeString(req.CMSBase64)
	}
	if err != nil {
		httpError(w, http.StatusBadRequest, "cms Base64: %v", err)
		return
	}

	mu.Lock()
	s := sess[req.SessionID]
	if s != nil && time.Now().After(s.Expires) {
		delete(sess, req.SessionID)
		s = nil
	}
	mu.Unlock()
	if s == nil {
		httpError(w, http.StatusNotFound, "сессия не найдена или истекла")
		return
	}

	signed, err := pdfsign.Assemble(s.PDF, s.ByteRange, cms)
	if err != nil {
		httpError(w, http.StatusBadRequest, "Assemble: %v", err)
		return
	}

	content, err := pdfsign.SignedContent(signed, s.ByteRange)
	if err == nil {
		if err := gocades.VerifyDetached(cms, content, gocades.CadesBES); err != nil {
			log.Printf("VerifyDetached: %v", err)
			httpError(w, http.StatusBadRequest, "CMS не проходит VerifyDetached: %v", err)
			return
		}
	}

	mu.Lock()
	delete(sess, req.SessionID)
	mu.Unlock()

	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="signed.pdf"`)
	_, _ = w.Write(signed)
}

func pruneSessions() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		mu.Lock()
		for id, s := range sess {
			if now.After(s.Expires) {
				delete(sess, id)
			}
		}
		mu.Unlock()
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func httpError(w http.ResponseWriter, code int, format string, args ...any) {
	http.Error(w, fmt.Sprintf(format, args...), code)
}
