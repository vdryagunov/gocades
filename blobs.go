package gocades

import "fmt"

// Blobs mirrors CadesBlobs: an ordered collection of byte blobs.
type Blobs struct {
	items [][]byte
}

// Count returns the number of blobs.
func (b Blobs) Count() int { return len(b.items) }

// Item returns the blob at index i.
func (b Blobs) Item(i int) ([]byte, error) {
	if i < 0 || i >= len(b.items) {
		return nil, fmt.Errorf("gocades: blob index %d out of range [0,%d)", i, len(b.items))
	}
	return b.items[i], nil
}

// All returns every blob.
func (b Blobs) All() [][]byte { return b.items }

// Add appends a blob.
func (b *Blobs) Add(v []byte) { b.items = append(b.items, v) }

// Clear removes all blobs.
func (b *Blobs) Clear() { b.items = nil }
