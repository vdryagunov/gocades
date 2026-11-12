//go:build (linux || darwin) && cgo

package gocades

/*
#include <stdlib.h>
#include "gocades.h"
*/
import "C"

import (
	"runtime"
	"unsafe"
)

// cAttrList holds C strings and value buffers for a signing call.
type cAttrList struct {
	list   C.cp_attr_list
	items  []C.cp_attr
	oids   []*C.char
	keep   [][]byte
	pinner runtime.Pinner
}

func (c *cAttrList) free() {
	c.pinner.Unpin()
	for _, o := range c.oids {
		C.free(unsafe.Pointer(o))
	}
	c.oids = nil
	c.items = nil
	c.keep = nil
	c.list.items = nil
	c.list.len = 0
}

func attributesToC(a Attributes) *cAttrList {
	if a.Count() == 0 {
		return &cAttrList{}
	}
	type pair struct {
		oid string
		val []byte
	}
	pairs := make([]pair, 0, a.Count())
	for _, it := range a.items {
		oid := it.OID
		if oid == "" {
			oid = oidForAttributeName(it.AttrName)
		}
		if oid == "" || len(it.Values) == 0 || len(it.Values[0]) == 0 {
			continue
		}
		pairs = append(pairs, pair{oid: oid, val: it.Values[0]})
	}
	out := &cAttrList{
		items: make([]C.cp_attr, len(pairs)),
		keep:  make([][]byte, len(pairs)),
		oids:  make([]*C.char, len(pairs)),
	}
	for i, p := range pairs {
		out.oids[i] = C.CString(p.oid)
		out.keep[i] = p.val
		out.pinner.Pin(&out.keep[i][0])
		out.items[i] = C.cp_attr{
			oid:       out.oids[i],
			value:     (*C.uchar)(unsafe.Pointer(&out.keep[i][0])),
			value_len: C.size_t(len(out.keep[i])),
		}
	}
	if len(out.items) > 0 {
		out.pinner.Pin(&out.items[0])
		out.list.items = &out.items[0]
		out.list.len = C.size_t(len(out.items))
	}
	return out
}
