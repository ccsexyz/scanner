package main

import "sync"

type bitmap struct {
	data []uint8
	lock sync.Mutex
}

func newBitmap(max int64) *bitmap {
	len := int(max>>3) + 1
	return &bitmap{
		data: make([]byte, len),
	}
}

func (bm *bitmap) set(v uint32) {
	bm.lock.Lock()
	defer bm.lock.Unlock()
	n := int(v >> 3)
	mask := byte(1 << (v & 7))
	bm.data[n] |= mask
}

func (bm *bitmap) check(v uint32) bool {
	bm.lock.Lock()
	defer bm.lock.Unlock()
	n := int(v >> 3)
	mask := byte(1 << (v & 7))
	return bm.data[n]&mask != 0
}
