package mlock

import (
	"crypto/rand"
	"errors"
	"io"
	"syscall"
)

const (
	// CanarySize is the number of bytes in the protected buffer's canary.
	CanarySize = 16

	// GuardPages is the number of pages allocated to guard an allocated buffer.
	GuardPages = 2
)

var (
	canary   [CanarySize]byte // initialized at startup
	pagesize int
)

// Buffer is a securely mlock-ed buffer allocated outside the Go runtime.
type Buffer struct {
	buf []byte // original buffer, for un-mapping

	frontGuard []byte
	padding    []byte
	canary     []byte
	data       []byte
	rearGuard  []byte

	strict bool // check padding as well as canary on access
}

// Alloc allocations a Buffer with the requested number of bytes. The bytes passed should
// be the number the user requires, not the value returned by RequiredPages.
func Alloc(bytes int) (b *Buffer, err error) {
	mustFreeOnErr := func(b []byte, free func(b []byte) error) {
		if err == nil {
			return
		}
		if e := free(b); e != nil {
			panic(e)
		}
	}

	needed := RequiredBytes(bytes)
	buf, err := syscall.Mmap(-1, 0, needed, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		return nil, err
	}
	defer mustFreeOnErr(buf, syscall.Munmap)

	if err = syscall.Mlock(buf); err != nil {
		return nil, err
	}
	defer mustFreeOnErr(buf, syscall.Munlock)

	// starting indices of sub-buffers, reverse order
	ri := len(buf) - pagesize
	di := ri - bytes
	ci := di - CanarySize
	pi := pagesize
	fi := 0

	b = &Buffer{
		buf:        buf,
		frontGuard: buf[fi:pi], // fi not needed, here for clarity
		padding:    buf[pi:ci],
		canary:     buf[ci:di],
		data:       buf[di:ri],
		rearGuard:  buf[ri:],
	}

	if err = syscall.Mprotect(b.frontGuard, syscall.PROT_NONE); err != nil {
		return nil, err
	}

	if err = syscall.Mprotect(b.rearGuard, syscall.PROT_NONE); err != nil {
		return nil, err
	}

	if n := copy(b.canary, canary[:]); n != CanarySize {
		panic("copied wrong number of bytes to canary")
	}

	return b, nil
}

// ErrAlreadyFreed means that the buffer has already freed.
var ErrAlreadyFreed = errors.New("buffer already free-d")

// Free releases the buffer back to the system.
func (b *Buffer) Free() error {
	if b.buf == nil {
		return ErrAlreadyFreed
	}
	if err := syscall.Munlock(b.buf); err != nil {
		return err
	}
	if err := syscall.Munmap(b.buf); err != nil {
		return err
	}
	b.buf = nil
	return nil
}

// RequiredBytes returns the number of bytes needed to allocate the requested number of
// bytes for user access. This is so a user can tell how much memory an alloc will
// require, and the result should not be passed to Alloc.
func RequiredBytes(bytes int) int {
	needed := bytes + CanarySize

	result := pagesize * (needed/pagesize + GuardPages)
	if needed%pagesize == 0 {
		return result
	}
	return result + pagesize // need an extra page for overflow
}

func init() {
	if _, err := io.ReadFull(rand.Reader, canary[:]); err != nil {
		panic(err)
	}
	pagesize = syscall.Getpagesize()
}
