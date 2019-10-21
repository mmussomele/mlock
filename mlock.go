package mlock

import (
	"bytes"
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

	i int

	strict bool // check padding as well as canary on access
}

// Alloc allocations a Buffer with the requested number of bytes. The bytes passed should
// be the number the user requires, not the value returned by RequiredPages.
//
// The returned Buffer is NOT managed by the Go runtime. It is allocated outside of it,
// and must be freed manually (by calling its Free() method) once the user has finished
// with it. Failing to do so will leak the memory, and if the Buffer goes out of scope
// without being freed, there is no way to release the memory until the process exits.
//
// Alloc panics if bytes is not positive.
func Alloc(bytes int) (b *Buffer, err error) {
	if bytes <= 0 {
		panic("non-positive bytes requested")
	}

	needed := RequiredBytes(bytes)
	buf, err := syscall.Mmap(-1, 0, needed, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err == nil {
			return
		}
		if e := b.Free(); e != nil {
			panic(e)
		}
		b = nil
	}()

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
		return b, err
	}

	if err = syscall.Mprotect(b.rearGuard, syscall.PROT_NONE); err != nil {
		return b, err
	}

	if n := copy(b.canary, canary[:]); n != CanarySize {
		panic("copied wrong number of bytes to canary")
	}

	return b, nil
}

// Realloc allocates a buffer with the new size, copies the contents of b into it, and
// then calls b.Free(). The new size must be able to hold the contents of b.
//
// Realloc panics if size is not positive.
func (b *Buffer) Realloc(size int) (r *Buffer, err error) {
	if size <= 0 {
		panic("non-positive size requested")
	}
	if err := b.canaryCheck(); err != nil {
		return nil, err
	}

	r, err = Alloc(size)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err == nil {
			return
		}
		if e := r.Free(); e != nil {
			panic(e)
		}
		r = nil
	}()

	if _, err := r.Write(b.data[:b.i]); err != nil {
		if err == ErrBufferFull {
			return r, ErrBufferTooSmall
		}
		return r, err
	}

	return r, b.Free()
}

// View returns a view on the user data for the buffer. It may be written to or read
// from, but data MUST not be copied outside the buffer - this will cause the data to
// lose its protected state. The buffer returned by View may be passed to cryptographic
// functions to decrypt data _into_ the buffer or encrypt data _out of_ the buffer (it is
// fine to encrypt data into the buffer as well, but there isn't much point).
//
// If b is corrupt or freed, a nil buffer is returned.
func (b *Buffer) View() []byte {
	if err := b.canaryCheck(); err != nil {
		return nil
	}

	return b.data[:b.i]
}

// Seek sets the current write index in the buffer. Seek panics if the index is negative.
// It is an error to seek past the end of written data.
func (b *Buffer) Seek(i int) error {
	if i < 0 {
		panic("negative index")
	}
	if err := b.canaryCheck(); err != nil {
		return err
	}

	if i > len(b.data) {
		return ErrSeekOutOfBounds
	}
	b.i = i
	return nil
}

var _ io.Writer = (*Buffer)(nil)

// Write implements the io.Writer interface.
func (b *Buffer) Write(buf []byte) (int, error) {
	if err := b.canaryCheck(); err != nil {
		return 0, err
	}

	n := copy(b.data[b.i:], buf)
	b.i += n
	if n < len(buf) {
		return n, ErrBufferFull
	}
	return n, nil
}

const progressThresh = 10

var _ io.ReaderFrom = (*Buffer)(nil)

// ReadFrom implements the io.ReadFrom interface.
func (b *Buffer) ReadFrom(r io.Reader) (int64, error) {
	if err := b.canaryCheck(); err != nil {
		return 0, err
	}

	var zeros int
	var total int64
	for {
		n, err := r.Read(b.data[b.i:])
		b.i += n
		total += int64(n)

		switch n {
		case 0:
			zeros++
		default:
			zeros = 0
		}

		switch {
		case err == nil:
			if zeros > progressThresh {
				return total, io.ErrNoProgress
			}
			continue
		case err == io.EOF:
			return total, nil
		default:
			return total, err
		}
	}
}

var (
	// ErrAlreadyFreed means that the buffer has already freed.
	ErrAlreadyFreed = errors.New("buffer already free-d")

	// ErrDataCorrupted means that the data in the buffer is corrupt.
	ErrDataCorrupted = errors.New("buffer data corrupted")

	// ErrBufferFull means that the buffer cannot hold more data.
	ErrBufferFull = errors.New("no room left in buffer")

	// ErrSeekOutOfBounds means that the seek index was outside of the buffer.
	ErrSeekOutOfBounds = errors.New("seek index out of bounds")

	// ErrBufferTooSmall means that the Buffer requested by a call to Realloc was too
	// small to hold the original Buffer's data.
	ErrBufferTooSmall = errors.New("realloc-ed buffer too small")
)

// Free releases the buffer back to the system.
func (b *Buffer) Free() error {
	if b.buf == nil {
		return ErrAlreadyFreed
	}
	b.Zero()
	if err := syscall.Munmap(b.buf); err != nil {
		return err
	}
	b.buf = nil
	return nil
}

// Zero sets the data section of the buffer to all zeros, and resets the write location
// to the start of the buffer.
func (b *Buffer) Zero() {
	b.data[0] = 0

	// Based on bytes.Repeat - logn runtime for copying repeated data into a buffer.
	for i := 1; i < len(b.data); i *= 2 {
		copy(b.data[i:], b.data[:i])
	}
	b.i = 0
}

// Strict sets the buffer to check the integrity of both the canary and any zero padding.
// By default, only the canary is checked.
func (b *Buffer) Strict() {
	b.strict = true
}

func (b *Buffer) canaryCheck() error {
	if b.buf == nil {
		return ErrAlreadyFreed
	}
	// TODO: Could unroll, since len(canary) is always 16.
	if !bytes.Equal(b.canary, canary[:]) {
		return ErrDataCorrupted
	}

	if !b.strict || len(b.padding) == 0 {
		return nil
	}

	for _, v := range b.padding {
		if v != 0 {
			return ErrDataCorrupted
		}
	}
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
