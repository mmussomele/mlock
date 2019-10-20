package mlock

import (
	"bytes"
	"io"
	"math/rand"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAlloc(t *testing.T) {
	b, err := Alloc(pagesize - CanarySize)
	require.NoError(t, err)
	require.Equal(t, 3*pagesize, len(b.buf))

	err = b.Free()
	require.NoError(t, err)
	err = b.Free()
	require.EqualError(t, err, ErrAlreadyFreed.Error())

	b, err = Alloc(pagesize)
	require.NoError(t, err)
	require.Equal(t, 4*pagesize, len(b.buf))

	err = b.Free()
	require.NoError(t, err)
	err = b.Free()
	require.EqualError(t, err, ErrAlreadyFreed.Error())
}

const (
	kb = 1024
	mb = kb * kb
)

var (
	text  = []byte("Hello, world! I am secure :)")
	sizes = []int{
		syscall.Getpagesize(),
		3 * len(text), 4 * len(text),
		100, 200, 300, 400, 500,
		kb / 2, kb, 2 * kb, 256 * kb, 512 * kb,
	}
	bigSizes = []int{
		mb, 2 * mb, 32 * mb, 64 * mb, 128 * mb,
		117, 343, 451, 1701, 4004,
	}
)

func TestWrite(t *testing.T) {
	for _, s := range getSizes() {
		testWrite(t, s)
	}
}

func testWrite(t *testing.T, size int) {
	b, err := Alloc(size)
	require.NoError(t, err)

	n, err := b.Write(text)
	require.Equal(t, len(text), n)
	require.NoError(t, err)
	require.Equal(t, text, b.data[:b.i])

	n, err = b.Write(text)
	require.Equal(t, n, len(text))
	require.NoError(t, err)
	double := append(append([]byte{}, text...), text...)
	require.Equal(t, double, b.data[:b.i])

	err = b.Free()
	require.NoError(t, err)
}

func TestWriteCorruption(t *testing.T) {
	for _, s := range getSizes() {
		testWriteCorruption(t, s)
	}
}

func testWriteCorruption(t *testing.T, size int) {
	b, err := Alloc(size)
	require.NoError(t, err)

	b.canary[5]++
	n, err := b.Write(text)
	require.Equal(t, 0, n)
	require.EqualError(t, err, ErrDataCorrupted.Error())
	b.canary[5]--

	n, err = b.Write(text)
	require.Equal(t, n, len(text))
	require.NoError(t, err)

	b.padding[7]++
	n, err = b.Write(text)
	require.Equal(t, n, len(text))
	require.NoError(t, err)

	b.Strict()
	n, err = b.Write(text)
	require.Equal(t, 0, n)
	require.EqualError(t, err, ErrDataCorrupted.Error())
	b.padding[7]--

	n, err = b.Write(text)
	require.Equal(t, n, len(text))
	require.NoError(t, err)

	err = b.Free()
	require.NoError(t, err)
}

func TestWriteFullBuffer(t *testing.T) {
	for _, s := range getSizes() {
		testWriteFullBuffer(t, s)
	}
}

func testWriteFullBuffer(t *testing.T, size int) {
	b, err := Alloc(size)
	require.NoError(t, err)

	testBufferFull(t, b, size)

	err = b.Free()
	require.NoError(t, err)
}

func TestWriteFullBufferZero(t *testing.T) {
	for _, s := range getSizes() {
		testWriteFullBufferZero(t, s)
	}
}

func testWriteFullBufferZero(t *testing.T, size int) {
	b, err := Alloc(size)
	require.NoError(t, err)

	testBufferFull(t, b, size)

	b.Zero()

	long := make([]byte, size)
	n, err := rand.Read(long)
	require.Equal(t, n, size)
	require.NoError(t, err)

	n, err = b.Write(long)
	require.Equal(t, size, n)
	require.NoError(t, err)
	require.Equal(t, long, b.data)

	err = b.Free()
	require.NoError(t, err)
}

func testBufferFull(t *testing.T, b *Buffer, size int) {
	n, err := b.Write(text)
	require.Equal(t, len(text), n)
	require.NoError(t, err)
	require.Equal(t, text, b.data[:b.i])

	long := make([]byte, size)
	n, err = rand.Read(long)
	require.Equal(t, n, size)
	require.NoError(t, err)

	n, err = b.Write(long)
	require.Equal(t, size-len(text), n)
	require.EqualError(t, err, ErrBufferFull.Error())

	contents := append(append([]byte{}, text...), long...)[:size]
	require.Equal(t, contents, b.data)
}

type stalledReader struct {
	b    []byte
	read bool
}

func (s *stalledReader) Read(b []byte) (int, error) {
	if s.read {
		return 0, nil
	}
	s.read = true
	n := copy(b, s.b)
	return n, nil
}

func TestReadFrom(t *testing.T) {
	for _, s := range getSizes() {
		testReadFrom(t, s)
	}
}

func testReadFrom(t *testing.T, size int) {
	b, err := Alloc(size)
	require.NoError(t, err)

	buf := bytes.NewReader(text)
	n, err := b.ReadFrom(buf)
	require.Equal(t, int64(len(text)), n)
	require.NoError(t, err)
	require.Equal(t, text, b.data[:b.i])

	r := &stalledReader{b: text}
	n, err = b.ReadFrom(r)
	require.Equal(t, int64(len(text)), n)
	require.EqualError(t, err, io.ErrNoProgress.Error())
	double := append(append([]byte{}, text...), text...)
	require.Equal(t, double, b.data[:b.i])

	err = b.Free()
	require.NoError(t, err)
}

func TestZero(t *testing.T) {
	for _, s := range getSizes() {
		testZero(t, s)
	}
}

func testZero(t *testing.T, size int) {
	b, err := Alloc(size)
	require.NoError(t, err)

	n, err := rand.Read(b.data)
	require.NoError(t, err)
	require.Equal(t, n, size)

	zeroes := bytes.Repeat([]byte{0}, size)

	ri := len(b.buf) - pagesize
	di := ri - size
	dataView := b.buf[di:ri]

	require.NotEqual(t, zeroes, b.data)
	require.NotEqual(t, zeroes, dataView)
	require.Equal(t, dataView, b.data)
	b.Zero()
	require.Equal(t, zeroes, b.data)
	require.Equal(t, zeroes, dataView)

	err = b.Free()
	require.NoError(t, err)
}

func getSizes() []int {
	s := make([]int, len(sizes))
	copy(s, sizes)
	if testing.Short() {
		return s
	}
	return append(s, bigSizes...)
}
