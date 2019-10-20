package mlock

import (
	"bytes"
	"math/rand"
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

var text = []byte("Hello, world! I am secure :)")

func TestWrite(t *testing.T) {
	b, err := Alloc(pagesize)
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
	b, err := Alloc(pagesize)
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
	b, err := Alloc(pagesize)
	require.NoError(t, err)

	testBufferFull(t, b)

	err = b.Free()
	require.NoError(t, err)
}

func TestWriteFullBufferZero(t *testing.T) {
	b, err := Alloc(pagesize)
	require.NoError(t, err)

	testBufferFull(t, b)

	b.Zero()

	long := make([]byte, pagesize)
	n, err := rand.Read(long)
	require.Equal(t, n, pagesize)
	require.NoError(t, err)

	n, err = b.Write(long)
	require.Equal(t, pagesize, n)
	require.NoError(t, err)
	require.Equal(t, long, b.data)

	err = b.Free()
	require.NoError(t, err)
}

func testBufferFull(t *testing.T, b *Buffer) {
	n, err := b.Write(text)
	require.Equal(t, len(text), n)
	require.NoError(t, err)
	require.Equal(t, text, b.data[:b.i])

	long := make([]byte, pagesize)
	n, err = rand.Read(long)
	require.Equal(t, n, pagesize)
	require.NoError(t, err)

	n, err = b.Write(long)
	require.Equal(t, pagesize-len(text), n)
	require.EqualError(t, err, ErrBufferFull.Error())

	contents := append(append([]byte{}, text...), long...)[:pagesize]
	require.Equal(t, contents, b.data)
}

func TestZero(t *testing.T) {
	b, err := Alloc(pagesize)
	require.NoError(t, err)

	n, err := rand.Read(b.data)
	require.NoError(t, err)
	require.Equal(t, n, pagesize)

	zeroes := bytes.Repeat([]byte{0}, pagesize)

	ri := len(b.buf) - pagesize
	di := ri - pagesize
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
