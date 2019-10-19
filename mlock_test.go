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

func TestZero(t *testing.T) {
	b, err := Alloc(pagesize)
	require.NoError(t, err)

	_, err = rand.Read(b.data)
	require.NoError(t, err)

	zeroes := bytes.Repeat([]byte{0}, pagesize)

	ri := len(b.buf) - pagesize
	di := ri - pagesize
	dataView := b.buf[di:ri]

	require.NotEqual(t, zeroes, b.data)
	require.NotEqual(t, zeroes, dataView)
	b.Zero()
	require.Equal(t, zeroes, b.data)
	require.Equal(t, zeroes, dataView)

	err = b.Free()
	require.NoError(t, err)
}
