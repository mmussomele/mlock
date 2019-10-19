package mlock

import (
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
