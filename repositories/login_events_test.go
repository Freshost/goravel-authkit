package repositories

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLiteralContainsPatternEscapesLikeMetacharacters(t *testing.T) {
	require.Equal(t, "%jane!!doe!%!_@example.com%", literalContainsPattern("Jane!Doe%_@Example.com"))
}
