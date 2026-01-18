package cmd

import (
	"testing"

	"github.com/ncode/courier/pkg/auditserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitAndTrim(t *testing.T) {
	assert.Nil(t, splitAndTrim(""))
	assert.Equal(t, []string{"a", "b", "c"}, splitAndTrim(" a, b , ,c "))
}

func TestBuildDestinationConfigs(t *testing.T) {
	t.Run("fan out single token", func(t *testing.T) {
		cfgs, err := buildDestinationConfigs([]string{"addr1", "addr2"}, []string{"tok"})
		require.NoError(t, err)
		assert.Equal(t, []auditserver.DestinationConfig{
			{Address: "addr1", Token: "tok"},
			{Address: "addr2", Token: "tok"},
		}, cfgs)
	})

	t.Run("mismatched lengths", func(t *testing.T) {
		cfgs, err := buildDestinationConfigs([]string{"addr1", "addr2", "addr3"}, []string{"tok1", "tok2"})
		require.Error(t, err)
		assert.Nil(t, cfgs)
	})

	t.Run("no addresses", func(t *testing.T) {
		cfgs, err := buildDestinationConfigs(nil, []string{"tok"})
		require.Error(t, err)
		assert.Nil(t, cfgs)
	})
}
