package cmd

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestInitConfigBindsFlags(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// Set required token via flag so initConfig does not exit.
	rootCmd.PersistentFlags().Set("vault.source.token", "flag-token")
	rootCmd.PersistentFlags().Set("vault.source.address", "http://example")
	defer rootCmd.PersistentFlags().Set("vault.source.token", "")

	initConfig()

	assert.Equal(t, "flag-token", viper.GetString("vault.source.token"))
	assert.Equal(t, "http://example", viper.GetString("vault.source.address"))
}

func TestRootExecuteWithHelp(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	// Provide token flag to satisfy validation, then request help to avoid running subcommands.
	rootCmd.SetArgs([]string{"--vault.source.token", "flag-token", "--help"})
	defer rootCmd.SetArgs(nil)

	err := rootCmd.Execute()
	assert.NoError(t, err)
}
