package main

import (
	"os"
	"testing"
)

func TestMainInvokesCommand(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	os.Args = []string{"courier", "--vault.source.token", "flag-token", "--help"}
	main()
}

