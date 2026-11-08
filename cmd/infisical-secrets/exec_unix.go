//go:build unix

package main

import (
	"fmt"
	"os/exec"
	"syscall"
)

// runCommand replaces this process with the command: the secrets live only in its
// environment and no wrapper process stays in memory.
func runCommand(args, env []string) (int, error) {
	path, err := exec.LookPath(args[0])
	if err != nil {
		return 0, fmt.Errorf("commando niet gevonden: %s", args[0])
	}
	return 0, syscall.Exec(path, args, env)
}
