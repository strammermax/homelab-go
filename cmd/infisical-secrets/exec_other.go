//go:build !unix

package main

import (
	"os"
	"os/exec"
)

// runCommand on Windows: no exec(); run the command as a child and pass on its exit code.
func runCommand(args, env []string) (int, error) {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env, cmd.Stdin, cmd.Stdout, cmd.Stderr = env, os.Stdin, os.Stdout, os.Stderr
	return exitCode(cmd.Run()), nil
}
