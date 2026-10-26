// Test cases for go-exec-nonconstant-command (run: make sast-test).
package semgreptest

import (
	"context"
	"os/exec"
)

const syftBinary = "syft"

func goodLiteral(ctx context.Context, image string) *exec.Cmd {
	// ok: go-exec-nonconstant-command
	return exec.CommandContext(ctx, "grype", "--output", "json", image)
}

func goodConstant(image string) *exec.Cmd {
	// ok: go-exec-nonconstant-command
	return exec.Command(syftBinary, "scan", image)
}

func goodConstantShellScript() *exec.Cmd {
	// ok: go-exec-nonconstant-command
	return exec.Command("sh", "-c", "echo ready")
}

func variableProgram(tool string, args []string) *exec.Cmd {
	// ruleid: go-exec-nonconstant-command
	return exec.Command(tool, args...)
}

func variableProgramContext(ctx context.Context, tool string) *exec.Cmd {
	// ruleid: go-exec-nonconstant-command
	return exec.CommandContext(ctx, tool)
}

func shellWithInput(ref string) *exec.Cmd {
	// ruleid: go-exec-nonconstant-command
	return exec.Command("sh", "-c", "cosign verify "+ref)
}

func bashWithInput(ctx context.Context, script string) *exec.Cmd {
	// ruleid: go-exec-nonconstant-command
	return exec.CommandContext(ctx, "/bin/bash", "-c", script)
}
