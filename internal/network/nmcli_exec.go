package network

import (
	"context"
	"strings"
	"time"

	"hostberry/internal/utils"
)

const nmcliTimeout = 45 * time.Second

// runSudoNmcli ejecuta nmcli con argumentos separados (sin shell) con los
// privilegios necesarios. Pasa por privileged-exec --argv (la única vía
// autorizada por sudoers) en lugar de `sudo nmcli` directo.
func runSudoNmcli(args ...string) (stdoutStderr string, err error) {
	if len(args) == 0 {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), nmcliTimeout)
	defer cancel()
	cmd, err := utils.NewArgvCommandContext(ctx, append([]string{"nmcli"}, args...)...)
	if err != nil {
		return "", err
	}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
