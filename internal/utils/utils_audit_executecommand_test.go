package utils

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

func findRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("Could not find repo root starting from %s", wd)
		}
		dir = parent
	}
}

// TestAudit_NoShellExecCallsRemain verifica que no se reintroduce el path de
// ejecución shell (ExecuteCommand/ExecCommand/execCommand con cadena). Toda la
// ejecución de comandos del proyecto debe ir por ExecuteArgv/ExecuteArgvWithTimeout
// o exec.Command con argumentos separados.
func TestAudit_NoShellExecCallsRemain(t *testing.T) {
	root := findRepoRoot(t)

	// Nombres prohibidos: el API shell fue eliminada de utils; cualquier
	// referencia externa es una regresión. execCommand interno de utils ya no
	// existe, así que tampoco debe aparecer.
	forbidden := map[string]bool{
		"ExecuteCommand":            true,
		"ExecuteCommandWithTimeout": true,
		"ExecCommand":               true,
		"ValidateShellCommand":      true,
	}

	var failures []string

	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}
		// Los propios tests de este archivo mencionan los nombres.
		if filepath.Base(path) == "utils_audit_executecommand_test.go" {
			return nil
		}
		// utils.go ya no define estas funciones; si el AST las referencia
		// fuera de comentarios, es una llamada real.
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				if fn.Sel != nil && forbidden[fn.Sel.Name] {
					failures = append(failures, path+": utils."+fn.Sel.Name)
				}
			case *ast.Ident:
				if forbidden[fn.Name] {
					failures = append(failures, path+": "+fn.Name)
				}
			}
			return true
		})
		return nil
	})

	if len(failures) > 0 {
		t.Fatalf("Shell exec API reintroduced: %v. Use ExecuteArgv/ExecuteArgvWithTimeout instead.", failures)
	}
}
