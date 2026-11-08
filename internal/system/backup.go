package system

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"hostberry/internal/config"
)

const backupDirName = "backups"

func resolveInstallDir() string {
	var candidates []string
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, wd)
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Dir(exe))
	}
	candidates = append(candidates, "/opt/hostberry")
	for _, d := range candidates {
		if d == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(d, "config.yaml")); err == nil {
			return d
		}
	}
	return "."
}

func backupDirectory() string {
	return filepath.Join(resolveInstallDir(), backupDirName)
}

// CreateSystemBackup genera un archivo .tar.gz con config y base de datos SQLite.
func CreateSystemBackup() (string, error) {
	base := resolveInstallDir()
	dir := backupDirectory()
	if err := os.MkdirAll(dir, 0750); err != nil {
		return "", err
	}

	stamp := time.Now().Format("20060102-150405")
	name := fmt.Sprintf("hostberry-backup-%s.tar.gz", stamp)
	outPath := filepath.Join(dir, name)

	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return "", err
	}
	defer out.Close()

	gz := gzip.NewWriter(out)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	entries := []string{"config.yaml"}
	if cfg := config.AppConfig; cfg != nil && cfg.Database.Type == "sqlite" {
		dbPath := cfg.Database.Path
		if !filepath.IsAbs(dbPath) {
			dbPath = filepath.Join(base, dbPath)
		}
		entries = append(entries, dbPath)
	}

	for _, src := range entries {
		if !filepath.IsAbs(src) {
			src = filepath.Join(base, src)
		}
		if err := addFileToTar(tw, src, filepath.Base(src)); err != nil {
			return "", err
		}
	}

	if err := tw.Close(); err != nil {
		return "", err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}
	return outPath, nil
}

func addFileToTar(tw *tar.Writer, src, name string) error {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("backup: no se pudo leer %s: %w", src, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	hdr, err := tar.FileInfoHeader(st, "")
	if err != nil {
		return err
	}
	hdr.Name = name
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := io.Copy(tw, f); err != nil {
		return err
	}
	return nil
}

// ListSystemBackups devuelve nombres de backups ordenados (más reciente primero).
func ListSystemBackups() ([]string, error) {
	dir := backupDirectory()
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasSuffix(n, ".tar.gz") {
			names = append(names, n)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	return names, nil
}

// RestoreSystemBackup restaura config y BD desde un backup en el directorio de backups.
func RestoreSystemBackup(fileName string) error {
	fileName = filepath.Base(strings.TrimSpace(fileName))
	if fileName == "" || strings.Contains(fileName, "..") {
		return fmt.Errorf("nombre de backup inválido")
	}
	src := filepath.Join(backupDirectory(), fileName)
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("backup no encontrado: %s", fileName)
	}

	base := resolveInstallDir()
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	// Limitar el tamaño del archivo comprimido: un backup legítimo son unos
	// pocos MB; sin tope un archivo enorme podría llenar el disco.
	const maxBackupCompressed = 256 << 20 // 256 MiB
	gz, err := gzip.NewReader(io.LimitReader(f, maxBackupCompressed+1))
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, maxBackupCompressed*20+1)) // tope al descomprimir

	const (
		maxEntries    = 32
		maxTotalBytes = 512 << 20 // 512 MiB descomprimido
	)
	entries := 0
	var totalBytes int64

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		entries++
		if entries > maxEntries {
			return fmt.Errorf("backup inválido: demasiadas entradas")
		}
		// Solo archivos regulares; symlinks/hardlinks/directorios se ignoran
		// explícitamente (nunca se escribe fuera de las rutas permitidas).
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if hdr.Size < 0 || hdr.Size > maxTotalBytes {
			return fmt.Errorf("backup inválido: entrada demasiado grande")
		}
		totalBytes += hdr.Size
		if totalBytes > maxTotalBytes {
			return fmt.Errorf("backup inválido: tamaño total excesivo")
		}
		name := filepath.Base(hdr.Name)
		var dest string
		switch name {
		case "config.yaml":
			dest = filepath.Join(base, "config.yaml")
		case "hostberry.db":
			if cfg := config.AppConfig; cfg != nil && cfg.Database.Path != "" {
				dest = cfg.Database.Path
				if !filepath.IsAbs(dest) {
					dest = filepath.Join(base, dest)
				}
			} else {
				dest = filepath.Join(base, "data", "hostberry.db")
			}
		default:
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0750); err != nil {
			return err
		}
		// Escribir en temporal y renombrar: una interrupción a mitad no deja
		// config.yaml/BD corruptos.
		tmp, err := os.CreateTemp(filepath.Dir(dest), ".hostberry-restore-*")
		if err != nil {
			return err
		}
		tmpName := tmp.Name()
		ok := false
		defer func() {
			if !ok {
				os.Remove(tmpName)
			}
		}()
		if _, err := io.Copy(tmp, io.LimitReader(tr, hdr.Size)); err != nil {
			tmp.Close()
			return err
		}
		if err := tmp.Chmod(0600); err != nil {
			tmp.Close()
			return err
		}
		if err := tmp.Close(); err != nil {
			return err
		}
		if err := os.Rename(tmpName, dest); err != nil {
			return err
		}
		ok = true
	}
	return nil
}
