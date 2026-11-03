package main

import (
	"bufio"
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/elchi-dev/conduit/internal/backup"
	"github.com/elchi-dev/conduit/internal/daemon"
	"github.com/elchi-dev/conduit/internal/version"
)

// backupCommand runs `conduitd backup` and `conduitd restore`.
//
//	conduitd backup  [-data DIR] -out FILE
//	conduitd restore [-data DIR] -in FILE
//
// The passphrase comes from CONDUIT_BACKUP_PASSPHRASE, -passphrase-file, or
// is asked for. A backup can be taken while the daemon runs; restore into a
// folder that doesn't exist yet (or is empty), then start the daemon on it.
func backupCommand(ctx context.Context, cmd string, args []string) int {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	data := fs.String("data", daemon.DefaultConfig().DataDir, "data directory")
	out := fs.String("out", "", "backup file to write (backup)")
	in := fs.String("in", "", "backup file to read (restore)")
	pf := fs.String("passphrase-file", "", "read the passphrase from this file")
	_ = fs.Parse(args)
	fail := func(err error) int {
		fmt.Fprintln(os.Stderr, "conduitd "+cmd+":", err)
		return 1
	}
	pass, err := passphrase(*pf, cmd == "backup")
	if err != nil {
		return fail(err)
	}
	if cmd == "backup" {
		if *out == "" {
			return fail(fmt.Errorf("say where to write it: -out conduit-backup.cdb"))
		}
		db, err := sql.Open("sqlite", "file:"+filepath.Join(*data, backup.DBName)+"?mode=ro&_pragma=busy_timeout(5000)")
		if err != nil {
			return fail(err)
		}
		defer db.Close()
		tmp := *out + ".tmp"
		f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return fail(err)
		}
		err = backup.Write(ctx, f, db, *data, pass, version.Version)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(tmp)
			return fail(err)
		}
		if err := os.Rename(tmp, *out); err != nil {
			return fail(err)
		}
		fmt.Println("wrote", *out)
		return 0
	}
	if *in == "" {
		return fail(fmt.Errorf("say which backup to restore: -in conduit-backup.cdb"))
	}
	f, err := os.Open(*in)
	if err != nil {
		return fail(err)
	}
	defer f.Close()
	h, err := backup.Restore(f, *data, pass)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("restored a backup from %s (Conduit %s) into %s\nStart the daemon with -data %s; unlock the vault with its own passphrase.\n",
		h.Created.Format("2 Jan 2006 15:04 MST"), h.Version, *data, *data)
	return 0
}

func passphrase(file string, confirm bool) (string, error) {
	if v := os.Getenv("CONDUIT_BACKUP_PASSPHRASE"); v != "" {
		return v, nil
	}
	if file != "" {
		b, err := os.ReadFile(file)
		return strings.TrimRight(string(b), "\r\n"), err
	}
	rd := bufio.NewReader(os.Stdin)
	fmt.Fprint(os.Stderr, "Backup passphrase (shown as you type; or set CONDUIT_BACKUP_PASSPHRASE): ")
	p, _ := rd.ReadString('\n')
	p = strings.TrimRight(p, "\r\n")
	if confirm {
		fmt.Fprint(os.Stderr, "Again: ")
		q, _ := rd.ReadString('\n')
		if strings.TrimRight(q, "\r\n") != p {
			return "", fmt.Errorf("the passphrases don't match")
		}
	}
	return p, nil
}
