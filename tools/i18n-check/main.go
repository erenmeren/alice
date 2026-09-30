// Command i18n-check verifies that every translation file has exactly the
// keys and placeholders of en.json. Usage: i18n-check <dir> [<dir>...]
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: i18n-check <dir> [<dir>...]")
		os.Exit(2)
	}
	failed := false
	for _, dir := range os.Args[1:] {
		problems, err := CheckDir(os.DirFS(dir), "en")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", dir, err)
			failed = true
			continue
		}
		for _, p := range problems {
			fmt.Fprintf(os.Stderr, "%s/%s: %s: %s\n", dir, p.File, p.Key, p.Msg)
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, "i18n-check: all catalogs are consistent")
}
