// safeioc is a command-line tool that applies the Safe-IOC
// obfuscation (and its inverse) defined in
// draft-grimminck-safe-ioc-sharing.
//
// Usage:
//
//	safeioc [-d] [input ...]
//
// With no input arguments, safeioc reads lines from stdin. Each line is
// transformed and written to stdout. The -d flag selects de-obfuscation.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/StefanGrimminck/safeioc"
)

func main() {
	deob := flag.Bool("d", false, "de-obfuscate instead of obfuscate")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [-d] [input ...]\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "  reads from stdin when no input arguments are given")
		flag.PrintDefaults()
	}
	flag.Parse()

	transform := safeioc.Obfuscate
	if *deob {
		transform = safeioc.Deobfuscate
	}

	if flag.NArg() > 0 {
		out := bufio.NewWriter(os.Stdout)
		defer out.Flush()
		for _, arg := range flag.Args() {
			fmt.Fprintln(out, transform(arg))
		}
		return
	}

	if err := streamLines(os.Stdin, os.Stdout, transform); err != nil {
		fmt.Fprintln(os.Stderr, "safeioc:", err)
		os.Exit(1)
	}
}

func streamLines(r io.Reader, w io.Writer, fn func(string) string) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	out := bufio.NewWriter(w)
	defer out.Flush()
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if _, err := fmt.Fprintln(out, fn(line)); err != nil {
			return err
		}
	}
	return scanner.Err()
}
