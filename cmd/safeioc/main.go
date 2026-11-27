// Command safeioc obfuscates and de-obfuscates indicators of compromise in
// the Safe-IOC format (draft-grimminck-safe-ioc-sharing).
//
// Usage:
//
//	safeioc [-d] [-t] [indicator ...]
//
// Each argument is transformed and printed on its own line. Without
// arguments, safeioc reads standard input and transforms it line by line.
//
// By default every argument or line is one indicator. With -t, the input
// is free text, such as a report or a log, and only the indicators found
// in it are transformed. With -d, safeioc restores obfuscated indicators
// instead.
//
// Examples:
//
//	$ safeioc https://evil.example/x
//	[https]://evil[.]example/x
//	$ safeioc -d '[https]://evil[.]example/x'
//	https://evil.example/x
//	$ safeioc -t < report.txt > report-safe.txt
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"

	"github.com/StefanGrimminck/safeioc"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("safeioc", flag.ContinueOnError)
	fs.SetOutput(stderr)
	deob := fs.Bool("d", false, "de-obfuscate instead of obfuscate")
	text := fs.Bool("t", false, "treat input as free text and transform only the indicators in it")
	version := fs.Bool("version", false, "print the version and exit")
	fs.Usage = func() {
		_, _ = fmt.Fprint(stderr, "usage: safeioc [-d] [-t] [indicator ...]\n"+
			"Obfuscates indicators of compromise in the Safe-IOC format; reads standard input when no indicator is given.\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *version {
		if _, err := fmt.Fprintln(stdout, "safeioc", moduleVersion()); err != nil {
			return 1
		}
		return 0
	}

	transform := safeioc.Obfuscate
	switch {
	case *deob && *text:
		transform = safeioc.DeobfuscateText
	case *deob:
		transform = safeioc.Deobfuscate
	case *text:
		transform = safeioc.ObfuscateText
	}

	var err error
	if fs.NArg() > 0 {
		err = transformArgs(fs.Args(), stdout, transform)
	} else {
		err = transformLines(stdin, stdout, transform)
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "safeioc:", err)
		return 1
	}
	return 0
}

func transformArgs(args []string, w io.Writer, fn func(string) string) error {
	out := bufio.NewWriter(w)
	for _, arg := range args {
		if _, err := out.WriteString(fn(arg) + "\n"); err != nil {
			return err
		}
	}
	return out.Flush()
}

// transformLines applies fn to each line of r, without its line ending,
// and writes the results to w, each with the line ending it had ("\n" or
// "\r\n"). A last line without one gets "\n". Lines may be of any length.
func transformLines(r io.Reader, w io.Writer, fn func(string) string) error {
	in := bufio.NewReader(r)
	out := bufio.NewWriter(w)
	for {
		line, err := in.ReadString('\n')
		if line != "" {
			ending := "\n"
			if strings.HasSuffix(line, "\r\n") {
				ending = "\r\n"
			}
			line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
			if _, err := out.WriteString(fn(line) + ending); err != nil {
				return err
			}
		}
		if errors.Is(err, io.EOF) {
			return out.Flush()
		}
		if err != nil {
			return err
		}
	}
}

func moduleVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "(devel)"
}
