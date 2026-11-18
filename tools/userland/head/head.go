// Copyright 2024 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
)

var errCombine = fmt.Errorf("can't combine line and byte counts")

func run(stdin io.Reader, stdout, stderr io.Writer, bytes, count int, files ...string) error {
	if bytes > 0 && count > 0 {
		return errCombine
	}

	if bytes < 0 || count < 0 {
		return fmt.Errorf("head: negative counts are unsupported")
	}
	var printBytes bool
	if bytes > 0 {
		printBytes = true
	}

	var newLineHeader bool
	var errs error

	handle := func(r io.Reader, name string) error {
		if bytes == 0 && count == 0 {
			return nil
		}
		if len(files) > 1 {
			if newLineHeader {
				fmt.Fprintf(stdout, "\n==> %s <==\n", name)
			} else {
				fmt.Fprintf(stdout, "==> %s <==\n", name)
				newLineHeader = true
			}
		}
		if printBytes {
			_, err := io.CopyN(stdout, r, int64(bytes))
			if err != nil && err != io.EOF {
				return err
			}

		} else {
			var c int
			scanner := bufio.NewScanner(r)
			for scanner.Scan() {
				if _, err := fmt.Fprintln(stdout, scanner.Text()); err != nil {
					return err
				}
				c++
				if c == count {
					break
				}
			}
			if err := scanner.Err(); err != nil {
				return err
			}
		}
		return nil
	}

	// handle stdin
	if len(files) == 0 {
		return handle(stdin, "")
	}

	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("head: %w", err))
			continue
		}
		err = errors.Join(handle(f, f.Name()), f.Close())
		if err != nil {
			errs = errors.Join(errs, err)
		}
	}

	if errs != nil {
		fmt.Fprintf(stderr, "\n%v\n", errs)
	}
	return errs
}

func main() {
	c := flag.Int("c", 0, "Print bytes of each of the specified files")
	n := flag.Int("n", 10, "Print count lines of each of the specified files")

	flag.Parse()
	nSet, cSet := false, false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "c" {
			cSet = true
		}
		if f.Name == "n" {
			nSet = true
		}
	})
	if cSet && nSet {
		log.Fatal(errCombine)
	}
	if cSet && !nSet {
		*n = 0
	}
	if err := run(os.Stdin, os.Stdout, os.Stderr, *c, *n, flag.Args()...); err != nil {
		log.Fatalf("head: %v", err)
	}
}
