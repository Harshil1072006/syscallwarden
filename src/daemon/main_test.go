package main

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestScope(t *testing.T) {
	for _, s := range []string{"", "SCOPE 0", "SCOPE -1", "SCOPE 23 x", "OTHER 3", "SCOPE 18446744073709551616"} {
		if _, err := labScope(s); err == nil {
			t.Fatalf("unexpected valid scope %q", s)
		}
	}
	if v, err := labScope("SCOPE 17\n"); v != "17" || err != nil {
		t.Fatalf("valid scope: %q, %v", v, err)
	}
}

func TestCopyCompleteLab(t *testing.T) {
	var out bytes.Buffer
	err := copyLab(bufio.NewReader(strings.NewReader("one\ntwo\nDONE\n")), &out)
	if err != nil || out.String() != "one\ntwo\n" {
		t.Fatalf("copy: %q, %v", out.String(), err)
	}
}

func TestCopyIncompleteOrOversize(t *testing.T) {
	for _, data := range []string{"one\n", strings.Repeat("x", 2048) + "\nDONE\n"} {
		if err := copyLab(bufio.NewReaderSize(strings.NewReader(data), 64), &bytes.Buffer{}); err == nil {
			t.Fatal("incomplete/oversized stream accepted")
		}
	}
}
