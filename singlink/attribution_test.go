// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0

package singlink

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The original-author attribution is required by NOTICE (Apache License 2.0,
// section 4(d)). These tests fail if it is removed or weakened.
func TestAttributionNamesOriginalAuthor(t *testing.T) {
	for _, want := range []string{
		"SingLink Beta Protocol",
		"originally developed and provided by SingLinkVPN, https://singlinkvpn.com",
		"https://github.com/SingLinkLabs/singlink-protocol",
	} {
		if !strings.Contains(Attribution, want) {
			t.Errorf("Attribution %q does not contain %q", Attribution, want)
		}
	}
	const want = "Based on the SingLink Beta Protocol, originally developed and provided by " +
		"SingLinkVPN, https://singlinkvpn.com · https://github.com/SingLinkLabs/singlink-protocol"
	if Attribution != want {
		t.Errorf("Attribution = %q, want %q", Attribution, want)
	}
	// The handshake identifier is wire format (SPEC.md §4, draft 4).
	if Identifier != "SingLink/1 by SingLinkVPN (singlinkvpn.com)" {
		t.Fatalf("handshake Identifier changed: %q", Identifier)
	}
}

func TestNoticeCarriesAttribution(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "NOTICE"))
	if err != nil {
		t.Fatal(err)
	}
	notice := string(b)
	for _, want := range []string{
		"Copyright 2026 SingLinkVPN",
		"Originally developed and provided by SingLinkVPN — https://singlinkvpn.com",
		"Software provided by the original author SingLinkVPN",
		"Based on the SingLink Beta Protocol by SingLinkVPN",
	} {
		if !strings.Contains(notice, want) {
			t.Errorf("NOTICE does not contain %q", want)
		}
	}
}

func TestSourceFilesKeepCopyrightHeader(t *testing.T) {
	var missing []string
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && path != ".." && (strings.HasPrefix(d.Name(), ".") || d.Name() == "build") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lines := strings.SplitN(string(b), "\n", 5)
		if !strings.Contains(strings.Join(lines[:min(4, len(lines))], "\n"), "Copyright 2026 SingLinkVPN") {
			missing = append(missing, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) > 0 {
		t.Fatalf("source files without the SingLinkVPN copyright header: %v", missing)
	}
}
