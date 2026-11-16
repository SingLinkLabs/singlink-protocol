// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/SingLinkLabs/singlink-protocol/singlink"
)

// The CLI help must show the required original-author attribution (NOTICE).
func TestUsageShowsAttribution(t *testing.T) {
	if !strings.Contains(usage, singlink.Attribution) {
		t.Fatalf("usage does not contain the attribution:\n%s", usage)
	}
}
