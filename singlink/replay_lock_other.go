//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

// Copyright 2026 SingLinkLabs
// SPDX-License-Identifier: Apache-2.0
package singlink

import (
	"context"
	"os"
)

func lockReplayFile(context.Context, string) (func(), error) { return nil, ErrReplayStore }

func replayOwnerOK(os.FileInfo) bool { return false }
