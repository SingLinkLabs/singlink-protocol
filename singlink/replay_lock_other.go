//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly && !windows

// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0
package singlink

import (
	"context"
	"os"
)

// The reference file store has no supported lock/permission model on this
// platform: it fails closed. Provide an external ReplayStore instead.

func lockReplayFile(context.Context, string) (func(), error) { return nil, ErrReplayStore }

func replayPrivate(string, os.FileInfo) bool { return false }

func makeReplayDir(string) error { return ErrReplayStore }

func replaceReplayFile(string, string) error { return ErrReplayStore }
