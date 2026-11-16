// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0
package singlink

import (
	"context"
	"io"
)

func forwardEarlyData(ctx context.Context, dst io.Writer, b []byte, lim *limiter, stats *Stats) error {
	if len(b) == 0 {
		return nil
	}
	if lim != nil {
		if err := lim.wait(ctx, len(b)); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	n, err := dst.Write(b)
	if stats != nil {
		stats.Up.Add(int64(n))
	}
	if err == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return err
}
