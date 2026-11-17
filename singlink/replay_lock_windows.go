//go:build windows

// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0
package singlink

// Windows backend for FileReplayStore, using only the standard library:
//   - mutual exclusion: LockFileEx on the stable sidecar lock file (an
//     exclusive byte-range lock held per handle, released by UnlockFileEx and
//     by the system if the process dies);
//   - privacy: the owner and DACL of the directory, lock, state and temporary
//     files must grant access only to this user, SYSTEM and Administrators
//     (privateACL); a directory the store creates gets exactly that protected
//     DACL, which its files inherit;
//   - atomic durable replacement: MoveFileExW with MOVEFILE_REPLACE_EXISTING
//     and MOVEFILE_WRITE_THROUGH after the temporary file was flushed.
// kernel32.dll and advapi32.dll are loaded from the system directory only
// (they are system DLLs registered by package syscall).

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")

	procLockFileEx        = modkernel32.NewProc("LockFileEx")
	procUnlockFileEx      = modkernel32.NewProc("UnlockFileEx")
	procMoveFileExW       = modkernel32.NewProc("MoveFileExW")
	procGetSecurityInfo   = modadvapi32.NewProc("GetSecurityInfo")
	procStringSDToSD      = modadvapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procSetNamedSecurity  = modadvapi32.NewProc("SetNamedSecurityInfoW")
	procGetSecurityDescDA = modadvapi32.NewProc("GetSecurityDescriptorDacl")
)

const (
	lockfileFailImmediately = 0x1
	lockfileExclusiveLock   = 0x2

	errorSharingViolation syscall.Errno = 32
	errorLockViolation    syscall.Errno = 33

	moveFileReplaceExisting = 0x1
	moveFileWriteThrough    = 0x8

	seFileObject                = 1
	ownerSecurityInformation    = 0x1
	daclSecurityInformation     = 0x4
	protectedDACLSecurityInfo   = 0x80000000
	readControl                 = 0x00020000
	sddlRevision1               = 1
	replayMoveRetryWindow       = 500 * time.Millisecond
	replayMoveRetryInterval     = 10 * time.Millisecond
	replayLockPollInterval      = 5 * time.Millisecond
	fileShareReadWriteAndDelete = syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE | syscall.FILE_SHARE_DELETE
)

func lockReplayFile(ctx context.Context, path string) (func(), error) {
	if st, err := os.Lstat(path); err == nil && (!st.Mode().IsRegular() || !replayPrivate(path, st)) {
		return nil, ErrReplayStore
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, ErrReplayStore
	}
	h := syscall.Handle(f.Fd())
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || !handlePrivate(h) {
		f.Close()
		return nil, ErrReplayStore
	}
	for {
		if err := ctx.Err(); err != nil {
			f.Close()
			return nil, err
		}
		ol := new(syscall.Overlapped)
		r, _, e := procLockFileEx.Call(uintptr(h), lockfileExclusiveLock|lockfileFailImmediately, 0, 1, 0, uintptr(unsafe.Pointer(ol)))
		if r != 0 {
			return func() {
				ul := new(syscall.Overlapped)
				procUnlockFileEx.Call(uintptr(h), 0, 1, 0, uintptr(unsafe.Pointer(ul)))
				f.Close()
			}, nil
		}
		if !errors.Is(e, errorLockViolation) {
			f.Close()
			return nil, ErrReplayStore
		}
		timer := time.NewTimer(replayLockPollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			f.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// replayPrivate checks the object at path itself (reparse points are not
// followed; callers have already required a real file or directory).
func replayPrivate(path string, _ os.FileInfo) bool {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	h, err := syscall.CreateFile(p, readControl, fileShareReadWriteAndDelete, nil, syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	return handlePrivate(h)
}

// winACL and winACEHeader mirror the ACL and ACE_HEADER structures.
type winACL struct {
	revision byte
	sbz1     byte
	size     uint16
	count    uint16
	sbz2     uint16
}

type winACEHeader struct {
	typ   byte
	flags byte
	size  uint16
}

// handlePrivate reads the owner and DACL of an open handle (which needs
// READ_CONTROL access) and applies privateACL.
func handlePrivate(h syscall.Handle) bool {
	self, err := currentUserSID()
	if err != nil {
		return false
	}
	var owner *syscall.SID
	var dacl *winACL
	var sd uintptr
	r, _, _ := procGetSecurityInfo.Call(uintptr(h), seFileObject, ownerSecurityInformation|daclSecurityInformation,
		uintptr(unsafe.Pointer(&owner)), 0, uintptr(unsafe.Pointer(&dacl)), 0, uintptr(unsafe.Pointer(&sd)))
	if r != 0 || sd == 0 {
		return false
	}
	defer syscall.LocalFree(syscall.Handle(sd))
	if owner == nil {
		return false
	}
	ownerSID, err := owner.String()
	if err != nil {
		return false
	}
	entries, ok := daclEntries(dacl)
	if !ok {
		return false
	}
	return privateACL(ownerSID, dacl == nil, entries, self)
}

// daclEntries decodes the entries of a DACL returned by the system, with
// bounds checks against the ACL's own size.
func daclEntries(acl *winACL) ([]aclEntry, bool) {
	if acl == nil {
		return nil, true
	}
	base := unsafe.Pointer(acl)
	limit := uintptr(acl.size)
	off := unsafe.Sizeof(*acl)
	entries := make([]aclEntry, 0, acl.count)
	for i := 0; i < int(acl.count); i++ {
		if off+unsafe.Sizeof(winACEHeader{}) > limit {
			return nil, false
		}
		hdr := (*winACEHeader)(unsafe.Add(base, off))
		size := uintptr(hdr.size)
		if size < unsafe.Sizeof(winACEHeader{}) || off+size > limit {
			return nil, false
		}
		e := aclEntry{typ: hdr.typ, flags: hdr.flags}
		if hdr.typ == aceTypeAccessAllowed || hdr.typ == aceTypeAccessDenied {
			// ACCESS_ALLOWED_ACE / ACCESS_DENIED_ACE: header, mask, SID.
			const sidOff = 8
			if size < sidOff+8 {
				return nil, false
			}
			subAuthorities := uintptr(*(*byte)(unsafe.Add(base, off+sidOff+1)))
			if sidOff+8+4*subAuthorities > size {
				return nil, false
			}
			s, err := (*syscall.SID)(unsafe.Add(base, off+sidOff)).String()
			if err != nil {
				return nil, false
			}
			e.sid = s
		}
		entries = append(entries, e)
		off += size
	}
	return entries, true
}

var processUser struct {
	once sync.Once
	sid  string
	err  error
}

// currentUserSID returns the SID of the user this process runs as.
func currentUserSID() (string, error) {
	processUser.once.Do(func() {
		t, err := syscall.OpenCurrentProcessToken()
		if err != nil {
			processUser.err = err
			return
		}
		defer t.Close()
		u, err := t.GetTokenUser()
		if err != nil {
			processUser.err = err
			return
		}
		processUser.sid, processUser.err = u.User.Sid.String()
	})
	return processUser.sid, processUser.err
}

// securityDescriptor converts SDDL into a self-relative security descriptor
// allocated by the system; free releases it.
func securityDescriptor(sddl string) (sd uintptr, free func(), err error) {
	p, err := syscall.UTF16PtrFromString(sddl)
	if err != nil {
		return 0, nil, err
	}
	r, _, e := procStringSDToSD.Call(uintptr(unsafe.Pointer(p)), sddlRevision1, uintptr(unsafe.Pointer(&sd)), 0)
	if r == 0 || sd == 0 {
		return 0, nil, e
	}
	return sd, func() { syscall.LocalFree(syscall.Handle(sd)) }, nil
}

// makeReplayDir creates a missing state directory with a protected DACL
// (privateDirSDDL) in one step. An existing directory is left unchanged and
// checked under the lock, like on Unix.
func makeReplayDir(dir string) error {
	if _, err := os.Lstat(dir); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0700); err != nil {
		return err
	}
	sid, err := currentUserSID()
	if err != nil {
		return err
	}
	sd, free, err := securityDescriptor(privateDirSDDL(sid))
	if err != nil {
		return err
	}
	defer free()
	sa := &syscall.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	p, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	if err := syscall.CreateDirectory(p, sa); err != nil && !errors.Is(err, syscall.ERROR_ALREADY_EXISTS) {
		return err
	}
	return nil
}

// setDACL replaces the DACL of path with the (protected) DACL in sddl. The
// store itself never changes existing permissions; tests use it.
func setDACL(path, sddl string) error {
	sd, free, err := securityDescriptor(sddl)
	if err != nil {
		return err
	}
	defer free()
	var present, defaulted int32
	var dacl uintptr
	r, _, e := procGetSecurityDescDA.Call(sd, uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted)))
	if r == 0 {
		return e
	}
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if rc, _, _ := procSetNamedSecurity.Call(uintptr(unsafe.Pointer(p)), seFileObject, daclSecurityInformation|protectedDACLSecurityInfo, 0, 0, dacl, 0); rc != 0 {
		return syscall.Errno(rc)
	}
	return nil
}

// replaceReplayFile atomically replaces path with temp. MOVEFILE_WRITE_THROUGH
// asks the system to complete the move on disk before returning; Windows has
// no portable directory flush, so power-loss durability of the rename itself
// is not guaranteed by this call (see docs). A short retry absorbs sharing
// violations from scanners that briefly open a freshly written file.
func replaceReplayFile(temp, path string) error {
	from, err := syscall.UTF16PtrFromString(temp)
	if err != nil {
		return err
	}
	to, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(replayMoveRetryWindow)
	for {
		r, _, e := procMoveFileExW.Call(uintptr(unsafe.Pointer(from)), uintptr(unsafe.Pointer(to)), moveFileReplaceExisting|moveFileWriteThrough)
		if r != 0 {
			return nil
		}
		transient := errors.Is(e, syscall.ERROR_ACCESS_DENIED) || errors.Is(e, errorSharingViolation) || errors.Is(e, errorLockViolation)
		if !transient || time.Now().After(deadline) {
			return e
		}
		time.Sleep(replayMoveRetryInterval)
	}
}
