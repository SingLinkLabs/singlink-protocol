// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0
package singlink

// Windows access-control policy for the reference replay store, kept free of
// system calls so it is tested on every platform. replay_lock_windows.go reads
// the owner and DACL of the real object and asks privateACL.

// Well-known Windows security identifiers.
const (
	sidLocalSystem    = "S-1-5-18"     // NT AUTHORITY\SYSTEM
	sidAdministrators = "S-1-5-32-544" // BUILTIN\Administrators
	sidOwnerRights    = "S-1-3-4"      // OWNER RIGHTS (whoever owns the object)
)

// ACE header values (winnt.h).
const (
	aceTypeAccessAllowed = 0x0
	aceTypeAccessDenied  = 0x1
	aceFlagInheritOnly   = 0x8
)

// aclEntry is one access control entry of a DACL: type, flags and trustee.
type aclEntry struct {
	typ   byte
	flags byte
	sid   string
}

// privateACL is the Windows equivalent of "owned by this user, mode 0700/0600".
// The object must be owned by self, SYSTEM or Administrators (the root
// equivalents) and its DACL may grant access only to self, SYSTEM,
// Administrators and OWNER RIGHTS. A NULL DACL (everyone has full access) and
// any entry type other than plain allow/deny fail closed. Deny entries only
// remove access, and inherit-only entries do not apply to the object itself
// (its children are checked on their own).
func privateACL(owner string, nullDACL bool, entries []aclEntry, self string) bool {
	if self == "" || nullDACL {
		return false
	}
	switch owner {
	case self, sidLocalSystem, sidAdministrators:
	default:
		return false
	}
	for _, e := range entries {
		switch e.typ {
		case aceTypeAccessDenied:
			continue
		case aceTypeAccessAllowed:
		default:
			return false
		}
		if e.flags&aceFlagInheritOnly != 0 {
			continue
		}
		switch e.sid {
		case self, sidLocalSystem, sidAdministrators, sidOwnerRights:
		default:
			return false
		}
	}
	return true
}

// privateDirSDDL is the protected DACL given to a replay state directory the
// store creates on Windows: full control for self, SYSTEM and Administrators,
// inherited by the lock, state and temporary files, and nothing inherited
// from the parent directory.
func privateDirSDDL(self string) string {
	return "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + self + ")"
}
