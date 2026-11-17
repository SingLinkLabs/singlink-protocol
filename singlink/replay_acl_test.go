// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0
package singlink

import "testing"

// The Windows privacy policy, exercised on every platform.
func TestPrivateACLPolicy(t *testing.T) {
	const me = "S-1-5-21-1111111111-2222222222-3333333333-1001"
	const other = "S-1-5-21-1111111111-2222222222-3333333333-1002"
	const everyone, users, creatorOwner = "S-1-1-0", "S-1-5-32-545", "S-1-3-0"
	allow := func(sid string) aclEntry { return aclEntry{typ: aceTypeAccessAllowed, sid: sid} }
	cases := []struct {
		name    string
		owner   string
		null    bool
		entries []aclEntry
		self    string
		want    bool
	}{
		{"private dir", me, false, []aclEntry{allow(sidLocalSystem), allow(sidAdministrators), allow(me)}, me, true},
		{"owned by administrators", sidAdministrators, false, []aclEntry{allow(me), allow(sidOwnerRights)}, me, true},
		{"owned by system service", sidLocalSystem, false, []aclEntry{allow(sidLocalSystem)}, sidLocalSystem, true},
		{"empty DACL (no access)", me, false, nil, me, true},
		{"NULL DACL", me, true, nil, me, false},
		{"unknown self", me, false, nil, "", false},
		{"owned by another user", other, false, []aclEntry{allow(me)}, me, false},
		{"everyone", me, false, []aclEntry{allow(me), allow(everyone)}, me, false},
		{"users group", me, false, []aclEntry{allow(users)}, me, false},
		{"another user", me, false, []aclEntry{allow(other)}, me, false},
		{"creator owner applies to object", me, false, []aclEntry{allow(creatorOwner)}, me, false},
		{"inherit-only creator owner", me, false, []aclEntry{{typ: aceTypeAccessAllowed, flags: aceFlagInheritOnly, sid: creatorOwner}}, me, true},
		{"inherit-only everyone", me, false, []aclEntry{{typ: aceTypeAccessAllowed, flags: aceFlagInheritOnly | 0x3, sid: everyone}}, me, true},
		{"inherited everyone", me, false, []aclEntry{{typ: aceTypeAccessAllowed, flags: 0x10 | 0x3, sid: everyone}}, me, false},
		{"deny everyone", me, false, []aclEntry{{typ: aceTypeAccessDenied, sid: everyone}, allow(me)}, me, true},
		{"callback or object entry", me, false, []aclEntry{{typ: 9, sid: me}}, me, false},
	}
	for _, c := range cases {
		if got := privateACL(c.owner, c.null, c.entries, c.self); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
	if got := privateDirSDDL(me); got != "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;"+me+")" {
		t.Fatalf("unexpected directory SDDL %q", got)
	}
}
