package rbac

import (
	"context"
	"errors"
	"fmt"
	"github.com/RoaringBitmap/roaring"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type _ErrorSlice []error

func (es _ErrorSlice) Error() string {
	var buf strings.Builder
	for i, e := range es {
		buf.WriteString(e.Error())
		if i < len(es)-1 {
			buf.WriteString(", ")
		}
	}
	return buf.String()
}

type RBAC struct {
	sync.RWMutex

	backend    Backend
	lastLoad   int64
	loadMaxAge int64

	perms         []Permission
	wildcards     map[string][]Permission
	roles         []Role
	roleConflicts map[uint32]map[uint32]bool
	bitmaps       map[uint32]*roaring.Bitmap

	byID struct {
		perms map[uint32]Permission
		roles map[uint32]Role
	}
	byName struct {
		perms map[string]Permission
		roles map[string]Role
	}
	errors   _ErrorSlice
	warnings []string

	cache map[string]*roaring.Bitmap
}

func (rbac *RBAC) Load(ctx context.Context) {
	rbac.Lock()
	defer rbac.Unlock()

	rbac.byID.perms = map[uint32]Permission{}
	rbac.byID.roles = map[uint32]Role{}
	rbac.byName.perms = map[string]Permission{}
	rbac.byName.roles = map[string]Role{}
	rbac.errors = nil
	rbac.warnings = nil
	rbac.wildcards = map[string][]Permission{}
	rbac.cache = map[string]*roaring.Bitmap{}

	rbac.perms = rbac.backend.GetAllPermissions(ctx)
	for _, p := range rbac.perms {
		rbac.byID.perms[p.ID()] = p
		rbac.byName.perms[p.Name()] = p
	}

	rbac.roles = rbac.backend.GetAllRoles(ctx)
	rbac.roleConflicts = map[uint32]map[uint32]bool{}
	rbac.bitmaps = map[uint32]*roaring.Bitmap{}
	rbac.build()

	rbac.lastLoad = time.Now().Unix()
}

func (rbac *RBAC) Errors() []error { return rbac.errors }

func (rbac *RBAC) Warnings() []string { return rbac.warnings }

func _exists(path []uint32, v uint32) bool {
	for _, i := range path {
		if i == v {
			return true
		}
	}
	return false
}

func (rbac *RBAC) roleByID(id uint32) Role { return rbac.byID.roles[id] }

func (rbac *RBAC) permByID(id uint32) Permission { return rbac.byID.perms[id] }

func (rbac *RBAC) roleByName(name string) Role { return rbac.byName.roles[name] }

func (rbac *RBAC) permByName(name string) Permission { return rbac.byName.perms[name] }

func (rbac *RBAC) getPermsByWildcard(name string) ([]Permission, error) {
	v, ok := rbac.wildcards[name]
	if !ok {
		v = nil
		if name == "*" {
			v = rbac.perms
		} else {
			if len(name) < 3 || !strings.HasSuffix(name, ".*") {
				return nil, fmt.Errorf("rbac: bad wildcard pattern, `%s`", name)
			}
			name = name[:len(name)-1]
			for _, p := range rbac.perms {
				if strings.HasPrefix(p.Name(), name) {
					v = append(v, p)
				}
			}
		}
		rbac.wildcards[name] = v
	}
	return v, nil
}

func (rbac *RBAC) traverse(role Role, bitmap *roaring.Bitmap, path []uint32, begin Role) error {
	if _exists(path, role.ID()) {
		return fmt.Errorf("rbac: bad role `%s`, `%d`, path: `%v`", role.Name(), role.ID(), path)
	}
	path = append(path, role.ID())

	if role != begin {
		cm := rbac.roleConflicts[begin.ID()]
		if cm[role.ID()] {
			return fmt.Errorf("rbac: role `%s` conflict with `%s`", begin.Name(), role.Name())
		}
		for _, id := range role.ConflictWith() {
			rbac.addRoleConflict(begin.ID(), id, false)
		}
	}

	for _, pid := range role.PermissionIDs() {
		if rbac.permByID(pid) == nil {
			return fmt.Errorf("rbac: permission %d is not exists", pid)
		}

		bitmap.Add(pid)
	}
	for _, wildcard := range role.PermissionWildcards() {
		matched, err := rbac.getPermsByWildcard(wildcard)
		if err != nil {
			return err
		}

		if len(matched) < 1 {
			rbac.warnings = append(
				rbac.warnings,
				fmt.Sprintf("Empty Wildcard: `%s`, on role `%s`", wildcard, role.Name()),
			)
		}

		for _, p := range matched {
			bitmap.Add(p.ID())
		}
	}

	for _, superRID := range role.SuperRoleIDs() {
		superR := rbac.roleByID(superRID)
		if superR == nil {
			return fmt.Errorf("rbac: role `%d` is not exists", superRID)
		}
		if err := rbac.traverse(superR, bitmap, path, begin); err != nil {
			return err
		}
	}
	return nil
}

func (rbac *RBAC) addRoleConflict(a, b uint32, rAdd bool) {
	if a == b {
		rbac.errors = append(rbac.errors, fmt.Errorf("rbac: role `%d` conflict with itself", a))
	}
	m := rbac.roleConflicts[a]
	if m == nil {
		m = map[uint32]bool{}
		rbac.roleConflicts[a] = m
	}
	m[b] = true

	if !rAdd {
		rbac.addRoleConflict(b, a, true)
	}
}

func (rbac *RBAC) build() {
	for _, role := range rbac.roles {
		for _, cR := range role.ConflictWith() {
			rbac.addRoleConflict(role.ID(), cR, false)
		}
	}

	for _, role := range rbac.roles {
		bitmap := roaring.New()
		if e := rbac.traverse(role, bitmap, nil, role); e != nil {
			rbac.errors = append(rbac.errors, e)
		} else {
			if bitmap.IsEmpty() {
				rbac.warnings = append(rbac.warnings, fmt.Sprintf("Empty Role: `%s`", role.Name()))
			}
			rbac.bitmaps[role.ID()] = bitmap
		}
	}
}

type _CheckPolicy int

const (
	PolicyAll = _CheckPolicy(iota)
	PolicyAny
)

func (rbac *RBAC) update(ctx context.Context) {
	rbac.RLock()
	if time.Now().Unix()-rbac.lastLoad <= rbac.loadMaxAge {
		rbac.RUnlock()
		return
	}
	rbac.RUnlock()

	rbac.Load(ctx)
}

func (rbac *RBAC) getJoinedBitmap(ctx context.Context, subject Subject) (*roaring.Bitmap, error) {
	roles := rbac.backend.GetSubjectRoleIDs(ctx, subject)
	if len(roles) < 1 {
		return nil, nil
	}

	var rUnlocked = false
	rbac.RLock()
	defer func() {
		if !rUnlocked {
			rbac.RUnlock()
		}
	}()

	if len(roles) == 1 {
		return rbac.bitmaps[roles[0]], nil
	}

	sort.Slice(roles, func(i, j int) bool { return roles[i] < roles[j] })
	var keyBuf strings.Builder
	for _, rid := range roles {
		keyBuf.WriteString(strconv.FormatInt(int64(rid), 10))
		keyBuf.WriteRune('|')
	}

	bitmap, ok := rbac.cache[keyBuf.String()]
	if ok {
		return bitmap, nil
	}
	rbac.RUnlock()
	rUnlocked = true

	rbac.Lock()
	defer rbac.Unlock()

	bitmap = roaring.New()
	for _, rid := range roles {
		bm := rbac.bitmaps[rid]
		if bm != nil {
			bitmap.Or(bm)
		}
	}
	rbac.cache[keyBuf.String()] = bitmap
	return bitmap, nil
}

func (rbac *RBAC) IsGranted(ctx context.Context, subject Subject, policy _CheckPolicy, perms ...string) error {
	rbac.update(ctx)

	rbac.RLock()
	var requiredPermIDs []uint32
	for _, pName := range perms {
		p := rbac.permByName(pName)
		if p == nil && policy == PolicyAll {
			rbac.RUnlock()
			return ErrPermissionDenied
		}
		if p != nil {
			requiredPermIDs = append(requiredPermIDs, p.ID())
		}
	}
	rbac.RUnlock()
	if len(requiredPermIDs) < 1 {
		return ErrPermissionDenied
	}

	bitmap, err := rbac.getJoinedBitmap(ctx, subject)
	if err != nil {
		return err
	}
	if bitmap == nil {
		return ErrPermissionDenied
	}

	switch policy {
	case PolicyAll:
		for _, pid := range requiredPermIDs {
			if !bitmap.Contains(pid) {
				return ErrPermissionDenied
			}
		}
		return nil
	case PolicyAny:
		for _, pid := range requiredPermIDs {
			if bitmap.Contains(pid) {
				return nil
			}
		}
		return ErrPermissionDenied
	}
	return fmt.Errorf("rbac: s, unknown policy `%d`", policy)
}

func (rbac *RBAC) IsGrantedAll(ctx context.Context, subject Subject, perms ...string) error {
	return rbac.IsGranted(ctx, subject, PolicyAll, perms...)
}

func (rbac *RBAC) IsGrantedAny(ctx context.Context, subject Subject, perms ...string) error {
	return rbac.IsGranted(ctx, subject, PolicyAny, perms...)
}

var ErrPermissionDenied = errors.New("rbac: permission denied")

func (rbac *RBAC) MustGrantedAll(ctx context.Context, subject Subject, perms ...string) {
	err := rbac.IsGrantedAll(ctx, subject, perms...)
	if err != nil {
		panic(err)
	}
}

func (rbac *RBAC) MustGrantedAny(ctx context.Context, subject Subject, perms ...string) {
	err := rbac.IsGrantedAny(ctx, subject, perms...)
	if err == nil {
		panic(err)
	}
}

func (rbac *RBAC) RolePermissions(ctx context.Context, role string) []Permission {
	rbac.update(ctx)

	rbac.RLock()
	defer rbac.RUnlock()

	var lst []Permission
	r := rbac.roleByName(role)
	if r == nil {
		return lst
	}

	bitmap := rbac.bitmaps[r.ID()]
	if bitmap == nil {
		return lst
	}
	iter := bitmap.Iterator()
	for iter.HasNext() {
		lst = append(lst, rbac.permByID(iter.Next()))
	}
	return lst
}

func (rbac *RBAC) RoleConflict(ctx context.Context, roleIDs []uint32) []error {
	var errs []error
	for i, a := range roleIDs {
		for j := i + 1; j < len(roleIDs); j++ {
			b := roleIDs[j]

			m := rbac.roleConflicts[a]
			if m == nil {
				errs = append(errs, fmt.Errorf("role: `%d` is not exists", a))
				continue
			}
			if m[b] {
				errs = append(errs, fmt.Errorf("role `%d` conflict with `%d`", a, b))
			}
		}
	}
	return errs
}

func New(backend Backend, maxAge int64) *RBAC {
	return &RBAC{backend: backend, loadMaxAge: maxAge}
}
