package rbac

import (
	"context"
	"errors"
	"fmt"
	"github.com/RoaringBitmap/roaring"
	ifs "github.com/zzztttkkk/rbac/interfaces"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ErrorSlice []error

func (es ErrorSlice) Error() string {
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

	backend    ifs.Backend
	lastLoad   int64
	loadMaxAge int64

	perms     []ifs.Permission
	wildcards map[string][]ifs.Permission
	roles     []ifs.Role
	bitmaps   map[uint32]*roaring.Bitmap

	byID struct {
		perms map[uint32]ifs.Permission
		roles map[uint32]ifs.Role
	}
	byName struct {
		perms map[string]ifs.Permission
		roles map[string]ifs.Role
	}
	errors ErrorSlice

	cache map[string]*roaring.Bitmap
}

func (rbac *RBAC) Load(ctx context.Context) {
	rbac.Lock()
	defer rbac.Unlock()

	rbac.byID.perms = map[uint32]ifs.Permission{}
	rbac.byID.roles = map[uint32]ifs.Role{}
	rbac.byName.perms = map[string]ifs.Permission{}
	rbac.byName.roles = map[string]ifs.Role{}
	rbac.errors = nil
	rbac.wildcards = map[string][]ifs.Permission{}
	rbac.cache = map[string]*roaring.Bitmap{}

	rbac.perms = rbac.backend.GetAllPermissions(ctx)
	for _, p := range rbac.perms {
		rbac.byID.perms[p.ID()] = p
		rbac.byName.perms[p.Name()] = p
	}

	rbac.roles = rbac.backend.GetAllRoles(ctx)
	rbac.bitmaps = map[uint32]*roaring.Bitmap{}
	rbac.build()

	rbac.lastLoad = time.Now().Unix()
}

func (rbac *RBAC) Errors() []error { return rbac.errors }

func _exists(path []uint32, v uint32) bool {
	for _, i := range path {
		if i == v {
			return true
		}
	}
	return false
}

func (rbac *RBAC) roleByID(id uint32) ifs.Role { return rbac.byID.roles[id] }

func (rbac *RBAC) permByID(id uint32) ifs.Permission { return rbac.byID.perms[id] }

func (rbac *RBAC) roleByName(name string) ifs.Role { return rbac.byName.roles[name] }

func (rbac *RBAC) permByName(name string) ifs.Permission { return rbac.byName.perms[name] }

func (rbac *RBAC) getPermsByWildcard(name string) ([]ifs.Permission, error) {
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

func (rbac *RBAC) traverse(role ifs.Role, bitmap *roaring.Bitmap, path []uint32) error {
	if _exists(path, role.ID()) {
		return fmt.Errorf("rbac: bad role `%s`, `%d`, path: `%v`", role.Name(), role.ID(), path)
	}
	path = append(path, role.ID())

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
		for _, p := range matched {
			bitmap.Add(p.ID())
		}
	}

	for _, superRID := range role.SuperRoleIDs() {
		superR := rbac.roleByID(superRID)
		if superR == nil {
			return fmt.Errorf("rbac: role `%d` is not exists", superRID)
		}
		if err := rbac.traverse(superR, bitmap, path); err != nil {
			return err
		}
	}
	return nil
}

func (rbac *RBAC) build() {
	for _, role := range rbac.roles {
		bitmap := roaring.New()
		if e := rbac.traverse(role, bitmap, nil); e != nil {
			rbac.errors = append(rbac.errors, e)
		} else {
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

func (rbac *RBAC) getJoinedBitmap(ctx context.Context, subject ifs.Subject) (*roaring.Bitmap, error) {
	var rUnlocked = false
	rbac.RLock()
	defer func() {
		if !rUnlocked {
			rbac.RUnlock()
		}
	}()

	roles := rbac.backend.GetSubjectRoleIDs(ctx, subject)
	if len(roles) < 1 {
		return nil, nil
	}
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

func (rbac *RBAC) Ensure(ctx context.Context, subject ifs.Subject, policy _CheckPolicy, perms ...string) error {
	rbac.update(ctx)

	rbac.RLock()
	var pids []uint32
	for _, pName := range perms {
		p := rbac.permByName(pName)
		if p == nil && policy == PolicyAll {
			rbac.RUnlock()
			return ErrPermissionDenied
		}
		if p != nil {
			pids = append(pids, p.ID())
		}
	}
	rbac.RUnlock()
	if len(pids) < 1 {
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
		for _, pid := range pids {
			if !bitmap.Contains(pid) {
				return ErrPermissionDenied
			}
		}
		return nil
	case PolicyAny:
		for _, pid := range pids {
			if bitmap.Contains(pid) {
				return nil
			}
		}
		return ErrPermissionDenied
	}
	return fmt.Errorf("rbac: s, unknown policy `%d`", policy)
}

func (rbac *RBAC) GrantedAll(ctx context.Context, subject ifs.Subject, perms ...string) error {
	return rbac.Ensure(ctx, subject, PolicyAll, perms...)
}

func (rbac *RBAC) GrantedAny(ctx context.Context, subject ifs.Subject, perms ...string) error {
	return rbac.Ensure(ctx, subject, PolicyAny, perms...)
}

var ErrPermissionDenied = errors.New("rbac: permission denied")

func (rbac *RBAC) MustGrantedAll(ctx context.Context, subject ifs.Subject, perms ...string) {
	err := rbac.GrantedAll(ctx, subject, perms...)
	if err != nil {
		panic(err)
	}
}

func (rbac *RBAC) MustGrantedAny(ctx context.Context, subject ifs.Subject, perms ...string) {
	err := rbac.GrantedAny(ctx, subject, perms...)
	if err == nil {
		panic(err)
	}
}

func New(backend ifs.Backend, maxAge int64) *RBAC {
	return &RBAC{backend: backend, loadMaxAge: maxAge}
}
