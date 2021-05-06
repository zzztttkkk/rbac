package internal

import (
	"context"
	"github.com/zzztttkkk/rbac/interfaces"
)

type Backend interface {
	interfaces.Backend

	NewPermission(ctx context.Context, name string) error
	DelPermission(ctx context.Context, name string) error

	NewRole(ctx context.Context, name string) error
	RoleAddPermission(ctx context.Context, role, perm string) error
	RoleDelPermission(ctx context.Context, role, perms string) error
	RoleAddSuper(ctx context.Context, role, super string) error
	RoleDelSuper(ctx context.Context, role, super string) error
}
