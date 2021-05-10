package interfaces

import "context"

type _Enum interface {
	ID() uint32
	Name() string
}

type Permission interface {
	_Enum
}

type Role interface {
	_Enum
	SuperRoleIDs() []uint32
	PermissionIDs() []uint32
	PermissionWildcards() []string
}

type Subject interface {
	ID() int64
}

type Backend interface {
	GetAllPermissions(ctx context.Context) []Permission
	GetAllRoles(ctx context.Context) []Role
	GetSubjectRoleIDs(ctx context.Context, subject Subject) []uint32
	NewPermission(ctx context.Context, name string) error
	DelPermission(ctx context.Context, name string) error

	NewRole(ctx context.Context, name string) error
	DelRole(ctx context.Context, name string) error
	RoleAddPermission(ctx context.Context, role, perm string) error
	RoleDelPermission(ctx context.Context, role, perms string) error
	RoleAddSuper(ctx context.Context, role, super string) error
	RoleDelSuper(ctx context.Context, role, super string) error
	RoleAddWildcard(ctx context.Context, role, wildcard string) error
	RoleDelWildcard(ctx context.Context, role, wildcard string) error

	SubjectAddRole(ctx context.Context, sid int64, role string) error
	SubjectDelRole(ctx context.Context, sid int64, role string) error
}

type Auth interface {
	Auth(ctx context.Context) (Subject, error)
}
