package interfaces

import "context"

type _Enum interface {
	ID() uint32
	Name() string
}

type Permission interface {
	_Enum
	MutexPermissions() []uint32
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
	LastModified(ctx context.Context) (int64, int64)

	GetAllPermissions(ctx context.Context) []Permission
	GetAllRoles(ctx context.Context) []Role
	GetSubjectRoleIDs(ctx context.Context, subject Subject) []uint32
}
