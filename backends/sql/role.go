package sql

import (
	"github.com/zzztttkkk/rbac/interfaces"
	"github.com/zzztttkkk/sqlx"
	sqltypes "github.com/zzztttkkk/sqlx/types"
	"time"
)

type Role struct {
	IDValue     uint32          `db:"id" json:"id"`
	NameValue   string          `db:"name" json:"name"`
	Supers      sqltypes.U32Set `db:"supers" json:"supers,omitempty"`
	Permissions sqltypes.U32Set `db:"permissions" json:"permissions,omitempty"`
	Wildcards   sqltypes.StrSet `db:"wildcards" json:"wildcards,omitempty"`
	Conflicts   sqltypes.U32Set `db:"conflicts" json:"conflicts,omitempty"`
	Created     time.Time       `db:"created" json:"created"`
	Deleted     *time.Time      `db:"deleted" json:"deleted,omitempty"`
}

func (r *Role) TableName() string {
	return "rbac_role"
}

func (r *Role) TableColumns(db *sqlx.DB) []string {
	var idC string

	switch db.DriverType() {
	case sqlx.DriverTypeMysql:
		idC = "id bigint primary key not null auto_increment"
	case sqlx.DriverTypePostgres:
		idC = "id serial8 primary key not null"
	}
	return []string{
		idC,
		"name varchar(128) not null",
		"supers varchar(2048)",
		"permissions varchar(2048)",
		"wildcards varchar(2048)",
		"created timestamp not null",
		"deleted timestamp",
	}
}

func (r *Role) ID() uint32 {
	return r.IDValue
}

func (r *Role) Name() string {
	return r.NameValue
}

func (r *Role) SuperRoleIDs() []uint32 {
	return r.Supers.ToSlice()
}

func (r *Role) PermissionIDs() []uint32 {
	return r.Permissions.ToSlice()
}

func (r *Role) PermissionWildcards() []string {
	return r.Wildcards.ToSlice()
}

func (r *Role) ConflictWith() []uint32 {
	return r.Conflicts.ToSlice()
}

var _ interfaces.Role = (*Role)(nil)
