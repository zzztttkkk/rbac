package sql

import (
	"github.com/zzztttkkk/sqlx"
	sqltypes "github.com/zzztttkkk/sqlx/types"
)

type SubjectRoles struct {
	ID    int64           `db:"id" json:"id"`
	Roles sqltypes.U32Set `db:"roles" json:"roles"`
}

func (s *SubjectRoles) TableName() string {
	return "rbac_subject_roles"
}

func (s *SubjectRoles) TableColumns(db *sqlx.DB) []string {
	return []string{
		"id bigint primary key not null",
		"roles varchar(2048)",
	}
}
