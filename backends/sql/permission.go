package sql

import (
	"github.com/zzztttkkk/rbac/interfaces"
	"github.com/zzztttkkk/sqlx"
	"time"
)

type Permission struct {
	IDValue   uint32     `db:"id" json:"id"`
	NameValue string     `db:"name" json:"name"`
	Created   time.Time  `db:"created" json:"created"`
	Deleted   *time.Time `db:"deleted" json:"deleted,omitempty"`
}

func (p *Permission) TableName() string {
	return "rbac_permission"
}

func (p *Permission) TableColumns(db *sqlx.DB) []string {
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
		"created timestamp not null",
		"deleted timestamp",
	}
}

func (p *Permission) ID() uint32 {
	return p.IDValue
}

func (p *Permission) Name() string {
	return p.NameValue
}

var _ interfaces.Permission = (*Permission)(nil)
