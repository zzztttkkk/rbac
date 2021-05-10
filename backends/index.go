package backends

import (
	"github.com/zzztttkkk/rbac/backends/sql"
	"github.com/zzztttkkk/rbac/interfaces"
)

func NewSqlBackend() (interfaces.Backend, error) { return sql.New() }
