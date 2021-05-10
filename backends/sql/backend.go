package sql

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/zzztttkkk/rbac/interfaces"
	"github.com/zzztttkkk/sqlx"
	sqltypes "github.com/zzztttkkk/sqlx/types"
	"math/rand"
	"time"
)

type Backend struct {
	perm  *sqlx.Operator
	role  *sqlx.Operator
	roles *sqlx.Operator
}

func (b *Backend) GetAllPermissions(ctx context.Context) []interfaces.Permission {
	var lst []interfaces.Permission
	sqlStr := b.perm.SqlSelect("*", "deleted is null")
	ctx, exe := sqlx.PickExecutor(ctx)
	rows, err := exe.Rows(ctx, sqlStr, nil)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		panic(err)
	}
	defer rows.Close()
	for rows.Next() {
		var perm = &Permission{}
		if err := rows.Scan(perm); err != nil {
			panic(err)
		}
		lst = append(lst, perm)
	}
	return lst
}

func (b *Backend) GetAllRoles(ctx context.Context) []interfaces.Role {
	var lst []interfaces.Role
	sqlStr := b.role.SqlSelect("*", "deleted is null")
	ctx, exe := sqlx.PickExecutor(ctx)
	rows, err := exe.Rows(ctx, sqlStr, nil)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		panic(err)
	}
	defer rows.Close()
	for rows.Next() {
		var dist = &Role{}
		if err := rows.Scan(dist); err != nil {
			panic(err)
		}
		lst = append(lst, dist)
	}
	return lst
}

func (b *Backend) GetSubjectRoleIDs(ctx context.Context, subject interfaces.Subject) []uint32 {
	var roles sqltypes.U32Set
	if err := b.roles.Get(
		ctx, "!roles", "id=${uid}", sqlx.ParamSlice{subject.ID()},
		sqlx.DirectDists{&roles},
	); err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		panic(err)
	}
	return roles
}

func (b *Backend) idByName(ctx context.Context, op *sqlx.Operator, name string) (uint32, error) {
	var pid uint32
	if err := op.Get(
		ctx, "!id",
		"name=${name} and deleted is null", sqlx.ParamSlice{name},
		sqlx.DirectDists{&pid},
	); err != nil && err != sql.ErrNoRows {
		return 0, err
	}
	return pid, nil
}

func (b *Backend) newRoleOrPerm(ctx context.Context, op *sqlx.Operator, name string) error {
	id, err := b.idByName(ctx, op, name)
	if err != nil {
		return err
	}
	if id != 0 {
		return nil
	}
	type Arg struct {
		Name    string    `db:"name"`
		Created time.Time `db:"created"`
	}
	_, err = op.Insert(ctx, Arg{Name: name, Created: time.Now()}, nil)
	return err
}

func (b *Backend) delRoleOrPerm(ctx context.Context, op *sqlx.Operator, name string) error {
	id, err := b.idByName(ctx, op, name)
	if err != nil {
		return err
	}
	if id == 0 {
		return nil
	}

	type CondArg struct {
		Id uint32 `db:"id"`
	}

	type DataArg struct {
		Name    string    `db:"name"`
		Deleted time.Time `db:"deleted"`
	}
	_, err = op.Update(
		ctx,
		"id=${id}", CondArg{id},
		DataArg{fmt.Sprintf("Deleted<%s>.(%d)", name, rand.Int63()), time.Now()},
		nil,
	)
	return err
}

func (b *Backend) NewPermission(ctx context.Context, name string) error {
	return b.newRoleOrPerm(ctx, b.perm, name)
}

func (b *Backend) DelPermission(ctx context.Context, name string) error {
	return b.delRoleOrPerm(ctx, b.perm, name)
}

func (b *Backend) NewRole(ctx context.Context, name string) error {
	return b.newRoleOrPerm(ctx, b.role, name)
}

func (b *Backend) DelRole(ctx context.Context, name string) error {
	return b.delRoleOrPerm(ctx, b.role, name)
}

func (b *Backend) RoleAddPermission(ctx context.Context, role, perm string) error {
	pid, err := b.idByName(ctx, b.perm, perm)
	if err != nil {
		return err
	}
	if pid == 0 {
		return sql.ErrNoRows
	}

	var rid uint32
	var perms sqltypes.U32Set
	if err := b.role.Get(
		ctx, "!id,permissions",
		"name=${name} and deleted is null", sqlx.ParamSlice{role},
		sqlx.DirectDists{&rid, &perms},
	); err != nil {
		return err
	}
	perms = append(perms, pid)

	type CondArg struct {
		Id uint32 `db:"id"`
	}
	type Arg struct {
		Permissions sqltypes.U32Set `db:"permissions"`
	}
	_, err = b.role.Update(ctx, "id=${id}", CondArg{Id: rid}, Arg{perms}, nil)
	return err
}

func (b *Backend) RoleDelPermission(ctx context.Context, role, perm string) error {
	pid, err := b.idByName(ctx, b.perm, perm)
	if err != nil {
		return err
	}
	if pid == 0 {
		return sql.ErrNoRows
	}

	var rid uint32
	var perms sqltypes.U32Set
	if err := b.role.Get(
		ctx, "!id,permissions",
		"name=${name} and deleted is null", sqlx.ParamSlice{role},
		sqlx.DirectDists{&rid, &perms},
	); err != nil {
		return err
	}

	var nPerms sqltypes.U32Set
	for _, _id := range perms {
		if _id != pid {
			nPerms = append(nPerms, _id)
		}
	}

	if len(nPerms) == len(perms) {
		return nil
	}

	type CondArg struct {
		Id uint32 `db:"id"`
	}
	type Arg struct {
		Permissions sqltypes.U32Set `db:"permissions"`
	}
	_, err = b.role.Update(ctx, "id=${id}", CondArg{Id: rid}, Arg{nPerms}, nil)
	return err
}

func (b *Backend) RoleAddSuper(ctx context.Context, role, super string) error {
	sid, err := b.idByName(ctx, b.role, super)
	if err != nil {
		return err
	}
	if sid == 0 {
		return sql.ErrNoRows
	}

	var rid uint32
	var supers sqltypes.U32Set
	if err := b.role.Get(
		ctx, "!id,supers",
		"name=${name} and deleted is null", sqlx.ParamSlice{role},
		sqlx.DirectDists{&rid, &supers},
	); err != nil {
		return err
	}
	supers = append(supers, sid)

	type CondArg struct {
		Id uint32 `db:"id"`
	}
	type Arg struct {
		Supers sqltypes.U32Set `db:"supers"`
	}
	_, err = b.role.Update(ctx, "id=${id}", CondArg{rid}, Arg{supers}, nil)
	return err
}

func (b *Backend) RoleDelSuper(ctx context.Context, role, super string) error {
	sid, err := b.idByName(ctx, b.role, super)
	if err != nil {
		return err
	}
	if sid == 0 {
		return sql.ErrNoRows
	}

	var rid uint32
	var supers sqltypes.U32Set
	if err := b.role.Get(
		ctx, "!id,supers",
		"name=${name} and deleted is null", sqlx.ParamSlice{role},
		sqlx.DirectDists{&rid, &supers},
	); err != nil {
		return err
	}

	var nSupers sqltypes.U32Set
	for _, _id := range supers {
		if _id != sid {
			nSupers = append(nSupers, _id)
		}
	}

	if len(nSupers) == len(supers) {
		return nil
	}

	type CondArg struct {
		Id uint32 `db:"id"`
	}
	type Arg struct {
		Supers sqltypes.U32Set `db:"supers"`
	}
	_, err = b.role.Update(ctx, "id=${id}", CondArg{rid}, Arg{nSupers}, nil)
	return err
}

func (b *Backend) RoleAddWildcard(ctx context.Context, role, wildcard string) error {
	var rid uint32
	var wcs sqltypes.StrSet
	if err := b.role.Get(
		ctx, "!id,wildcards",
		"name=${name} and deleted is null", sqlx.ParamSlice{role},
		sqlx.DirectDists{&rid, &wcs},
	); err != nil {
		return err
	}
	wcs = append(wcs, wildcard)
	type CondArg struct {
		Id uint32 `db:"id"`
	}
	type Arg struct {
		Wildcards sqltypes.StrSet `db:"wildcards"`
	}
	_, err := b.role.Update(ctx, "id=${id}", CondArg{rid}, Arg{wcs}, nil)
	return err
}

func (b *Backend) RoleDelWildcard(ctx context.Context, role, wildcard string) error {
	var rid uint32
	var wcs sqltypes.StrSet
	if err := b.role.Get(
		ctx, "!id,wildcards",
		"name=${name} and deleted is null", sqlx.ParamSlice{role},
		sqlx.DirectDists{&rid, &wcs},
	); err != nil {
		return err
	}

	var nWcs sqltypes.StrSet
	for _, _id := range wcs {
		if _id != wildcard {
			nWcs = append(nWcs, _id)
		}
	}

	if len(nWcs) == len(wcs) {
		return nil
	}

	type CondArg struct {
		Id uint32 `db:"id"`
	}
	type Arg struct {
		Wildcards sqltypes.StrSet `db:"wildcards"`
	}
	_, err := b.role.Update(ctx, "id=${id}", CondArg{rid}, Arg{nWcs}, nil)
	return err
}

func (b *Backend) SubjectAddRole(ctx context.Context, sid int64, role string) error {
	rid, err := b.idByName(ctx, b.role, role)
	if err != nil {
		return err
	}
	if rid == 0 {
		return sql.ErrNoRows
	}

	var roles sqltypes.U32Set
	if err := b.roles.Get(
		ctx, "!roles",
		"id=${id}", sqlx.ParamSlice{sid},
		sqlx.DirectDists{&roles},
	); err != nil {
		return err
	}

	roles = append(roles, rid)

	ctx, exe := sqlx.PickExecutor(ctx)
	var sqlInsertOrUpdate string
	switch exe.DB().DriverType() {
	case sqlx.DriverTypeMysql:
		sqlInsertOrUpdate = "insert into rbac_subject_roles (id, roles) values(${id}, ${roles}) on duplicate key update rbac_subject_roles.roles=excluded.roles"
	case sqlx.DriverTypePostgres:
		sqlInsertOrUpdate = "insert into rbac_subject_roles (id, roles) values(${id}, ${roles}) on conflict (id) do update set roles=excluded.roles"
	default:
		return fmt.Errorf("rbac: unsupported sql driver")
	}
	_, err = exe.Execute(ctx, sqlInsertOrUpdate, sqlx.ParamSlice{sid, roles})
	return err
}

func (b *Backend) SubjectDelRole(ctx context.Context, sid int64, role string) error {
	rid, err := b.idByName(ctx, b.role, role)
	if err != nil {
		return err
	}
	if rid == 0 {
		return nil
	}

	var roles sqltypes.U32Set
	if err := b.roles.Get(
		ctx, "!roles",
		"id=${id}", sqlx.ParamSlice{sid},
		sqlx.DirectDists{&roles},
	); err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return err
	}

	var nRoles sqltypes.U32Set
	for _, _id := range roles {
		if _id != rid {
			nRoles = append(nRoles, _id)
		}
	}

	if len(nRoles) == len(roles) {
		return nil
	}
	type CondArg struct {
		Id uint32 `db:"id"`
	}
	type Arg struct {
		Roles sqltypes.U32Set `db:"roles"`
	}
	_, err = b.roles.Update(ctx, "id=${id}", CondArg{rid}, Arg{nRoles}, nil)
	return err
}

var _ interfaces.Backend = (*Backend)(nil)

func New() (interfaces.Backend, error) {
	v := &Backend{}

	v.perm = sqlx.NewOperator(&Permission{})
	err := v.perm.CreateTable(context.Background())
	if err != nil {
		return nil, err
	}

	v.role = sqlx.NewOperator(&Role{})
	err = v.role.CreateTable(context.Background())
	if err != nil {
		return nil, err
	}

	v.roles = sqlx.NewOperator(&SubjectRoles{})
	err = v.roles.CreateTable(context.Background())
	if err != nil {
		return nil, err
	}
	return v, nil
}
