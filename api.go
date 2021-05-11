package rbac

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/zzztttkkk/sqlx"
	"io"
	"net/http"
	"regexp"
)

var initPerms []string

func perm(v string) string {
	initPerms = append(initPerms, v)
	return v
}

var (
	PermApiLogin = perm("rbac.api.login")
	PermApiWrite = perm("rbac.api.write")
	PermApiRead  = perm("rbac.api.read")
)

func errorHandler(w http.ResponseWriter, request Request, v interface{}) {
	if ace, ok := v.(*sqlx.AutoCommitError); ok {
		if ace.Recoverd != nil {
			errorHandler(w, request, ace.Recoverd)
			return
		}
	}

	if err, ok := v.(error); ok {
		switch err {
		case ErrPermissionDenied:
			w.WriteHeader(http.StatusForbidden)
			return
		case sql.ErrNoRows:
			w.WriteHeader(http.StatusNotFound)
			return
		default:
			panic(err)
		}
	} else {
		panic(err)
	}
}

func makeIndex(backend Backend) Handler {
	return func(res http.ResponseWriter, req Request) {
		if req.GetMethod() != http.MethodGet {
			res.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		ctx, tx := sqlx.MustBegin(req.GetContext(), &sqlx.TxOptions{TxOptions: sql.TxOptions{ReadOnly: true}})
		defer tx.AutoCommit()
		var rbac RBAC
		rbac.backend = backend
		rbac.Load(ctx)
		rbac.MustGrantedAll(ctx, req.Subject(), PermApiLogin)

	}
}

func writeJSON(res http.ResponseWriter, data interface{}) {
	res.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(res).Encode(data)
}

func makeGetAll(backend Backend) Handler {
	return func(res http.ResponseWriter, req Request) {
		if req.GetMethod() != http.MethodGet {
			res.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		ctx, tx := sqlx.MustBegin(req.GetContext(), &sqlx.TxOptions{TxOptions: sql.TxOptions{ReadOnly: true}})
		defer tx.AutoCommit()

		var rbac RBAC
		rbac.backend = backend
		rbac.Load(ctx)
		rbac.MustGrantedAll(ctx, req.Subject(), PermApiRead)

		type Data struct {
			Permissions []Permission
			Roles       []Role
		}
		var data Data
		data.Permissions = backend.GetAllPermissions(ctx)
		data.Roles = backend.GetAllRoles(ctx)
		writeJSON(res, data)
	}
}

type Op struct {
	Type       string `json:"type"`
	Column     string `json:"column"`
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	SecondName string `json:"second_name"`
}

type Request interface {
	GetContext() context.Context
	GetMethod() string
	GetBody() io.Reader
	Subject() Subject
}

type Handler func(w http.ResponseWriter, req Request)

func makeSave(backend Backend) Handler {
	return func(res http.ResponseWriter, req Request) {
		if req.GetMethod() != http.MethodPost {
			res.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var ops []Op
		decoder := json.NewDecoder(req.GetBody())
		err := decoder.Decode(&ops)
		if err != nil {
			res.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(ops) < 1 {
			return
		}

		ctx, tx := sqlx.MustBegin(req.GetContext(), nil)
		defer tx.AutoCommit()

		var rbac RBAC
		rbac.backend = backend
		rbac.Load(ctx)
		rbac.MustGrantedAll(ctx, req.Subject(), PermApiWrite)

		for ind := 0; ind < len(ops); ind++ {
			err = applyOp(ctx, &(ops[ind]), backend)
			if err != nil {
				panic(err)
			}
		}
	}
}

var nameRegexp = regexp.MustCompile(`^\w+(.\w+)*$`)

func check(op *Op, cID bool, cSN bool) error {
	if !nameRegexp.MatchString(op.Name) {
		return fmt.Errorf("rbac: bad name `%s`", op.Name)
	}
	if cID && op.ID < 1 {
		return fmt.Errorf("rbac: bad subject id `%d`", op.ID)
	}
	if cSN && !nameRegexp.MatchString(op.Name) {
		return fmt.Errorf("rbac: bad name `%s`", op.SecondName)
	}
	return nil
}

func applyOp(ctx context.Context, op *Op, backend Backend) error {
	if op.Type != "add" && op.Type != "del" {
		return fmt.Errorf("rbac: unknown op type `%s`", op.Type)
	}

	var err error
	var doLoadCheck bool
	switch op.Column {
	case "perm":
		if err = check(op, false, false); err != nil {
			return err
		}
		switch op.Type {
		case "add":
			err = backend.NewPermission(ctx, op.Name)
		case "del":
			err = backend.DelPermission(ctx, op.Name)
		}
	case "role":
		if err = check(op, false, false); err != nil {
			return err
		}
		switch op.Type {
		case "add":
			err = backend.NewRole(ctx, op.Name)
		case "del":
			err = backend.DelPermission(ctx, op.Name)
		}
	case "role.perm":
		if err = check(op, false, true); err != nil {
			return err
		}
		switch op.Type {
		case "add":
			err = backend.RoleDelPermission(ctx, op.Name, op.SecondName)
		case "del":
			err = backend.RoleDelPermission(ctx, op.Name, op.SecondName)
		}
	case "role.super":
		doLoadCheck = true
		if err = check(op, false, true); err != nil {
			return err
		}
		switch op.Type {
		case "add":
			err = backend.RoleAddSuper(ctx, op.Name, op.SecondName)
		case "del":
			err = backend.RoleDelSuper(ctx, op.Name, op.SecondName)
		}
	case "role.conflicts":
		doLoadCheck = true
		if err = check(op, false, true); err != nil {
			return err
		}
		switch op.Type {
		case "add":
			err = backend.RoleAddConflict(ctx, op.Name, op.SecondName)
		case "del":
			err = backend.RoleDelConflict(ctx, op.Name, op.SecondName)
		}
	case "subject":
		if err = check(op, true, false); err != nil {
			return err
		}
		switch op.Type {
		case "add":
			err = backend.SubjectAddRole(ctx, op.ID, op.Name)
		case "del":
			err = backend.SubjectDelRole(ctx, op.ID, op.Name)
		}
	default:
		return fmt.Errorf("rbac: unknown column `%s`", op.Column)
	}

	if err != nil {
		return err
	}

	if doLoadCheck {
		var rbac RBAC
		rbac.backend = backend
		rbac.Load(ctx)

		if len(rbac.errors) > 0 {
			return rbac.errors
		}
		return nil
	}
	return nil
}

type Router interface {
	HandleFunc(p string, fn Handler)
}

type Options struct {
	PathPrefix   string
	ErrorHandler func(w http.ResponseWriter, r Request, v interface{})
}

func wrap(handler Handler, er func(w http.ResponseWriter, r Request, v interface{})) Handler {
	return func(w http.ResponseWriter, req Request) {
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			er(w, req, v)
		}()
		handler(w, req)
	}
}

func Register(mux Router, backend Backend, opt *Options) {
	for _, p := range initPerms {
		if err := backend.NewPermission(context.Background(), p); err != nil {
			panic(err)
		}
	}

	if opt == nil {
		opt = &Options{PathPrefix: "/rbac", ErrorHandler: errorHandler}
	}
	if opt.ErrorHandler == nil {
		opt.ErrorHandler = errorHandler
	}

	mux.HandleFunc(opt.PathPrefix+"/", wrap(makeIndex(backend), opt.ErrorHandler))
	mux.HandleFunc(opt.PathPrefix+"/get", wrap(makeGetAll(backend), opt.ErrorHandler))
	mux.HandleFunc(opt.PathPrefix+"/save", wrap(makeSave(backend), opt.ErrorHandler))
}
