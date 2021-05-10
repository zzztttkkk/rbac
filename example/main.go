package main

import (
	"context"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	"github.com/zzztttkkk/rbac"
	"github.com/zzztttkkk/rbac/backends/sql"
	ifs "github.com/zzztttkkk/rbac/interfaces"
	"github.com/zzztttkkk/sqlx"
	"io"
	"net/http"
)

type Req struct {
	*http.Request
}

type SubjectInt int64

func (s SubjectInt) ID() int64 {
	return int64(s)
}

func (r Req) Subject() ifs.Subject {
	return SubjectInt(1)
}

func (r Req) GetContext() context.Context {
	return r.Request.Context()
}

func (r Req) GetMethod() string {
	return r.Method
}

func (r Req) GetBody() io.Reader {
	return r.Body
}

var _ rbac.Request = (*Req)(nil)

type _Mux struct {
	mux *http.ServeMux
}

func (m *_Mux) HandleFunc(p string, fn rbac.Handler) {
	m.mux.HandleFunc(
		p,
		func(writer http.ResponseWriter, request *http.Request) { fn(writer, &Req{request}) },
	)
}

var _ rbac.Router = (*_Mux)(nil)

func main() {
	_, err := sqlx.OpenWriteableDB("postgres", "user=postgres password=123456 port=15432 database=testing sslmode=disable")
	if err != nil {
		panic(err)
	}

	var server http.Server
	var mux = http.NewServeMux()
	backend, err := sql.New()
	if err != nil {
		panic(err)
	}

	_ = backend.NewRole(context.Background(), "root")
	_ = backend.RoleAddWildcard(context.Background(), "root", "*")
	e := backend.SubjectAddRole(context.Background(), 1, "root")
	if e != nil {
		panic(e)
	}

	rbac.Register(&_Mux{mux: mux}, backend, nil)

	server.Handler = mux
	server.Addr = "127.0.0.1:8080"
	fmt.Println("Listening @ " + server.Addr)
	_ = server.ListenAndServe()
}
