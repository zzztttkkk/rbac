module example

go 1.16

require (
	github.com/go-sql-driver/mysql v1.6.0
	github.com/lib/pq v1.10.1
	github.com/zzztttkkk/rbac v0.0.0
	github.com/zzztttkkk/sqlx v0.0.2
)

replace github.com/zzztttkkk/rbac v0.0.0 => ../
replace github.com/zzztttkkk/sqlx v0.0.2 => ../../sqlx
