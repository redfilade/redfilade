// Package db holds the database migrations and the tenancy test, embedded so
// the Test Bench can apply and check them.
package db

import "embed"

// Files holds migrations/*.sql (applied in name order) and tests/*.sql.
//
//go:embed migrations/*.sql tests/*.sql
var Files embed.FS
