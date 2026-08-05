// Package audit is the composition root for the Audit context (ADR-0025).
//
// It exists because Go's internal/ rule stops cmd/ from naming an internal type, so without it
// "wire in cmd/" is not expressible. One constructor per adapter choice; cmd/ picks one.
package audit

import (
	"github.com/gitfrok/backend/modules/audit/api"
	auditpg "github.com/gitfrok/backend/modules/audit/internal/adapters/postgres"
	"github.com/gitfrok/backend/platform/db"
)

// NewPostgresLog returns the Postgres-backed audit log as its api.Log surface — Append and Verify,
// with no update or delete path to hand out (SPEC-0003 AC1).
func NewPostgresLog(pool *db.Pool) api.Log { return auditpg.New(pool) }
