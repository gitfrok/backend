package postgres

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/gitfrok/backend/modules/notifications/api"
	"github.com/gitfrok/backend/modules/notifications/internal/app"
	"github.com/gitfrok/backend/platform/db"
)

// Store is the durable notifications store: one row per (recipient, event)
// behind forced RLS (SPEC-0063 AC4/AC5).
type Store struct {
	pool *db.Pool
}

func New(pool *db.Pool) *Store {
	if pool == nil {
		panic("notifications postgres: pool is required")
	}
	return &Store{pool: pool}
}

func (s *Store) Append(ctx context.Context, rows []app.Row) error {
	return s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		for _, r := range rows {
			// ON CONFLICT DO NOTHING is the idempotency proof (AC4): a replayed
			// event lands on the same natural key and changes nothing.
			if _, err := tx.Exec(ctx,
				`INSERT INTO notifications.items
				   (tenant_id, recipient_id, event_id, kind, repository_id, merge_request_id, actor_id, head_revision, occurred_at)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
				 ON CONFLICT (tenant_id, recipient_id, event_id) DO NOTHING`,
				r.TenantID, r.RecipientID, r.EventID, string(r.Kind),
				r.RepositoryID, r.MergeRequestID, r.ActorID, r.HeadRevision, r.OccurredAt,
			); err != nil {
				return err
			}
		}
		return nil
	})
}

const itemColumns = `event_id, kind, repository_id, merge_request_id, actor_id, head_revision, occurred_at, read_at`

func scanItem(row pgx.Row) (api.Notification, error) {
	var n api.Notification
	var kind string
	var readAt *time.Time
	if err := row.Scan(&n.ID, &kind, &n.RepositoryID, &n.MergeRequestID, &n.ActorID, &n.HeadRevision, &n.OccurredAt, &readAt); err != nil {
		return api.Notification{}, err // ErrNoRows stays raw so callers can distinguish
	}
	n.Kind = api.Kind(kind)
	n.Read = readAt != nil
	return n, nil
}

func (s *Store) List(ctx context.Context, tenantID, recipientID string, pageSize int, pageToken string) (api.Page, error) {
	offset := 0
	if pageToken != "" {
		v, err := strconv.Atoi(pageToken)
		if err != nil || v < 0 {
			return api.Page{}, api.ErrDenied
		}
		offset = v
	}
	page := api.Page{}
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+itemColumns+` FROM notifications.items
			  WHERE tenant_id = $1 AND recipient_id = $2
			  ORDER BY occurred_at DESC, event_id ASC
			  LIMIT $3 OFFSET $4`,
			tenantID, recipientID, pageSize+1, offset)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			n, err := scanItem(rows)
			if err != nil {
				return err
			}
			page.Notifications = append(page.Notifications, n)
		}
		return rows.Err()
	})
	if err != nil {
		return api.Page{}, err
	}
	if len(page.Notifications) > pageSize {
		page.NextPageToken = strconv.Itoa(offset + pageSize)
		page.Notifications = page.Notifications[:pageSize]
	}
	return page, nil
}

func (s *Store) UnreadCount(ctx context.Context, tenantID, recipientID string) (int64, error) {
	var n int64
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM notifications.items
			  WHERE tenant_id = $1 AND recipient_id = $2 AND read_at IS NULL`,
			tenantID, recipientID).Scan(&n)
	})
	return n, err
}

func (s *Store) MarkRead(ctx context.Context, tenantID, recipientID, eventID string, readAt time.Time) (api.Notification, error) {
	var n api.Notification
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		n, err = scanItem(tx.QueryRow(ctx,
			`UPDATE notifications.items SET read_at = $4
			  WHERE tenant_id = $1 AND recipient_id = $2 AND event_id = $3 AND read_at IS NULL
			  RETURNING `+itemColumns,
			tenantID, recipientID, eventID, readAt))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		// Already read (the WHERE read_at IS NULL missed) or not the caller's
		// own row at all. Re-read so an idempotent second mark returns the row,
		// while a foreign one still refuses.
		return s.get(ctx, tenantID, recipientID, eventID)
	}
	if err != nil {
		return api.Notification{}, err
	}
	return n, nil
}

func (s *Store) get(ctx context.Context, tenantID, recipientID, eventID string) (api.Notification, error) {
	var n api.Notification
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		n, err = scanItem(tx.QueryRow(ctx,
			`SELECT `+itemColumns+` FROM notifications.items
			  WHERE tenant_id = $1 AND recipient_id = $2 AND event_id = $3`,
			tenantID, recipientID, eventID))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.Notification{}, api.ErrDenied
	}
	return n, err
}

func (s *Store) PutCreator(ctx context.Context, tenantID, repositoryID, mergeRequestID, creatorID string) error {
	return s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO notifications.mr_creators (tenant_id, repository_id, merge_request_id, creator_id)
			 VALUES ($1, $2, $3, $4)
			 ON CONFLICT (tenant_id, repository_id, merge_request_id) DO UPDATE SET creator_id = EXCLUDED.creator_id`,
			tenantID, repositoryID, mergeRequestID, creatorID)
		return err
	})
}

func (s *Store) Creator(ctx context.Context, tenantID, repositoryID, mergeRequestID string) (string, error) {
	var creator string
	err := s.pool.InTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT creator_id FROM notifications.mr_creators
			  WHERE tenant_id = $1 AND repository_id = $2 AND merge_request_id = $3`,
			tenantID, repositoryID, mergeRequestID).Scan(&creator)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return creator, err
}

var (
	_ app.Store        = (*Store)(nil)
	_ app.CreatorStore = (*Store)(nil)
)
