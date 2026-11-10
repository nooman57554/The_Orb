package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nooman57554/The_Orb/orb_libs/dbconnector"
)

// Authorization event type constants for transactional outbox.
const (
	EventRoleCreated            = "role.created"
	EventRoleUpdated            = "role.updated"
	EventRoleDeleted            = "role.deleted"
	EventRolePermissionsChanged = "role.permissions_changed"
	EventPlatformRoleAssigned   = "platform_role.assigned"
	EventPlatformRoleRemoved    = "platform_role.removed"
	EventTenantRoleAssigned     = "tenant_role.assigned"
	EventTenantRoleRemoved      = "tenant_role.removed"
	EventUserStatusChanged      = "user_status.changed"
	EventTenantStatusChanged    = "tenant_status.changed"
)

// OutboxRecord represents an event stored in the authz_outbox table.
type OutboxRecord struct {
	ID            uuid.UUID       `json:"id"`
	EventType     string          `json:"event_type"`
	AggregateType string          `json:"aggregate_type"`
	AggregateID   string          `json:"aggregate_id"`
	Version       int64           `json:"version"`
	Payload       json.RawMessage `json:"payload"`
	CreatedAt     time.Time       `json:"created_at"`
	ProcessedAt   *time.Time      `json:"processed_at,omitempty"`
}

// OutboxRepository defines operations for the transactional outbox.
type OutboxRepository interface {
	WriteEvent(ctx context.Context, tx pgx.Tx, eventType, aggregateType, aggregateID string, payload any) (int64, error)
	ListUnprocessed(ctx context.Context, limit int) ([]OutboxRecord, error)
	MarkProcessed(ctx context.Context, ids []uuid.UUID) error
	GetLatestVersion(ctx context.Context) (int64, error)
}

// PostgresOutboxRepository implements OutboxRepository for PostgreSQL.
type PostgresOutboxRepository struct {
	db *dbconnector.DBConnector
}

func NewPostgresOutboxRepository(db *dbconnector.DBConnector) *PostgresOutboxRepository {
	return &PostgresOutboxRepository{db: db}
}

// WriteEvent writes an outbox record within the provided transaction and allocates a monotonic version.
func (r *PostgresOutboxRepository) WriteEvent(
	ctx context.Context,
	tx pgx.Tx,
	eventType, aggregateType, aggregateID string,
	payload any,
) (int64, error) {
	if tx == nil {
		return 0, fmt.Errorf("transaction is required for transactional outbox write")
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("marshal outbox payload: %w", err)
	}

	var version int64
	err = tx.QueryRow(ctx, "SELECT nextval('authz_version_seq')").Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("nextval authz_version_seq: %w", err)
	}

	eventID, err := uuid.NewV7()
	if err != nil {
		return 0, fmt.Errorf("generate outbox event id: %w", err)
	}

	const query = `
		INSERT INTO authz_outbox (id, event_type, aggregate_type, aggregate_id, version, payload, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
	`
	_, err = tx.Exec(ctx, query, eventID, eventType, aggregateType, aggregateID, version, payloadBytes)
	if err != nil {
		return 0, fmt.Errorf("insert authz_outbox: %w", err)
	}

	return version, nil
}

// ListUnprocessed returns unprocessed outbox events ordered by creation time.
func (r *PostgresOutboxRepository) ListUnprocessed(ctx context.Context, limit int) ([]OutboxRecord, error) {
	if limit <= 0 {
		limit = 100
	}

	const query = `
		SELECT id, event_type, aggregate_type, aggregate_id, version, payload, created_at, processed_at
		FROM authz_outbox
		WHERE processed_at IS NULL
		ORDER BY version ASC
		LIMIT $1
	`
	rows, err := r.db.Pool().Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("list unprocessed outbox events: %w", err)
	}
	defer rows.Close()

	records := make([]OutboxRecord, 0)
	for rows.Next() {
		var rec OutboxRecord
		if err := rows.Scan(
			&rec.ID,
			&rec.EventType,
			&rec.AggregateType,
			&rec.AggregateID,
			&rec.Version,
			&rec.Payload,
			&rec.CreatedAt,
			&rec.ProcessedAt,
		); err != nil {
			return nil, fmt.Errorf("scan outbox record: %w", err)
		}
		records = append(records, rec)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return records, nil
}

// MarkProcessed marks the specified outbox records as processed.
func (r *PostgresOutboxRepository) MarkProcessed(ctx context.Context, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}

	const query = `
		UPDATE authz_outbox
		SET processed_at = NOW()
		WHERE id = ANY($1)
	`
	_, err := r.db.Pool().Exec(ctx, query, ids)
	if err != nil {
		return fmt.Errorf("mark outbox processed: %w", err)
	}
	return nil
}

// GetLatestVersion returns the current version sequence value.
func (r *PostgresOutboxRepository) GetLatestVersion(ctx context.Context) (int64, error) {
	var version int64
	err := r.db.Pool().QueryRow(ctx, "SELECT COALESCE(MAX(version), 1) FROM authz_outbox").Scan(&version)
	if err != nil {
		return 1, fmt.Errorf("get latest outbox version: %w", err)
	}
	return version, nil
}
