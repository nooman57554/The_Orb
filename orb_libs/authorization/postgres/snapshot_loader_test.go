package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nooman57554/The_Orb/orb_libs/authorization"
)

// mockRow implements pgx.Row
type mockRow struct {
	scanFunc func(dest ...any) error
}

func (r *mockRow) Scan(dest ...any) error {
	if r.scanFunc != nil {
		return r.scanFunc(dest...)
	}
	return nil
}

// mockDB implements DB interface for testing error handling and transaction options.
type mockDB struct {
	queryRowFunc func(ctx context.Context, sql string, args ...any) pgx.Row
	beginTxFunc  func(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error)
}

func (m *mockDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if m.queryRowFunc != nil {
		return m.queryRowFunc(ctx, sql, args...)
	}
	return &mockRow{}
}

func (m *mockDB) BeginTx(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error) {
	if m.beginTxFunc != nil {
		return m.beginTxFunc(ctx, txOptions)
	}
	return nil, errors.New("not implemented")
}

func TestSnapshotLoader_GetLatestVersion(t *testing.T) {
	ctx := context.Background()

	// 1. Successful version query
	dbSuccess := &mockDB{
		queryRowFunc: func(ctx context.Context, sql string, args ...any) pgx.Row {
			return &mockRow{
				scanFunc: func(dest ...any) error {
					if len(dest) > 0 {
						if p, ok := dest[0].(*int64); ok {
							*p = 42
						}
					}
					return nil
				},
			}
		},
	}
	loaderSuccess := NewSnapshotLoader(dbSuccess)
	v, err := loaderSuccess.GetLatestVersion(ctx)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if v != 42 {
		t.Fatalf("expected version 42, got %d", v)
	}

	// 2. Query error must be propagated, never silently substituted
	dbError := &mockDB{
		queryRowFunc: func(ctx context.Context, sql string, args ...any) pgx.Row {
			return &mockRow{
				scanFunc: func(dest ...any) error {
					return errors.New("connection reset by peer")
				},
			}
		},
	}
	loaderError := NewSnapshotLoader(dbError)
	_, err = loaderError.GetLatestVersion(ctx)
	if err == nil {
		t.Fatalf("expected error from GetLatestVersion when query fails, got nil")
	}
}

func TestSnapshotLoader_LoadSnapshot_BeginTxFailure(t *testing.T) {
	ctx := context.Background()

	expectedErr := errors.New("pool exhausted")
	db := &mockDB{
		beginTxFunc: func(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error) {
			if txOptions.IsoLevel != pgx.RepeatableRead {
				t.Errorf("expected RepeatableRead isolation, got %v", txOptions.IsoLevel)
			}
			if txOptions.AccessMode != pgx.ReadOnly {
				t.Errorf("expected ReadOnly access mode, got %v", txOptions.AccessMode)
			}
			return nil, expectedErr
		},
	}

	loader := NewSnapshotLoader(db)
	_, err := loader.LoadSnapshot(ctx)
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected %v, got %v", expectedErr, err)
	}
}

// mockTx implements pgx.Tx for transaction testing
type mockTx struct {
	queryRowFunc func(ctx context.Context, sql string, args ...any) pgx.Row
	queryFunc    func(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	rolledBack   bool
}

func (m *mockTx) Begin(ctx context.Context) (pgx.Tx, error) { return nil, nil }
func (m *mockTx) Commit(ctx context.Context) error          { return nil }
func (m *mockTx) Rollback(ctx context.Context) error {
	m.rolledBack = true
	return nil
}
func (m *mockTx) CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error) {
	return 0, nil
}
func (m *mockTx) SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults { return nil }
func (m *mockTx) LargeObjects() pgx.LargeObjects                               { return pgx.LargeObjects{} }
func (m *mockTx) Prepare(ctx context.Context, name, sql string) (*pgconn.StatementDescription, error) {
	return nil, nil
}
func (m *mockTx) Exec(ctx context.Context, sql string, arguments ...any) (commandTag pgconn.CommandTag, err error) {
	return pgconn.CommandTag{}, nil
}
func (m *mockTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if m.queryFunc != nil {
		return m.queryFunc(ctx, sql, args...)
	}
	return nil, errors.New("unimplemented query")
}
func (m *mockTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	if m.queryRowFunc != nil {
		return m.queryRowFunc(ctx, sql, args...)
	}
	return &mockRow{}
}
func (m *mockTx) Conn() *pgx.Conn { return nil }

func TestSnapshotLoader_LoadSnapshot_VersionQueryFailureRollback(t *testing.T) {
	ctx := context.Background()

	tx := &mockTx{
		queryRowFunc: func(ctx context.Context, sql string, args ...any) pgx.Row {
			return &mockRow{
				scanFunc: func(dest ...any) error {
					return errors.New("syntax error")
				},
			}
		},
	}

	db := &mockDB{
		beginTxFunc: func(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error) {
			return tx, nil
		},
	}

	loader := NewSnapshotLoader(db)
	_, err := loader.LoadSnapshot(ctx)
	if err == nil {
		t.Fatalf("expected error from LoadSnapshot when version query fails")
	}
	if !tx.rolledBack {
		t.Fatalf("expected transaction to be rolled back on error")
	}
}

// Compile-time check that SnapshotLoader implements authorization.SnapshotSource
var _ authorization.SnapshotSource = (*SnapshotLoader)(nil)
