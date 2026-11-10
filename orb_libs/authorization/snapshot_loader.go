package authorization

import "context"

// SnapshotSource defines the methods required by the authorization runtime
// to check the authoritative policy version and load a complete, consistent policy snapshot.
type SnapshotSource interface {
	GetLatestVersion(ctx context.Context) (int64, error)
	LoadSnapshot(ctx context.Context) (*PolicySnapshot, error)
}
