package tenantresource

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/dbconnector"
)

type TenantDBManager struct {
	mu         sync.RWMutex
	connectors map[uuid.UUID]*dbconnector.DBConnector
	config     dbconnector.Config
}

func NewTenantDBManager(config dbconnector.Config) *TenantDBManager {
	return &TenantDBManager{
		connectors: make(map[uuid.UUID]*dbconnector.DBConnector),
		config:     config,
	}
}

func (m *TenantDBManager) GetConnector(
	ctx context.Context,
	tenantID uuid.UUID,
	databaseURL string,
) (*dbconnector.DBConnector, error) {

	m.mu.RLock()
	connector, exists := m.connectors[tenantID]
	m.mu.RUnlock()

	if exists {
		return connector, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Another goroutine may have created it
	// while we were waiting for the write lock.
	if connector, exists := m.connectors[tenantID]; exists {
		return connector, nil
	}

	config := m.config
	config.DatabaseURL = databaseURL

	connector, err := dbconnector.New(ctx, config)
	if err != nil {
		return nil, fmt.Errorf(
			"create connector for tenant %s: %w",
			tenantID,
			err,
		)
	}

	m.connectors[tenantID] = connector

	return connector, nil
}
