package management

import (
	"context"
	"sync"

	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

type memoryAuthStore struct {
	mu    sync.Mutex
	items map[string]*coreauth.Auth
}

func (s *memoryAuthStore) List(ctx context.Context) ([]*coreauth.Auth, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*coreauth.Auth, 0, len(s.items))
	for _, auth := range s.items {
		out = append(out, auth.Clone())
	}
	return out, nil
}

func (s *memoryAuthStore) Save(ctx context.Context, auth *coreauth.Auth) (string, error) {
	_ = ctx
	if auth == nil {
		return "", nil
	}
	s.mu.Lock()
	if s.items == nil {
		s.items = make(map[string]*coreauth.Auth)
	}
	s.items[auth.ID] = auth.Clone()
	s.mu.Unlock()
	return auth.ID, nil
}

func (s *memoryAuthStore) Delete(ctx context.Context, id string) error {
	_ = ctx
	s.mu.Lock()
	delete(s.items, id)
	s.mu.Unlock()
	return nil
}
