package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/colzphml/pkce_istio_external/internal/config"
	"github.com/colzphml/pkce_istio_external/internal/model"
	"github.com/redis/go-redis/v9"
)

var releaseLockScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("DEL", KEYS[1])
end
return 0
`)

type RedisStore struct {
	client    redis.UniversalClient
	keyPrefix string
}

func NewRedisStore(cfg config.RedisConfig) (*RedisStore, error) {
	tlsCfg, err := cfg.TLSConfig()
	if err != nil {
		return nil, err
	}

	universalOptions := &redis.UniversalOptions{
		Addrs:            cfg.Addresses,
		DB:               cfg.DB,
		Username:         cfg.Username,
		Password:         cfg.Password,
		MasterName:       cfg.MasterName,
		SentinelUsername: cfg.SentinelUsername,
		SentinelPassword: cfg.SentinelPassword,
		DialTimeout:      cfg.DialTimeout,
		ReadTimeout:      cfg.ReadTimeout,
		WriteTimeout:     cfg.WriteTimeout,
		PoolSize:         cfg.PoolSize,
		MinIdleConns:     cfg.MinIdleConns,
		TLSConfig:        tlsCfg,
	}

	if cfg.Mode != "sentinel" {
		universalOptions.MasterName = ""
		universalOptions.SentinelUsername = ""
		universalOptions.SentinelPassword = ""
	}

	return &RedisStore{
		client:    redis.NewUniversalClient(universalOptions),
		keyPrefix: cfg.KeyPrefix,
	}, nil
}

func (s *RedisStore) Ping(ctx context.Context) error {
	return s.client.Ping(ctx).Err()
}

func (s *RedisStore) SaveLoginState(ctx context.Context, state model.LoginState, ttl time.Duration) error {
	payload, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal login state: %w", err)
	}
	return s.client.Set(ctx, s.loginStateKey(state.State), payload, ttl).Err()
}

func (s *RedisStore) ConsumeLoginState(ctx context.Context, key string) (*model.LoginState, error) {
	raw, err := s.client.GetDel(ctx, s.loginStateKey(key)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("getdel login state: %w", err)
	}

	var out model.LoginState
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("unmarshal login state: %w", err)
	}
	return &out, nil
}

func (s *RedisStore) SaveSession(ctx context.Context, sess model.Session, ttl time.Duration) error {
	payload, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	pipe := s.client.TxPipeline()
	pipe.Set(ctx, s.sessionKey(sess.ID), payload, ttl)
	if sess.KCSessionID != "" {
		pipe.SAdd(ctx, s.kcSessionKey(sess.KCSessionID), sess.ID)
		pipe.Expire(ctx, s.kcSessionKey(sess.KCSessionID), ttl)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("save session: %w", err)
	}
	return nil
}

func (s *RedisStore) GetSession(ctx context.Context, id string) (*model.Session, error) {
	raw, err := s.client.Get(ctx, s.sessionKey(id)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get session: %w", err)
	}

	var out model.Session
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}
	return &out, nil
}

func (s *RedisStore) DeleteSession(ctx context.Context, id string) error {
	sess, err := s.GetSession(ctx, id)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	pipe := s.client.TxPipeline()
	pipe.Del(ctx, s.sessionKey(id))
	if sess != nil && sess.KCSessionID != "" {
		pipe.SRem(ctx, s.kcSessionKey(sess.KCSessionID), id)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (s *RedisStore) DeleteSessionsByKCSessionID(ctx context.Context, kcSessionID string) (int, error) {
	if kcSessionID == "" {
		return 0, nil
	}

	memberIDs, err := s.client.SMembers(ctx, s.kcSessionKey(kcSessionID)).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return 0, fmt.Errorf("get kc session members: %w", err)
	}
	if len(memberIDs) == 0 {
		if err := s.client.Del(ctx, s.kcSessionKey(kcSessionID)).Err(); err != nil {
			return 0, fmt.Errorf("delete empty kc session index: %w", err)
		}
		return 0, nil
	}

	keys := make([]string, 0, len(memberIDs)+1)
	for _, memberID := range memberIDs {
		keys = append(keys, s.sessionKey(memberID))
	}
	keys = append(keys, s.kcSessionKey(kcSessionID))
	if err := s.client.Del(ctx, keys...).Err(); err != nil {
		return 0, fmt.Errorf("delete kc sessions: %w", err)
	}
	return len(memberIDs), nil
}

func (s *RedisStore) AcquireRefreshLock(ctx context.Context, sessionID, owner string, ttl time.Duration) (bool, error) {
	ok, err := s.client.SetNX(ctx, s.refreshLockKey(sessionID), owner, ttl).Result()
	if err != nil {
		return false, fmt.Errorf("acquire refresh lock: %w", err)
	}
	return ok, nil
}

func (s *RedisStore) ReleaseRefreshLock(ctx context.Context, sessionID, owner string) error {
	if _, err := releaseLockScript.Run(ctx, s.client, []string{s.refreshLockKey(sessionID)}, owner).Result(); err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("release refresh lock: %w", err)
	}
	return nil
}

func (s *RedisStore) loginStateKey(state string) string {
	return s.keyPrefix + "state:" + state
}

func (s *RedisStore) sessionKey(id string) string {
	return s.keyPrefix + "session:" + id
}

func (s *RedisStore) kcSessionKey(id string) string {
	return s.keyPrefix + "kc-session:" + id
}

func (s *RedisStore) refreshLockKey(id string) string {
	return s.keyPrefix + "lock:refresh:" + id
}
