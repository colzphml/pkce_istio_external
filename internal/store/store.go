package store

import (
	"context"
	"errors"
	"time"

	"github.com/colzphml/pkce_istio_external/internal/model"
)

var ErrNotFound = errors.New("not found")

type Store interface {
	Ping(context.Context) error
	SaveLoginState(context.Context, model.LoginState, time.Duration) error
	ConsumeLoginState(context.Context, string) (*model.LoginState, error)
	SaveSession(context.Context, model.Session, time.Duration) error
	GetSession(context.Context, string) (*model.Session, error)
	DeleteSession(context.Context, string) error
	DeleteSessionsByKCSessionID(context.Context, string) (int, error)
	AcquireRefreshLock(context.Context, string, string, time.Duration) (bool, error)
	ReleaseRefreshLock(context.Context, string, string) error
}
