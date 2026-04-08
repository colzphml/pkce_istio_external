package app

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/colzphml/pkce_istio_external/internal/clock"
	"github.com/colzphml/pkce_istio_external/internal/config"
	"github.com/colzphml/pkce_istio_external/internal/extauth"
	"github.com/colzphml/pkce_istio_external/internal/httpserver"
	"github.com/colzphml/pkce_istio_external/internal/oidc"
	"github.com/colzphml/pkce_istio_external/internal/session"
	"github.com/colzphml/pkce_istio_external/internal/store"
	"github.com/colzphml/pkce_istio_external/internal/telemetry"
	"github.com/colzphml/pkce_istio_external/internal/version"
)

func Run(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	buildInfo := version.Current()
	logger.Info("starting oidc auth service", "version", buildInfo.Version, "commit", buildInfo.Commit, "build_date", buildInfo.BuildDate)

	metrics := telemetry.New()
	clk := clock.RealClock{}

	redisStore, err := store.NewRedisStore(cfg.Redis)
	if err != nil {
		return fmt.Errorf("create redis store: %w", err)
	}
	if err := redisStore.Ping(ctx); err != nil {
		return fmt.Errorf("ping redis: %w", err)
	}

	oidcClient, err := oidc.New(ctx, oidc.Config{
		IssuerURL:            cfg.OIDC.IssuerURL,
		ClientID:             cfg.OIDC.ClientID,
		ClientSecret:         cfg.OIDC.ClientSecret,
		Scopes:               cfg.OIDC.Scopes,
		HTTPTimeout:          cfg.OIDC.HTTPTimeout,
		ClockSkew:            cfg.OIDC.ClockSkew,
		AccessTokenAudiences: cfg.OIDC.AccessTokenAudiences,
	})
	if err != nil {
		return fmt.Errorf("create oidc client: %w", err)
	}

	manager := session.NewManager(cfg, redisStore, oidcClient, logger, clk, metrics)
	httpSrv := httpserver.New(cfg.Server.HTTPAddr, manager, cfg, logger, metrics, func() error {
		return redisStore.Ping(context.Background())
	})

	grpcSrv := grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 5 * time.Minute,
			Time:              30 * time.Second,
			Timeout:           10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	authv3.RegisterAuthorizationServer(grpcSrv, extauth.NewServer(manager, cfg, logger, metrics))

	httpListener, err := net.Listen("tcp", cfg.Server.HTTPAddr)
	if err != nil {
		return fmt.Errorf("listen http: %w", err)
	}
	grpcListener, err := net.Listen("tcp", cfg.Server.GRPCAddr)
	if err != nil {
		return fmt.Errorf("listen grpc: %w", err)
	}

	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		logger.Info("starting http server", "addr", cfg.Server.HTTPAddr)
		if err := httpSrv.HTTPServer().Serve(httpListener); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("serve http: %w", err)
		}
		return nil
	})
	group.Go(func() error {
		logger.Info("starting grpc server", "addr", cfg.Server.GRPCAddr)
		if err := grpcSrv.Serve(grpcListener); err != nil {
			return fmt.Errorf("serve grpc: %w", err)
		}
		return nil
	})
	group.Go(func() error {
		<-groupCtx.Done()

		stopCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
		defer cancel()

		grpcStopped := make(chan struct{})
		go func() {
			grpcSrv.GracefulStop()
			close(grpcStopped)
		}()

		select {
		case <-grpcStopped:
		case <-stopCtx.Done():
			grpcSrv.Stop()
		}

		if err := httpSrv.HTTPServer().Shutdown(stopCtx); err != nil {
			return fmt.Errorf("shutdown http server: %w", err)
		}

		return nil
	})

	if err := group.Wait(); err != nil && err != context.Canceled {
		return err
	}

	return nil
}
