package auth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"

	"github.com/vaultvision/go-auth-example/pkg/config"
)

type Manager struct {
	cfg *config.Config

	mu  sync.Mutex   // sync writes
	val atomic.Value // *oidc.Provider

	try  int
	last time.Time
}

func NewManager(cfg *config.Config) (*Manager, error) {
	if _, err := url.Parse(cfg.VVIssuerURL); err != nil {
		err := errors.New("pkg/auth/provider.NewManager: invalid VVIssuerURL")
		return nil, err
	}

	o := &Manager{
		cfg: cfg,
	}

	err := errors.New("pkg/auth/provider.NewManager: not initialized")
	o.down(err)
	return o, nil
}

func (o *Manager) String() string {
	return fmt.Sprintf("auth.Manager(%v)", o.cfg.VVClientID)
}

func (o *Manager) GetConfig() *config.Config {
	return o.cfg
}

func (o *Manager) Get() (*Provider, error) {
	val := o.load()
	if val.err != nil {
		return nil, val.err
	}
	return val, nil
}

func (o *Manager) Load(ctx context.Context) (*Provider, error) {
	if v := o.load(); v.err == nil {
		return v, nil
	}

	o.mu.Lock()
	defer o.mu.Unlock()
	v := o.load()
	if v.err != nil {
		return o.getAt(ctx, time.Now(), v.err)
	}
	return v, nil
}

func (o *Manager) down(err error)      { o.store(&Provider{err: err}) }
func (o *Manager) store(val *Provider) { o.val.Store(val) }
func (o *Manager) load() *Provider     { return o.val.Load().(*Provider) }

func (o *Manager) getAt(
	ctx context.Context,
	at time.Time,
	e error,
) (*Provider, error) {
	since := at.Sub(o.last)
	if time.Second > since {
		return nil, e
	}
	o.try++
	o.last = at

	val, err := NewProvider(ctx, o.cfg)
	if err != nil {
		o.down(err)
		return nil, err
	}

	o.try = 0
	o.store(val)
	return val, nil
}

type Provider struct {
	err error
	cfg *config.Config
	oa2 oauth2.Config
	pvr *oidc.Provider
	vfy *oidc.IDTokenVerifier
}

func NewProvider(ctx context.Context, cfg *config.Config) (*Provider, error) {
	o := &Provider{
		cfg: cfg,
	}
	if err := o.init(ctx); err != nil {
		return nil, fmt.Errorf("pkg/auth/provider.NewProvider: %w", err)
	}
	return o, nil
}

func (o *Provider) init(ctx context.Context) error {
	redir, err := url.JoinPath(o.cfg.BaseURL, "/auth/callback")
	if err != nil {
		return err
	}

	pvr, err := oidc.NewProvider(ctx, o.cfg.VVIssuerURL)
	if err != nil {
		return err
	}
	o.pvr = pvr

	o.oa2 = oauth2.Config{
		ClientID:     o.cfg.VVClientID,
		ClientSecret: o.cfg.VVClientSecret,
		RedirectURL:  redir,
		Endpoint:     pvr.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	o.vfy = pvr.Verifier(&oidc.Config{
		ClientID: o.cfg.VVClientID,
	})
	return nil
}

func (o *Provider) GetAuthCodeURL(
	ctx context.Context,
	state string,
	opts ...oauth2.AuthCodeOption,
) (string, error) {
	redir := o.oa2.AuthCodeURL(state, opts...)
	return redir, nil
}

func (o *Provider) Verify(
	ctx context.Context,
	rawIDToken string,
) (*oidc.IDToken, error) {
	return o.vfy.Verify(ctx, rawIDToken)
}

func (o *Provider) UserInfo(
	ctx context.Context,
	tokenSource oauth2.TokenSource,
) (*oidc.UserInfo, error) {
	return o.pvr.UserInfo(ctx, tokenSource)
}

func (o *Provider) Exchange(
	ctx context.Context,
	code string,
	opts ...oauth2.AuthCodeOption,
) (*oauth2.Token, error) {
	return o.oa2.Exchange(ctx, code, opts...)
}
