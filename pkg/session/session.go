package session

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	"golang.org/x/crypto/pbkdf2"
	"gopkg.in/square/go-jose.v2"

	"github.com/vaultvision/go-auth-example/pkg/config"
)

type Session struct {
	LoggedIn   bool
	LoggedInAt time.Time
	UserInfo   map[string]interface{}
}

type sessionKey struct{}

func Get(ctx context.Context) (*Session, bool) {
	if v, ok := ctx.Value(sessionKey{}).(*Session); ok {
		return v, true
	}
	return nil, false
}

func Put(ctx context.Context, v *Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, v)
}

type Manager struct {
	key []byte
	enc jose.Encrypter
}

func New(cfg *config.Config) (*Manager, error) {
	salt := []byte("go-auth-example")
	pass := []byte(cfg.SessionSecret)

	key := pbkdf2.Key(salt, pass, 4096, 32, sha256.New)
	enc, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{
			Algorithm: jose.A128GCMKW,
			Key:       key,
		},
		nil,
	)
	if err != nil {
		return nil, err
	}

	o := &Manager{
		key: key,
		enc: enc,
	}
	return o, nil
}

func (o *Manager) Create(ctx context.Context, data interface{}) (string, error) {
	plain, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return o.CreateBytes(ctx, plain)
}

func (o *Manager) CreateBytes(ctx context.Context, plain []byte) (string, error) {
	object, err := o.enc.Encrypt(plain)
	if err != nil {
		return "", err
	}

	compact, err := object.CompactSerialize()
	if err != nil {
		return "", err
	}
	return compact, nil
}

func (o *Manager) Open(ctx context.Context, jwt string, dst interface{}) error {
	plain, err := o.OpenBytes(ctx, jwt)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(plain, dst); err != nil {
		return err
	}
	return nil
}

func (o *Manager) OpenBytes(ctx context.Context, jwt string) ([]byte, error) {
	object, err := jose.ParseEncrypted(jwt)
	if err != nil {
		return nil, err
	}

	plain, err := object.Decrypt(o.key)
	if err != nil {
		return nil, err
	}
	return plain, nil
}
