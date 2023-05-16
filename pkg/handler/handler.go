package handler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"

	"github.com/vaultvision/go-auth-example/pkg/auth"
	"github.com/vaultvision/go-auth-example/pkg/config"
	"github.com/vaultvision/go-auth-example/pkg/session"
	"github.com/vaultvision/go-auth-example/pkg/templates"
	"github.com/vaultvision/go-auth-example/pkg/utils"
)

type Handler struct {
	cfg  *config.Config
	base *url.URL

	authMng *auth.Manager
	sessMng *session.Manager
	tpl     *template.Template
	mux     *http.ServeMux
}

func New(ctx context.Context, cfg *config.Config) (*Handler, error) {
	httpMux := http.NewServeMux()
	o := &Handler{
		cfg: cfg,
		mux: httpMux,
	}
	if err := o.init(ctx); err != nil {
		return nil, fmt.Errorf("pkg/handler.New: %w", err)
	}
	return o, nil
}

func (o *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if loginCookie, err := r.Cookie("authsess"); err == nil {
		jwt := loginCookie.Value
		sess := new(session.Session)
		if err := o.sessMng.Open(r.Context(), jwt, sess); err == nil {
			r = r.WithContext(session.Put(r.Context(), sess))
		}
	}

	log.Printf("pkg/handler.ServeHTTP - %v %v", r.Method, r.URL)
	o.mux.ServeHTTP(w, r)
}

func (o *Handler) init(ctx context.Context) error {
	sessMng, err := session.New(o.cfg)
	if err != nil {
		return err
	}
	o.sessMng = sessMng

	authMng, err := auth.NewManager(o.cfg)
	if err != nil {
		return err
	}
	o.authMng = authMng

	baseURL, err := url.Parse(o.cfg.BaseURL)
	if err != nil {
		return err
	}
	o.base = baseURL

	tpl, err := templates.New()
	if err != nil {
		return err
	}
	o.tpl = tpl

	// app routes
	o.mux.Handle("/", Func(o.getIndex))
	o.mux.Handle("/login", Func(o.getLogin))
	o.mux.Handle("/auth/login", Func(o.getAuthLogin))
	o.mux.Handle("/auth/callback", Func(o.getAuthCallback))
	o.mux.Handle("/logout", Func(o.getLogout))
	o.mux.Handle("/auth/logout", Func(o.getAuthLogout))
	o.mux.Handle("/settings", Func(o.getSettings))
	o.mux.Handle("/auth/settings", Func(o.getAuthSettings))

	// static route
	staticFs := http.FS(os.DirFS(o.cfg.StaticDir))
	staticHr := http.StripPrefix("/static/", http.FileServer(staticFs))
	o.mux.Handle("/static/", staticHr)
	return nil
}

func (o *Handler) getIndex(w http.ResponseWriter, r *http.Request) error {
	if r.URL.Path != "/" {
		return newError(http.StatusNotFound, "")
	}
	if r.Method != "GET" {
		return newError(http.StatusMethodNotAllowed, "")
	}

	oidc := templates.Data{
		"issuer_url": o.cfg.VVIssuerURL,
	}
	if _, err := o.authMng.Load(context.Background()); err != nil {
		oidc["error"] = err.Error()
	}

	data := templates.Data{
		"oidc": oidc,
	}
	if sess, ok := session.Get(r.Context()); ok {
		data["user"] = sess.UserInfo

		b, err := json.MarshalIndent(sess.UserInfo, "", "  ")
		if err == nil {
			data["user_json"] = string(b)
		}
	}

	if err := o.tpl.Execute(w, data); err != nil {
		return err
	}
	return nil
}

// /settings just redirects to /auth/settings. But it could contain any app
// specific logic or a confirmation page that shows a settings button.
func (o *Handler) getSettings(w http.ResponseWriter, r *http.Request) error {
	if r.Method != "GET" {
		return newError(http.StatusMethodNotAllowed, "")
	}

	http.Redirect(w, r, "/auth/settings", http.StatusFound)
	return nil
}

// /auth/settings redirects to the Vault Vision settings page so users can
// manage their email, password, social logins, webauthn credentials and more.
//
// This works by using an oidc prompt named "settings". When the user returns
// your session will be updated to reflect any changes they made.
func (o *Handler) getAuthSettings(w http.ResponseWriter, r *http.Request) error {
	return o.getAuthLoginOpts(w, r,
		oauth2.SetAuthURLParam("prompt", "settings"))
}

// /login just redirects to /auth/login. But it could contain any app specific
// logic or a confirmation page that shows a login button.
func (o *Handler) getLogin(w http.ResponseWriter, r *http.Request) error {
	if r.Method != "GET" {
		return newError(http.StatusMethodNotAllowed, "")
	}

	http.Redirect(w, r, "/auth/login", http.StatusFound)
	return nil
}

// /auth/login kicks off the OIDC flow by redirecting to Vault Vision. Once
// authentication is complete the user will be returned to /auth/callback.
func (o *Handler) getAuthLogin(w http.ResponseWriter, r *http.Request) error {
	return o.getAuthLoginOpts(w, r)
}

func (o *Handler) getAuthLoginOpts(
	w http.ResponseWriter,
	r *http.Request,
	authCodeOpts ...oauth2.AuthCodeOption,
) error {
	if r.Method != "GET" {
		return newError(http.StatusMethodNotAllowed, "")
	}

	ctx := r.Context()
	pvr, err := o.authMng.Load(context.Background())
	if err != nil {
		return err
	}

	state, err := utils.RandString(16)
	if err != nil {
		return err
	}

	nonce, err := utils.RandString(16)
	if err != nil {
		return err
	}

	pkceCode, err := utils.RandString(16)
	if err != nil {
		return err
	}

	setCookie(w, r, "state", state, 3600)
	setCookie(w, r, "nonce", nonce, 3600)
	setCookie(w, r, "pkce_code", pkceCode, 3600)

	h := sha256.New()
	h.Write([]byte(pkceCode))
	pkceChallengeS256 := h.Sum(nil)
	pkceChallenge := base64.RawURLEncoding.EncodeToString(pkceChallengeS256)

	opts := []oauth2.AuthCodeOption{
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", pkceChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	opts = append(opts, authCodeOpts...)

	redir, err := pvr.GetAuthCodeURL(ctx, state, opts...)
	if err != nil {
		return err
	}

	http.Redirect(w, r, redir, http.StatusFound)
	return nil
}

// Once Vault Vision authenticates a user they will be sent here to complete
// the OIDC flow.
func (o *Handler) getAuthCallback(
	w http.ResponseWriter,
	r *http.Request,
) error {
	ctx := r.Context()
	pvr, err := o.authMng.Load(context.Background())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return nil
	}

	stateCookie, err := r.Cookie("state")
	if err != nil {
		http.Error(w, "state not found", http.StatusBadRequest)
		return nil
	}

	reqState := r.URL.Query().Get("state")
	if a, b := reqState, stateCookie.Value; a != b || a == "" || b == "" {
		http.Error(w, "state did not match", http.StatusBadRequest)
		return nil
	}

	codeChalCookie, err := r.Cookie("pkce_code")
	if err != nil {
		http.Error(w, "state not found", http.StatusBadRequest)
		return nil
	}

	oauth2Token, err := pvr.Exchange(ctx,
		r.URL.Query().Get("code"),
		oauth2.SetAuthURLParam("code_verifier", codeChalCookie.Value),
	)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return nil
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return nil
	}

	idToken, err := pvr.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return nil
	}

	nonceCookie, err := r.Cookie("nonce")
	if err != nil {
		http.Error(w, "Nonce not found", http.StatusBadRequest)
		return nil
	}
	if a, b := idToken.Nonce, nonceCookie.Value; a != b || a == "" || b == "" {
		http.Error(w, "Nonce did not match", http.StatusBadRequest)
		return nil
	}

	var idClaims map[string]interface{}
	if err := idToken.Claims(&idClaims); err != nil {
		http.Error(w, "Failed to get id token claims: "+err.Error(),
			http.StatusInternalServerError)
		return nil
	}

	userInfo, err := pvr.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
	if err != nil {
		http.Error(w, "Failed to get userinfo: "+err.Error(),
			http.StatusInternalServerError)
		return nil
	}

	var infoClaims map[string]interface{}
	if err := userInfo.Claims(&infoClaims); err != nil {
		http.Error(w, "Failed to get user info claims: "+err.Error(),
			http.StatusInternalServerError)
		return nil
	}

	sess := &session.Session{
		UserInfo:   infoClaims,
		LoggedIn:   true,
		LoggedInAt: time.Now(),
	}

	jwt, err := o.sessMng.Create(ctx, sess)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil
	}
	setCookie(w, r, "authsess", jwt, 0)

	http.Redirect(w, r, "/", http.StatusFound)
	return nil
}

// Logout clears the cookies and then sends the users to Vault Vision to clear
// the session, then Vault Vision will redirect the user to /auth/logout.
func (o *Handler) getLogout(w http.ResponseWriter, r *http.Request) error {
	if r.Method != "GET" {
		return newError(http.StatusMethodNotAllowed, "")
	}
	o.clearSess(w, r)

	returnTo, err := url.JoinPath(o.cfg.BaseURL, "/auth/logout")
	if err != nil {
		return newError(http.StatusInternalServerError, err.Error())
	}

	q := make(url.Values)
	q.Add("client_id", o.cfg.VVClientID)
	q.Add("return_to", returnTo)

	redirURL, err := url.Parse(o.cfg.VVIssuerURL)
	if err != nil {
		return newError(http.StatusInternalServerError, err.Error())
	}
	redirURL.Path = "/logout"
	redirURL.RawQuery = q.Encode()

	redir := redirURL.String()
	http.Redirect(w, r, redir, http.StatusFound)
	return nil
}

// Once Vault Vision clears the users session, they return to this route.
func (o *Handler) getAuthLogout(w http.ResponseWriter, r *http.Request) error {
	if r.Method != "GET" {
		return newError(http.StatusMethodNotAllowed, "")
	}
	o.clearSess(w, r)

	http.Redirect(w, r, "/", http.StatusFound)
	return nil
}

func (o *Handler) clearSess(w http.ResponseWriter, r *http.Request) {
	setCookie(w, r, "authsess", "", -1)
	setCookie(w, r, "state", "", -1)
	setCookie(w, r, "nonce", "", -1)
	setCookie(w, r, "login", "", -1)
	setCookie(w, r, "pkce_code", "", -1)
}

type httpError struct {
	code int
	text string
}

func newError(code int, text string) error {
	return &httpError{code: code, text: text}
}

func (o *httpError) GetCode() int { return o.code }
func (o *httpError) Error() string {
	code := o.code
	text := o.text
	if text == "" {
		text = http.StatusText(o.code)
	}
	return fmt.Sprintf("%d: %v", code, text)
}

// Func is an http.Handler that returns an error.
type Func func(w http.ResponseWriter, r *http.Request) error

// ServeHTTP implements http.Handler.
func (f Func) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := f(w, r)
	if err == nil {
		return
	}

	code := http.StatusBadRequest
	if v, ok := err.(interface{ GetCode() int }); ok {
		code = v.GetCode()
	}

	text := http.StatusText(code)
	http.Error(w, text, code)
}

func setCookie(
	w http.ResponseWriter,
	r *http.Request,
	name, value string,
	maxAge int,
) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   maxAge,
		Path:     "/",
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}
