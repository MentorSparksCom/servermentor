package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

const (
	defaultSessionCookieName = "servermentor_session"
	stateCookiePrefix        = "servermentor_auth_state_"
	defaultSessionTTL        = 8 * time.Hour
	defaultStateTTL          = 10 * time.Minute
	defaultGitHubUserURL     = "https://api.github.com/user"
	defaultGitHubEmailsURL   = "https://api.github.com/user/emails"
	defaultGitHubOrgsURL     = "https://api.github.com/user/orgs"
	defaultGitHubTeamsURL    = "https://api.github.com/user/teams"
)

type Identity struct {
	Provider       string   `json:"provider"`
	Subject        string   `json:"subject"`
	ProviderUserID string   `json:"providerUserId,omitempty"`
	Email          string   `json:"email,omitempty"`
	DisplayName    string   `json:"displayName,omitempty"`
	Groups         []string `json:"groups,omitempty"`
	Organizations  []string `json:"organizations,omitempty"`
	Teams          []string `json:"teams,omitempty"`
}

type authSession struct {
	Identity  Identity  `json:"identity"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type authState struct {
	ProviderID string    `json:"providerId"`
	Value      string    `json:"value"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

type LoginProvider struct {
	ID       string
	Name     string
	LoginURL string
}

type AuthProvider interface {
	ID() string
	DisplayName() string
	AuthCodeURL(state string) string
	ExchangeIdentity(ctx context.Context, code string) (*Identity, error)
}

type AuthManager struct {
	codec             *sealedCookieCodec
	sessionCookieName string
	cookieDomain      string
	sessionTTL        time.Duration
	secureCookies     bool
	authDisabled      bool
	proxyAuth         *ProxyAuthConfig
	providers         map[string]AuthProvider
	providerOrder     []string
	authorizer        Authorizer
}

type ProxyAuthConfig struct {
	proxyOnly           bool
	displayName         string
	trustAll            bool
	trustedProxies      []netip.Prefix
	subjectHeaders      []string
	emailHeaders        []string
	nameHeaders         []string
	groupsHeaders       []string
	organizationHeaders []string
	teamHeaders         []string
}

type Authorizer struct {
	adminEmails        map[string]struct{}
	adminGroups        map[string]struct{}
	requiredDomain     string
	githubAllowedOrgs  map[string]struct{}
	githubAllowedTeams map[string]struct{}
	allowAnyUser       bool
}

type sealedCookieCodec struct {
	gcm cipher.AEAD
}

type oauthUserInfoProvider struct {
	id           string
	displayName  string
	oauthConfig  *oauth2.Config
	userInfoURL  string
	emailClaim   string
	nameClaim    string
	subjectClaim string
	groupsClaim  string
}

type gitHubProvider struct {
	displayName  string
	oauthConfig  *oauth2.Config
	loadOrgs     bool
	loadTeams    bool
	apiUserURL   string
	apiEmailsURL string
	apiOrgsURL   string
	apiTeamsURL  string
	providerID   string
}

type gitHubUser struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type gitHubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

type gitHubOrg struct {
	Login string `json:"login"`
}

type gitHubTeam struct {
	Slug string `json:"slug"`
	Org  struct {
		Login string `json:"login"`
	} `json:"organization"`
}

func NewAuthManagerFromEnv() (*AuthManager, error) {
	authMode := strings.ToLower(strings.TrimSpace(os.Getenv("AUTH_MODE")))
	if authMode == "disabled" {
		if !envBool("ALLOW_INSECURE_NO_AUTH", false) {
			return nil, errors.New("AUTH_MODE=disabled requires ALLOW_INSECURE_NO_AUTH=true")
		}

		codec, err := newSealedCookieCodec(loadSessionSecret())
		if err != nil {
			return nil, err
		}

		return &AuthManager{
			codec:             codec,
			sessionCookieName: firstNonEmpty(os.Getenv("AUTH_SESSION_COOKIE_NAME"), defaultSessionCookieName),
			cookieDomain:      strings.TrimSpace(os.Getenv("AUTH_COOKIE_DOMAIN")),
			sessionTTL:        parseDurationEnv("AUTH_SESSION_TTL", defaultSessionTTL),
			secureCookies:     envBool("AUTH_SECURE_COOKIES", false),
			authDisabled:      true,
			providers:         map[string]AuthProvider{},
			providerOrder:     nil,
			authorizer:        loadAuthorizerFromEnv(),
		}, nil
	}

	authorizer := loadAuthorizerFromEnv()
	configuredIDs := configuredProviderIDs()
	proxyConfigured := authMode == "proxy" || envBool("AUTH_PROXY_ENABLED", false)
	providerIDs := make([]string, 0, len(configuredIDs))
	for _, providerID := range configuredIDs {
		if providerID == "proxy" {
			proxyConfigured = true
			continue
		}
		providerIDs = append(providerIDs, providerID)
	}
	if authMode == "proxy" {
		providerIDs = nil
	}

	proxyAuth, err := loadProxyAuthFromEnv(proxyConfigured, authMode == "proxy")
	if err != nil {
		return nil, err
	}

	providers := make(map[string]AuthProvider, len(providerIDs))
	providerOrder := make([]string, 0, len(providerIDs))

	for _, providerID := range providerIDs {
		if _, exists := providers[providerID]; exists {
			continue
		}

		provider, err := buildProviderFromEnv(providerID, authorizer)
		if err != nil {
			return nil, err
		}
		providers[providerID] = provider
		providerOrder = append(providerOrder, providerID)
	}

	codec, err := newSealedCookieCodec(loadSessionSecret())
	if err != nil {
		return nil, err
	}

	if len(providers) == 0 && proxyAuth == nil {
		log.Println("Authentication is not configured: no auth providers enabled")
	}

	return &AuthManager{
		codec:             codec,
		sessionCookieName: firstNonEmpty(os.Getenv("AUTH_SESSION_COOKIE_NAME"), defaultSessionCookieName),
		cookieDomain:      strings.TrimSpace(os.Getenv("AUTH_COOKIE_DOMAIN")),
		sessionTTL:        parseDurationEnv("AUTH_SESSION_TTL", defaultSessionTTL),
		secureCookies:     envBool("AUTH_SECURE_COOKIES", false),
		proxyAuth:         proxyAuth,
		providers:         providers,
		providerOrder:     providerOrder,
		authorizer:        authorizer,
	}, nil
}

func (m *AuthManager) ShowLogin(c *gin.Context) {
	if m == nil {
		c.String(http.StatusInternalServerError, "Authentication is unavailable")
		return
	}

	if m.authDisabled {
		c.Redirect(http.StatusFound, "/admin")
		return
	}

	if identity, statusCode, _ := m.authenticateProxyRequest(c); identity != nil && statusCode == 0 {
		if m.authorizer.Authorize(*identity) {
			c.Redirect(http.StatusFound, "/admin")
			return
		}
	}

	if sessionCookie, err := c.Cookie(m.sessionCookieName); err == nil {
		var session authSession
		if err := m.codec.Decode(sessionCookie, &session); err == nil && time.Now().Before(session.ExpiresAt) {
			if m.authorizer.Authorize(session.Identity) {
				c.Redirect(http.StatusFound, "/admin")
				return
			}
		}
	}

	providers := m.LoginProviders()
	authURL := ""
	if len(providers) > 0 {
		authURL = providers[0].LoginURL
	}

	message := ""
	if m.proxyAuth != nil && len(m.providerOrder) == 0 {
		message = "Authentication is handled by your reverse proxy or access gateway. Use the button below through that entrypoint."
	} else if len(providers) == 0 {
		message = "Authentication is not configured yet. Set AUTH_PROVIDERS and provider credentials to sign in."
	}

	c.HTML(http.StatusOK, "login.html", gin.H{
		"AuthURL":       authURL,
		"Providers":     providers,
		"AuthProviders": providers,
		"AuthMessage":   message,
	})
}

func (m *AuthManager) LoginProviders() []LoginProvider {
	providers := make([]LoginProvider, 0, len(m.providerOrder))
	for _, providerID := range m.providerOrder {
		provider := m.providers[providerID]
		if provider == nil {
			continue
		}

		providers = append(providers, LoginProvider{
			ID:       provider.ID(),
			Name:     provider.DisplayName(),
			LoginURL: fmt.Sprintf("/auth/%s/login", provider.ID()),
		})
	}

	if m.proxyAuth != nil {
		providers = append(providers, LoginProvider{
			ID:       "proxy",
			Name:     m.proxyAuth.displayName,
			LoginURL: "/admin",
		})
	}

	return providers
}

func (m *AuthManager) HandleLogin(c *gin.Context) {
	provider, ok := m.providerForRequest(c)
	if !ok {
		return
	}

	stateValue, err := randomToken(32)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to initialize login")
		return
	}

	payload, err := m.codec.Encode(authState{
		ProviderID: provider.ID(),
		Value:      stateValue,
		ExpiresAt:  time.Now().Add(defaultStateTTL),
	})
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to initialize login")
		return
	}

	m.setCookie(c, stateCookieName(provider.ID()), payload, int(defaultStateTTL.Seconds()))
	c.Redirect(http.StatusFound, provider.AuthCodeURL(stateValue))
}

func (m *AuthManager) HandleCallback(c *gin.Context) {
	provider, ok := m.providerForRequest(c)
	if !ok {
		return
	}

	m.handleCallbackForProvider(c, provider)
}

func (m *AuthManager) HandleCallbackFor(providerID string) gin.HandlerFunc {
	return func(c *gin.Context) {
		provider, ok := m.providers[providerID]
		if !ok {
			c.String(http.StatusNotFound, "Unknown authentication provider")
			return
		}

		m.handleCallbackForProvider(c, provider)
	}
}

func (m *AuthManager) RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		if m.authDisabled {
			c.Next()
			return
		}

		if identity, statusCode, message := m.authenticateProxyRequest(c); identity != nil || statusCode != 0 {
			if statusCode != 0 {
				c.String(statusCode, message)
				c.Abort()
				return
			}

			if !m.authorizer.Authorize(*identity) {
				c.String(http.StatusForbidden, "Not authorized to access admin pages")
				c.Abort()
				return
			}

			c.Set("authIdentity", *identity)
			c.Next()
			return
		}

		sessionCookie, err := c.Cookie(m.sessionCookieName)
		if err != nil {
			c.Redirect(http.StatusFound, "/")
			c.Abort()
			return
		}

		var session authSession
		if err := m.codec.Decode(sessionCookie, &session); err != nil || time.Now().After(session.ExpiresAt) {
			m.clearCookie(c, m.sessionCookieName)
			c.Redirect(http.StatusFound, "/")
			c.Abort()
			return
		}

		if !m.authorizer.Authorize(session.Identity) {
			m.clearCookie(c, m.sessionCookieName)
			c.Redirect(http.StatusFound, "/")
			c.Abort()
			return
		}

		c.Set("authIdentity", session.Identity)
		c.Next()
	}
}

func (m *AuthManager) Logout(c *gin.Context) {
	m.clearCookie(c, m.sessionCookieName)
	for _, providerID := range m.providerOrder {
		m.clearCookie(c, stateCookieName(providerID))
	}
	c.Redirect(http.StatusFound, "/")
}

func (m *AuthManager) handleCallbackForProvider(c *gin.Context, provider AuthProvider) {
	state := strings.TrimSpace(c.Query("state"))
	code := strings.TrimSpace(c.Query("code"))
	if state == "" || code == "" {
		c.String(http.StatusBadRequest, "Missing authentication callback parameters")
		return
	}

	stateCookie, err := c.Cookie(stateCookieName(provider.ID()))
	if err != nil {
		c.String(http.StatusBadRequest, "Missing authentication state")
		return
	}

	var storedState authState
	if err := m.codec.Decode(stateCookie, &storedState); err != nil {
		m.clearCookie(c, stateCookieName(provider.ID()))
		c.String(http.StatusBadRequest, "Invalid authentication state")
		return
	}

	if storedState.ProviderID != provider.ID() || storedState.Value != state || time.Now().After(storedState.ExpiresAt) {
		m.clearCookie(c, stateCookieName(provider.ID()))
		c.String(http.StatusBadRequest, "Invalid authentication state")
		return
	}

	identity, err := provider.ExchangeIdentity(c.Request.Context(), code)
	if err != nil {
		m.clearCookie(c, stateCookieName(provider.ID()))
		log.Printf("auth callback failed for %s: %v", provider.ID(), err)
		c.String(http.StatusBadGateway, "Authentication failed")
		return
	}

	identity.Provider = provider.ID()
	if !m.authorizer.Authorize(*identity) {
		m.clearCookie(c, stateCookieName(provider.ID()))
		c.String(http.StatusForbidden, "Not authorized to access admin pages")
		return
	}

	sessionValue, err := m.codec.Encode(authSession{
		Identity:  *identity,
		ExpiresAt: time.Now().Add(m.sessionTTL),
	})
	if err != nil {
		m.clearCookie(c, stateCookieName(provider.ID()))
		c.String(http.StatusInternalServerError, "Failed to create session")
		return
	}

	m.clearCookie(c, stateCookieName(provider.ID()))
	m.setCookie(c, m.sessionCookieName, sessionValue, int(m.sessionTTL.Seconds()))
	c.Redirect(http.StatusFound, "/admin")
}

func (m *AuthManager) providerForRequest(c *gin.Context) (AuthProvider, bool) {
	providerID := strings.TrimSpace(strings.ToLower(c.Param("provider")))
	provider, ok := m.providers[providerID]
	if !ok {
		c.String(http.StatusNotFound, "Unknown authentication provider")
		return nil, false
	}

	return provider, true
}

func (m *AuthManager) setCookie(c *gin.Context, name, value string, maxAge int) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(name, value, maxAge, "/", m.cookieDomain, m.secureCookies, true)
}

func (m *AuthManager) clearCookie(c *gin.Context, name string) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(name, "", -1, "/", m.cookieDomain, m.secureCookies, true)
}

func (m *AuthManager) authenticateProxyRequest(c *gin.Context) (*Identity, int, string) {
	if m.proxyAuth == nil {
		return nil, 0, ""
	}

	return m.proxyAuth.authenticateRequest(c.Request)
}

func (p *ProxyAuthConfig) authenticateRequest(r *http.Request) (*Identity, int, string) {
	if p == nil {
		return nil, 0, ""
	}

	headersPresent := p.hasAnyConfiguredHeader(r)
	if !headersPresent {
		if p.proxyOnly {
			return nil, http.StatusUnauthorized, "Proxy authentication required"
		}
		return nil, 0, ""
	}

	if !p.isTrustedSource(r.RemoteAddr) {
		return nil, http.StatusForbidden, "Proxy authentication headers are only accepted from trusted proxies"
	}

	identity := p.identityFromHeaders(r)
	if identity.Subject == "" {
		return nil, http.StatusUnauthorized, "Proxy authentication headers did not include a user identity"
	}

	return identity, 0, ""
}

func (p *ProxyAuthConfig) hasAnyConfiguredHeader(r *http.Request) bool {
	for _, header := range p.allHeaders() {
		if strings.TrimSpace(r.Header.Get(header)) != "" {
			return true
		}
	}

	return false
}

func (p *ProxyAuthConfig) allHeaders() []string {
	combined := make([]string, 0, len(p.subjectHeaders)+len(p.emailHeaders)+len(p.nameHeaders)+len(p.groupsHeaders)+len(p.organizationHeaders)+len(p.teamHeaders))
	combined = append(combined, p.subjectHeaders...)
	combined = append(combined, p.emailHeaders...)
	combined = append(combined, p.nameHeaders...)
	combined = append(combined, p.groupsHeaders...)
	combined = append(combined, p.organizationHeaders...)
	combined = append(combined, p.teamHeaders...)
	return compactStrings(combined)
}

func (p *ProxyAuthConfig) isTrustedSource(remoteAddr string) bool {
	if p.trustAll {
		return true
	}

	remoteIP, err := remoteIPFromAddr(remoteAddr)
	if err != nil {
		return false
	}

	for _, prefix := range p.trustedProxies {
		if prefix.Contains(remoteIP) {
			return true
		}
	}

	return false
}

func (p *ProxyAuthConfig) identityFromHeaders(r *http.Request) *Identity {
	subject := p.firstHeaderValue(r, p.subjectHeaders)
	email := strings.ToLower(p.firstHeaderValue(r, p.emailHeaders))
	if subject == "" {
		subject = email
	}

	identity := &Identity{
		Provider:       "proxy",
		Subject:        subject,
		ProviderUserID: subject,
		Email:          email,
		DisplayName:    firstNonEmpty(p.firstHeaderValue(r, p.nameHeaders), email, subject),
		Groups:         compactStrings(splitAndTrim(p.firstHeaderValue(r, p.groupsHeaders))),
		Organizations:  lowercaseStrings(splitAndTrim(p.firstHeaderValue(r, p.organizationHeaders))),
		Teams:          normalizeGitHubTeams(splitAndTrim(p.firstHeaderValue(r, p.teamHeaders))),
	}

	return identity
}

func (p *ProxyAuthConfig) firstHeaderValue(r *http.Request, names []string) string {
	for _, name := range names {
		if value := strings.TrimSpace(r.Header.Get(name)); value != "" {
			return value
		}
	}

	return ""
}

func loadAuthorizerFromEnv() Authorizer {
	return Authorizer{
		adminEmails:        toSet(splitAndTrim(os.Getenv("AUTH_ADMIN_EMAILS"))),
		adminGroups:        toSet(splitAndTrim(os.Getenv("AUTH_ADMIN_GROUPS"))),
		requiredDomain:     strings.ToLower(strings.TrimSpace(os.Getenv("AUTH_REQUIRED_DOMAIN"))),
		githubAllowedOrgs:  toSet(splitAndTrim(os.Getenv("AUTH_GITHUB_ALLOWED_ORGS"))),
		githubAllowedTeams: toSet(normalizeGitHubTeams(splitAndTrim(os.Getenv("AUTH_GITHUB_ALLOWED_TEAMS")))),
		allowAnyUser:       envBool("AUTH_ALLOW_ANY_AUTHENTICATED", false),
	}
}

func (a Authorizer) Authorize(identity Identity) bool {
	if identity.Subject == "" {
		return false
	}

	domainMatched := false
	if a.requiredDomain != "" {
		domainMatched = domainFromEmail(identity.Email) == a.requiredDomain
	}

	if a.allowAnyUser {
		if a.requiredDomain == "" {
			return true
		}
		return domainMatched
	}

	if len(a.adminEmails) == 0 && len(a.adminGroups) == 0 && len(a.githubAllowedOrgs) == 0 && len(a.githubAllowedTeams) == 0 {
		return domainMatched
	}

	if containsSet(a.adminEmails, strings.ToLower(strings.TrimSpace(identity.Email))) {
		return true
	}

	if domainMatched {
		return true
	}

	for _, group := range identity.Groups {
		if containsSet(a.adminGroups, strings.ToLower(strings.TrimSpace(group))) {
			return true
		}
	}

	if strings.EqualFold(identity.Provider, "github") {
		for _, org := range identity.Organizations {
			if containsSet(a.githubAllowedOrgs, strings.ToLower(strings.TrimSpace(org))) {
				return true
			}
		}

		for _, team := range identity.Teams {
			if containsSet(a.githubAllowedTeams, strings.ToLower(strings.TrimSpace(team))) {
				return true
			}
		}
	}

	return false
}

func (a Authorizer) NeedsGitHubOrgData() bool {
	return len(a.githubAllowedOrgs) > 0 || len(a.githubAllowedTeams) > 0
}

func (a Authorizer) NeedsGitHubTeamData() bool {
	return len(a.githubAllowedTeams) > 0
}

func loadProxyAuthFromEnv(enabled, proxyOnly bool) (*ProxyAuthConfig, error) {
	if !enabled {
		return nil, nil
	}

	trustedProxies, usingDefaultTrust, err := loadTrustedProxyPrefixes()
	if err != nil {
		return nil, err
	}

	trustAll := envBool("AUTH_PROXY_TRUST_ALL", false)
	if usingDefaultTrust && !trustAll {
		log.Println("AUTH_PROXY_TRUSTED_PROXIES is not set; only loopback proxies are trusted for proxy authentication")
	}
	if trustAll {
		log.Println("AUTH_PROXY_TRUST_ALL=true enables proxy header trust for every source; use only in controlled environments")
	}

	return &ProxyAuthConfig{
		proxyOnly:           proxyOnly,
		displayName:         firstNonEmpty(os.Getenv("AUTH_PROXY_DISPLAY_NAME"), "Single Sign-On"),
		trustAll:            trustAll,
		trustedProxies:      trustedProxies,
		subjectHeaders:      parseHeaderNames(firstNonEmpty(os.Getenv("AUTH_PROXY_SUBJECT_HEADERS"), "X-Forwarded-User,X-Auth-Request-User,Remote-User,X-Remote-User")),
		emailHeaders:        parseHeaderNames(firstNonEmpty(os.Getenv("AUTH_PROXY_EMAIL_HEADERS"), "X-Forwarded-Email,X-Auth-Request-Email,Remote-Email,X-Remote-Email")),
		nameHeaders:         parseHeaderNames(firstNonEmpty(os.Getenv("AUTH_PROXY_NAME_HEADERS"), "X-Forwarded-Preferred-Username,X-Forwarded-Name,X-Auth-Request-Preferred-Username,X-Auth-Request-User")),
		groupsHeaders:       parseHeaderNames(firstNonEmpty(os.Getenv("AUTH_PROXY_GROUPS_HEADERS"), "X-Forwarded-Groups,X-Auth-Request-Groups,Remote-Groups,X-Remote-Groups")),
		organizationHeaders: parseHeaderNames(firstNonEmpty(os.Getenv("AUTH_PROXY_ORGS_HEADERS"), "X-Forwarded-Orgs,X-Auth-Request-Orgs")),
		teamHeaders:         parseHeaderNames(firstNonEmpty(os.Getenv("AUTH_PROXY_TEAMS_HEADERS"), "X-Forwarded-Teams,X-Auth-Request-Teams")),
	}, nil
}

func loadTrustedProxyPrefixes() ([]netip.Prefix, bool, error) {
	configured := splitAndTrim(os.Getenv("AUTH_PROXY_TRUSTED_PROXIES"))
	if len(configured) == 0 {
		return defaultLoopbackProxyPrefixes(), true, nil
	}

	prefixes := make([]netip.Prefix, 0, len(configured))
	for _, raw := range configured {
		prefix, err := parseTrustedProxyPrefix(raw)
		if err != nil {
			return nil, false, fmt.Errorf("invalid AUTH_PROXY_TRUSTED_PROXIES entry %q: %w", raw, err)
		}
		prefixes = append(prefixes, prefix.Masked())
	}

	return prefixes, false, nil
}

func parseTrustedProxyPrefix(value string) (netip.Prefix, error) {
	if strings.Contains(value, "/") {
		return netip.ParsePrefix(value)
	}

	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}

	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func defaultLoopbackProxyPrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("127.0.0.1/32"),
		netip.MustParsePrefix("::1/128"),
	}
}

func remoteIPFromAddr(remoteAddr string) (netip.Addr, error) {
	host := strings.TrimSpace(remoteAddr)
	if parsedHost, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = strings.TrimSpace(parsedHost)
	}

	return netip.ParseAddr(host)
}

func parseHeaderNames(value string) []string {
	return compactStrings(splitAndTrim(value))
}

func buildProviderFromEnv(providerID string, authorizer Authorizer) (AuthProvider, error) {
	switch providerID {
	case "mentorlogin":
		return newMentorLoginProviderFromEnv()
	case "github":
		return newGitHubProviderFromEnv(authorizer)
	default:
		return nil, fmt.Errorf("unsupported auth provider %q", providerID)
	}
}

func newMentorLoginProviderFromEnv() (AuthProvider, error) {
	issuer := strings.TrimRight(strings.TrimSpace(os.Getenv("AUTH_PROVIDER_MENTORLOGIN_ISSUER")), "/")
	clientID := strings.TrimSpace(os.Getenv("AUTH_PROVIDER_MENTORLOGIN_CLIENT_ID"))
	clientSecret := strings.TrimSpace(os.Getenv("AUTH_PROVIDER_MENTORLOGIN_CLIENT_SECRET"))
	redirectURL := strings.TrimSpace(os.Getenv("AUTH_PROVIDER_MENTORLOGIN_CALLBACK_URL"))
	if issuer == "" || clientID == "" || clientSecret == "" || redirectURL == "" {
		return nil, errors.New("mentorlogin auth requires issuer, client id, client secret, and callback url")
	}

	scopes := splitAndTrim(os.Getenv("AUTH_PROVIDER_MENTORLOGIN_SCOPES"))
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	userInfoURL := strings.TrimSpace(os.Getenv("AUTH_PROVIDER_MENTORLOGIN_USERINFO_URL"))
	if userInfoURL == "" {
		userInfoURL = issuer + "/userinfo"
	}

	return &oauthUserInfoProvider{
		id:          "mentorlogin",
		displayName: firstNonEmpty(os.Getenv("AUTH_PROVIDER_MENTORLOGIN_DISPLAY_NAME"), "MentorLogin"),
		oauthConfig: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:  issuer + "/authorize",
				TokenURL: issuer + "/token",
			},
			Scopes: scopes,
		},
		userInfoURL:  userInfoURL,
		emailClaim:   firstNonEmpty(os.Getenv("AUTH_PROVIDER_MENTORLOGIN_EMAIL_CLAIM"), "email"),
		nameClaim:    firstNonEmpty(os.Getenv("AUTH_PROVIDER_MENTORLOGIN_NAME_CLAIM"), "name"),
		subjectClaim: firstNonEmpty(os.Getenv("AUTH_PROVIDER_MENTORLOGIN_SUBJECT_CLAIM"), "sub"),
		groupsClaim:  firstNonEmpty(os.Getenv("AUTH_PROVIDER_MENTORLOGIN_GROUPS_CLAIM"), "groups"),
	}, nil
}

func (p *oauthUserInfoProvider) ID() string {
	return p.id
}

func (p *oauthUserInfoProvider) DisplayName() string {
	return p.displayName
}

func (p *oauthUserInfoProvider) AuthCodeURL(state string) string {
	return p.oauthConfig.AuthCodeURL(state)
}

func (p *oauthUserInfoProvider) ExchangeIdentity(ctx context.Context, code string) (*Identity, error) {
	token, err := p.oauthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	client := p.oauthConfig.Client(ctx, token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("userinfo request failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var claims map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, err
	}

	subject := firstNonEmpty(stringClaim(claims, p.subjectClaim), stringClaim(claims, "sub"))
	email := firstNonEmpty(stringClaim(claims, p.emailClaim), stringClaim(claims, "email"))
	if subject == "" {
		subject = email
	}

	identity := &Identity{
		Provider:       p.id,
		Subject:        subject,
		ProviderUserID: subject,
		Email:          email,
		DisplayName:    firstNonEmpty(stringClaim(claims, p.nameClaim), stringClaim(claims, "preferred_username"), email),
		Groups:         stringSliceClaim(claims, p.groupsClaim),
	}

	return identity, nil
}

func newGitHubProviderFromEnv(authorizer Authorizer) (AuthProvider, error) {
	clientID := strings.TrimSpace(firstNonEmpty(
		os.Getenv("AUTH_PROVIDER_GITHUB_CLIENT_ID"),
		os.Getenv("GITHUB_CLIENT_ID"),
	))
	clientSecret := strings.TrimSpace(firstNonEmpty(
		os.Getenv("AUTH_PROVIDER_GITHUB_CLIENT_SECRET"),
		os.Getenv("GITHUB_CLIENT_SECRET"),
	))
	redirectURL := strings.TrimSpace(firstNonEmpty(
		os.Getenv("AUTH_PROVIDER_GITHUB_CALLBACK_URL"),
		os.Getenv("GITHUB_CALLBACK_URL"),
	))
	if clientID == "" || clientSecret == "" || redirectURL == "" {
		return nil, errors.New("github auth requires client id, client secret, and callback url")
	}

	scopes := splitAndTrim(firstNonEmpty(os.Getenv("AUTH_PROVIDER_GITHUB_SCOPES"), os.Getenv("GITHUB_SCOPES")))
	if len(scopes) == 0 {
		scopes = []string{"read:user", "user:email"}
	}
	if authorizer.NeedsGitHubOrgData() && !containsFoldSlice(scopes, "read:org") {
		scopes = append(scopes, "read:org")
	}

	return &gitHubProvider{
		providerID:  "github",
		displayName: firstNonEmpty(os.Getenv("AUTH_PROVIDER_GITHUB_DISPLAY_NAME"), "GitHub"),
		oauthConfig: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://github.com/login/oauth/authorize",
				TokenURL: "https://github.com/login/oauth/access_token",
			},
			Scopes: scopes,
		},
		loadOrgs:     authorizer.NeedsGitHubOrgData(),
		loadTeams:    authorizer.NeedsGitHubTeamData(),
		apiUserURL:   defaultGitHubUserURL,
		apiEmailsURL: defaultGitHubEmailsURL,
		apiOrgsURL:   defaultGitHubOrgsURL,
		apiTeamsURL:  defaultGitHubTeamsURL,
	}, nil
}

func (p *gitHubProvider) ID() string {
	return p.providerID
}

func (p *gitHubProvider) DisplayName() string {
	return p.displayName
}

func (p *gitHubProvider) AuthCodeURL(state string) string {
	return p.oauthConfig.AuthCodeURL(state)
}

func (p *gitHubProvider) ExchangeIdentity(ctx context.Context, code string) (*Identity, error) {
	token, err := p.oauthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	client := p.oauthConfig.Client(ctx, token)
	user, err := p.loadUser(ctx, client)
	if err != nil {
		return nil, err
	}

	email, err := p.loadPrimaryEmail(ctx, client)
	if err != nil {
		return nil, err
	}
	if email == "" {
		email = strings.TrimSpace(user.Email)
	}

	identity := &Identity{
		Provider:       p.providerID,
		Subject:        firstNonEmpty(user.Login, strconv.FormatInt(user.ID, 10)),
		ProviderUserID: strconv.FormatInt(user.ID, 10),
		Email:          strings.ToLower(strings.TrimSpace(email)),
		DisplayName:    firstNonEmpty(strings.TrimSpace(user.Name), strings.TrimSpace(user.Login), strings.TrimSpace(email)),
	}

	if p.loadOrgs {
		identity.Organizations, err = p.loadOrganizations(ctx, client)
		if err != nil {
			return nil, err
		}
	}
	if p.loadTeams {
		identity.Teams, err = p.loadTeamsMembership(ctx, client)
		if err != nil {
			return nil, err
		}
	}

	return identity, nil
}

func (p *gitHubProvider) loadUser(ctx context.Context, client *http.Client) (gitHubUser, error) {
	var user gitHubUser
	if err := getJSON(ctx, client, p.apiUserURL, &user); err != nil {
		return gitHubUser{}, err
	}
	return user, nil
}

func (p *gitHubProvider) loadPrimaryEmail(ctx context.Context, client *http.Client) (string, error) {
	var emails []gitHubEmail
	if err := getJSON(ctx, client, p.apiEmailsURL, &emails); err != nil {
		return "", err
	}

	for _, email := range emails {
		if email.Primary && email.Verified {
			return strings.ToLower(strings.TrimSpace(email.Email)), nil
		}
	}
	for _, email := range emails {
		if email.Verified {
			return strings.ToLower(strings.TrimSpace(email.Email)), nil
		}
	}
	return "", nil
}

func (p *gitHubProvider) loadOrganizations(ctx context.Context, client *http.Client) ([]string, error) {
	var orgs []gitHubOrg
	if err := getJSON(ctx, client, p.apiOrgsURL, &orgs); err != nil {
		return nil, err
	}

	values := make([]string, 0, len(orgs))
	for _, org := range orgs {
		if login := strings.ToLower(strings.TrimSpace(org.Login)); login != "" {
			values = append(values, login)
		}
	}

	sort.Strings(values)
	return compactStrings(values), nil
}

func (p *gitHubProvider) loadTeamsMembership(ctx context.Context, client *http.Client) ([]string, error) {
	var teams []gitHubTeam
	if err := getJSON(ctx, client, p.apiTeamsURL, &teams); err != nil {
		return nil, err
	}

	values := make([]string, 0, len(teams))
	for _, team := range teams {
		org := strings.ToLower(strings.TrimSpace(team.Org.Login))
		slug := strings.ToLower(strings.TrimSpace(team.Slug))
		if org == "" || slug == "" {
			continue
		}
		values = append(values, org+"/"+slug)
	}

	sort.Strings(values)
	return compactStrings(values), nil
}

func getJSON(ctx context.Context, client *http.Client, endpoint string, dest any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("request to %s failed with status %d: %s", endpoint, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return json.NewDecoder(resp.Body).Decode(dest)
}

func newSealedCookieCodec(secret string) (*sealedCookieCodec, error) {
	hash := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &sealedCookieCodec{gcm: gcm}, nil
}

func (c *sealedCookieCodec) Encode(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	sealed := c.gcm.Seal(nil, nonce, payload, nil)
	buffer := append(nonce, sealed...)
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func (c *sealedCookieCodec) Decode(value string, dest any) error {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return err
	}

	nonceSize := c.gcm.NonceSize()
	if len(raw) <= nonceSize {
		return errors.New("invalid encoded value")
	}

	payload, err := c.gcm.Open(nil, raw[:nonceSize], raw[nonceSize:], nil)
	if err != nil {
		return err
	}

	return json.Unmarshal(payload, dest)
}

func configuredProviderIDs() []string {
	configured := splitAndTrim(os.Getenv("AUTH_PROVIDERS"))
	if len(configured) == 0 {
		if hasMentorLoginEnv() {
			configured = append(configured, "mentorlogin")
		}
		if hasGitHubEnv() {
			configured = append(configured, "github")
		}
	}

	values := make([]string, 0, len(configured))
	seen := make(map[string]struct{}, len(configured))
	for _, providerID := range configured {
		providerID = strings.ToLower(strings.TrimSpace(providerID))
		if providerID == "" {
			continue
		}
		if _, ok := seen[providerID]; ok {
			continue
		}
		seen[providerID] = struct{}{}
		values = append(values, providerID)
	}

	return values
}

func hasMentorLoginEnv() bool {
	return strings.TrimSpace(os.Getenv("AUTH_PROVIDER_MENTORLOGIN_CLIENT_ID")) != ""
}

func hasGitHubEnv() bool {
	return strings.TrimSpace(firstNonEmpty(
		os.Getenv("AUTH_PROVIDER_GITHUB_CLIENT_ID"),
		os.Getenv("GITHUB_CLIENT_ID"),
	)) != ""
}

func loadSessionSecret() string {
	secret := strings.TrimSpace(os.Getenv("AUTH_SESSION_SECRET"))
	if secret != "" {
		return secret
	}

	generated, err := randomToken(48)
	if err != nil {
		log.Fatal("failed to generate auth session secret:", err)
	}
	log.Println("AUTH_SESSION_SECRET is not set; using an ephemeral secret for this process")
	return generated
}

func envBool(key string, defaultValue bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return defaultValue
	}

	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return defaultValue
	}

	return parsed
}

func parseDurationEnv(key string, defaultValue time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return defaultValue
	}

	parsed, err := time.ParseDuration(value)
	if err != nil {
		log.Printf("Invalid duration for %s: %q, using default %s", key, value, defaultValue)
		return defaultValue
	}

	return parsed
}

func splitAndTrim(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n'
	})
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			values = append(values, part)
		}
	}
	return values
}

func toSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	return set
}

func containsSet(values map[string]struct{}, value string) bool {
	if len(values) == 0 || value == "" {
		return false
	}
	_, ok := values[value]
	return ok
}

func containsFoldSlice(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), target) {
			return true
		}
	}
	return false
}

func randomToken(length int) (string, error) {
	buffer := make([]byte, length)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func stringClaim(claims map[string]any, path string) string {
	value := claimValue(claims, path)
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case int64:
		return strconv.FormatInt(typed, 10)
	case json.Number:
		return typed.String()
	default:
		return ""
	}
}

func stringSliceClaim(claims map[string]any, path string) []string {
	value := claimValue(claims, path)
	switch typed := value.(type) {
	case []string:
		return compactStrings(typed)
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok {
				values = append(values, text)
			}
		}
		return compactStrings(values)
	case string:
		return compactStrings(splitAndTrim(typed))
	default:
		return nil
	}
}

func claimValue(claims map[string]any, path string) any {
	if path == "" {
		return nil
	}

	segments := strings.Split(path, ".")
	var current any = claims
	for _, segment := range segments {
		mapping, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current, ok = mapping[segment]
		if !ok {
			return nil
		}
	}
	return current
}

func domainFromEmail(email string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(email)), "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

func normalizeGitHubTeams(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		normalized = append(normalized, strings.ReplaceAll(value, " ", ""))
	}
	return normalized
}

func compactStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(values))
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		cleaned = append(cleaned, value)
	}
	return cleaned
}

func lowercaseStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			cleaned = append(cleaned, value)
		}
	}

	return compactStrings(cleaned)
}

func stateCookieName(providerID string) string {
	return stateCookiePrefix + providerID
}
