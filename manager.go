package ose_jwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ose-micro/rid"
)

type Config struct {
	Prefix     string        `json:"prefix"`
	Secret     string        `json:"secret"`
	Issuer     string        `json:"issuer"`
	AccessTTL  time.Duration `json:"access_ttl"`
	RefreshTTL time.Duration `json:"refresh_ttl"`
	PurposeTTL time.Duration `json:"purpose_ttl"`
}

type Manager struct {
	prefix     string
	secret     []byte
	issuer     string
	accessTTL  time.Duration
	refreshTTL time.Duration
	purposeTTL time.Duration
}

// helper: use defaults if duration is <= 0
func defaultDuration(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// NewManager creates a JWT manager with defaults
func NewManager(config Config) (*Manager, error) {
	if len(config.Secret) == 0 {
		return nil, errors.New("secret required")
	}

	prefix := config.Prefix
	if prefix == "" {
		prefix = "jwt"
	}

	return &Manager{
		prefix:     prefix,
		secret:     []byte(config.Secret),
		issuer:     config.Issuer,
		accessTTL:  defaultDuration(config.AccessTTL, 15*time.Minute),
		refreshTTL: defaultDuration(config.RefreshTTL, 7*24*time.Hour),
		purposeTTL: defaultDuration(config.PurposeTTL, 30*time.Minute),
	}, nil
}

func (m *Manager) issue(sub string, kind TokenKind, tenants map[string]Tenant, ttl time.Duration, extra map[string]any) (string, *Claims, error) {
	now := time.Now().UTC()
	jti := rid.New(m.prefix, true)

	claims := &Claims{
		Sub:       sub,
		Kind:      kind,
		Tenants:   tenants,
		JTI:       jti.String(),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl).UTC()), // <- force UTC
		IssuedAt:  jwt.NewNumericDate(now.UTC()),
		Issuer:    m.issuer,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Add extra claims if provided (flattened MapClaims)
	if extra != nil {
		mc := jwt.MapClaims{
			"sub": claims.Sub,
			"typ": claims.Kind,
			"jti": claims.JTI,
			"iss": claims.Issuer,
			"iat": claims.IssuedAt.Unix(),
			"exp": claims.ExpiresAt.Unix(),
		}
		for k, v := range extra {
			mc[k] = v
		}
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, mc)
	}

	signed, err := token.SignedString(m.secret)
	if err != nil {
		return "", nil, err
	}

	return signed, claims, nil
}

// IssueAccessToken Public issue methods
func (m *Manager) IssueAccessToken(sub string, tenants map[string]Tenant, extra map[string]any) (string, *Claims, error) {
	return m.issue(sub, AccessToken, tenants, m.accessTTL, extra)
}

func (m *Manager) IssueRefreshToken(sub string, tenants map[string]Tenant, extra map[string]any) (string, *Claims, error) {
	return m.issue(sub, RefreshToken, tenants, m.refreshTTL, extra)
}

func (m *Manager) IssuePurposeToken(sub string, tenants map[string]Tenant, extra map[string]any) (string, *Claims, error) {
	return m.issue(sub, PurposeToken, tenants, m.purposeTTL, extra)
}

// IssueToken Generic issue with custom TTL
func (m *Manager) IssueToken(sub string, kind TokenKind, tenants map[string]Tenant, extra map[string]any, ttl time.Duration) (string, error) {
	tok, _, err := m.issue(sub, kind, tenants, ttl, extra)
	return tok, err
}

// ParseClaimsUnsafe parses without signature validation
func (m *Manager) ParseClaimsUnsafe(tokenStr string) (*Claims, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	var out Claims
	_, _, err := parser.ParseUnverified(tokenStr, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ParseClaims validates signature and returns Claims
func (m *Manager) ParseClaims(tokenStr string) (*Claims, error) {
	var claims Claims
	token, err := jwt.ParseWithClaims(tokenStr, &claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return m.secret, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	return &claims, nil
}
