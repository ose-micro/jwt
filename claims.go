package ose_jwt

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/ose-micro/common/claims"
)

// Tenant holds role + permissions for a specific tenant
type Tenant struct {
	Role        string              `json:"role"`
	Tenant      string              `json:"tenant"`
	Permissions []claims.Permission `json:"permissions"`
}

type TokenKind string

const (
	AccessToken  TokenKind = "access"
	RefreshToken TokenKind = "refresh"
	PurposeToken TokenKind = "purpose"
)

// Claims defines our custom JWT dto
type Claims struct {
	Sub       string            `json:"sub"`
	Kind      TokenKind         `json:"typ"`
	Tenants   map[string]Tenant `json:"tenants,omitempty"`
	JTI       string            `json:"jti"`
	ExpiresAt *jwt.NumericDate  `json:"exp,omitempty"`
	IssuedAt  *jwt.NumericDate  `json:"iat,omitempty"`
	Issuer    string            `json:"iss,omitempty"`
	Audience  jwt.ClaimStrings  `json:"aud,omitempty"`
}

// --- Standard JWT Claim methods ---

func (c Claims) GetExpirationTime() (*jwt.NumericDate, error) {
	return c.ExpiresAt, nil
}

func (c Claims) GetIssuedAt() (*jwt.NumericDate, error) {
	return c.IssuedAt, nil
}

func (c Claims) GetNotBefore() (*jwt.NumericDate, error) {
	// If you don’t use nbf, return nil
	return nil, nil
}

func (c Claims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

func (c Claims) GetSubject() (string, error) {
	return c.Sub, nil
}

func (c Claims) GetAudience() (jwt.ClaimStrings, error) {
	return c.Audience, nil
}
