package ose_jwt

import (
	"github.com/ose-micro/common/claims"
)

// HasTenantRole checks if the user has a specific role in a tenant
func HasTenantRole(c Claims, tenantID, role string) bool {
	if tenant, ok := c.Tenants[tenantID]; ok {
		return tenant.Role == role
	}
	return false
}

// HasTenantPermission checks if the user has a specific permission in a tenant
func HasTenantPermission(c Claims, tenantID string, perm claims.Permission) bool {
	if tenant, ok := c.Tenants[tenantID]; ok {
		for _, p := range tenant.Permissions {
			if p.Action == perm.Action && p.Resource == perm.Resource {
				return true
			}
		}
	}
	return false
}
