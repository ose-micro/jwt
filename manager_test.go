package ose_jwt_test

import (
	"testing"

	"github.com/ose-micro/common"
	ose_jwt "github.com/ose-micro/jwt"
	"github.com/stretchr/testify/assert"
)

func TestManager_IssueAccessToken(t *testing.T) {

	secret := []byte("secret")

	manager, err := ose_jwt.NewManager(ose_jwt.Config{
		Prefix: "FMC",
		Secret: secret,
		Issuer: "ose",
	})

	if err != nil {
		t.Fatal(err)
	}

	tenants := make(map[string]ose_jwt.Tenant)
	tenants["owner"] = ose_jwt.Tenant{
		Role:   "admin",
		Tenant: "owner",
		Permissions: []common.Permission{
			{
				Resource: "campaign",
				Action:   "create",
			},
			{
				Resource: "campaign",
				Action:   "read",
			},
			{
				Resource: "campaign",
				Action:   "update",
			},
		},
	}

	token, _, err := manager.IssueAccessToken("me", tenants, nil)
	if err != nil {
		t.Fatal(err)
	}

	claims, err := manager.ParseClaims(token)
	if err != nil {
		t.Fatal(err)
	}

	res := ose_jwt.HasTenantRole(*claims, "owner", "admin")
	assert.True(t, res)

	res = ose_jwt.HasTenantPermission(*claims, "owner", common.Permission{
		Resource: "campaign",
		Action:   "create",
	})
	assert.True(t, res)

	res = ose_jwt.HasTenantPermission(*claims, "owner", common.Permission{
		Resource: "account",
		Action:   "create",
	})
	assert.False(t, res)
}
