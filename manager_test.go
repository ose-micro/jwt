package ose_jwt_test

import (
	"testing"

	"github.com/ose-micro/common"
	ose_jwt "github.com/ose-micro/jwt"
	"github.com/stretchr/testify/assert"
)

func TestManager_IssueAccessToken(t *testing.T) {
	manager, err := ose_jwt.NewManager(ose_jwt.Config{
		Prefix: "FMC",
		Secret: "secret",
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

	t.Log(token)
}

func TestManager_ParseClaims(t *testing.T) {
	manager, err := ose_jwt.NewManager(ose_jwt.Config{
		Prefix: "FMC",
		Secret: "mI7r9jQpLk3uXy6fHnWb2sEwRtAq8fGhJaL0yUzXk1E=",
		Issuer: "Fundme.cloud",
	})

	if err != nil {
		t.Fatal(err)
	}

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJVU1IyNTA4Mi0xODExLTQwMTctMTM3Mi00NjIxMDYwOEI3MjkiLCJ0eXAiOiJyZWZyZXNoIiwidGVuYW50cyI6eyJUTlQyNTA4Mi0xMzEyLUMzNEUtMjQ0QS1BOEFDNDAwNkVDNkEiOnsicm9sZSI6IlJPTDI1MDgyLTE1NDEtRTYxNS1BQkVGLUVGRTg4RjE4MDY4RSIsInRlbmFudCI6IlROVDI1MDgyLTEzMTItQzM0RS0yNDRBLUE4QUM0MDA2RUM2QSIsInBlcm1pc3Npb25zIjpbeyJyZXNvdXJjZSI6ImNhbXBhaWduIiwiYWN0aW9uIjoidmlldyJ9LHsicmVzb3VyY2UiOiJjYW1wYWlnbiIsImFjdGlvbiI6ImVkaXQifSx7InJlc291cmNlIjoiY2FtcGFpZ24iLCJhY3Rpb24iOiJjcmVhdGUifSx7InJlc291cmNlIjoiY2FtcGFpZ24iLCJhY3Rpb24iOiJkZWxldGUifV19fSwianRpIjoiMjUwODMxICAtMDEzNS02QTgwLTQ4QjMtMTFGNUM0QzcxQzM3IiwiZXhwIjoxNzU2NjA0MTM3LCJpYXQiOjE3NTY2MDQxMzd9.QYyRZBeORFxmRQSDG4JN_Xk90fZnPHuRwtsIlHi2pVY"

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
