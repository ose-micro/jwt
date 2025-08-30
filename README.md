# ose-jwt

`ose-jwt` is a Go package for managing JSON Web Tokens (JWT) with support for **access tokens**, **refresh tokens**, and
**purpose-specific tokens**. It provides a structured way to include **multi-tenant roles and permissions**, as well as
custom claims. The package is lightweight, secure, and easy to integrate.

---

## Features

- Issue JWTs for **access**, **refresh**, or **purpose** tokens
- Supports **multi-tenant role and permission claims**
- Include **custom extra claims**
- Parse and validate JWTs safely
- Automatically manages **expiration** and **issued-at timestamps**
- Uses **UTC** timestamps for consistency across systems

---

## Installation

```bash
go get github.com/ose-micro/jwt
```

## Usage

### Initialize Manager

```go
package main

import (
	"fmt"
	"time"

	ose_jwt "github.com/ose-micro/jwt"
)

func main() {
	cfg := ose_jwt.Config{
		Prefix:     "OSE",
		Secret:     []byte("super-secret-key"),
		Issuer:     "ose",
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 7 * 24 * time.Hour,
		PurposeTTL: 30 * time.Minute,
	}

	manager, err := ose_jwt.NewManager(cfg)
	if err != nil {
		panic(err)
	}

	fmt.Println("JWT Manager initialized:", manager)
}

```

Issue Tokens

```go
tenants := map[string]jwt.Tenant{
    "owner": {
        Role:   "admin",
        Tenant: "owner",
        Permissions: []common.Permission{
            {Resource: "campaign", Action: "create"},
            {Resource: "campaign", Action: "read"},
        },
    },
}

token, claims, err := manager.IssueAccessToken("user123", tenants, nil)
if err != nil {
    panic(err)
}

fmt.Println("Access Token:", token)
fmt.Println("Claims:", claims)
```

⚠ Warning: ParseClaimsUnsafe does not validate the token signature. Use it only for debugging or logging.

Helpers

Check tenant roles and permissions easily:
```go
if jwt.HasTenantRole(*claims, "owner", "admin") {
    fmt.Println("User is an admin in the owner tenant")
}

perm := common.Permission{Resource: "campaign", Action: "create"}
if jwt.HasTenantPermission(*claims, "owner", perm) {
    fmt.Println("User can create campaigns")
}
```
License

MIT License © 2025 Moriba SL