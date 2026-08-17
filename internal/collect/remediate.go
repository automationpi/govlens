package collect

import (
	"context"
	"fmt"
)

// Remediation reads and (optionally) writes used by the worker. These are the
// ONLY mutating calls in the codebase; a delete needs a write-capable SP
// (RoleManagement.ReadWrite.Directory for Entra, roleAssignments/delete for RBAC).

// GlobalAdminCount returns how many Global Administrator directory-role
// assignments currently exist — used by the "never drop below N admins" guard.
func (c *Collector) GlobalAdminCount(ctx context.Context) (int, error) {
	roles, err := c.directoryRoles(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, a := range roles {
		if a.Role == "Global Administrator" {
			n++
		}
	}
	return n, nil
}

// Exists re-validates that a revoke target still exists before acting on it.
func (c *Collector) Exists(ctx context.Context, kind, ident string) (bool, error) {
	switch kind {
	case "entra_role":
		return existsGET(ctx, c.graph, graphBase+"/roleManagement/directory/roleAssignments/"+ident)
	case "rbac":
		return existsGET(ctx, c.arm, armBase+ident+"?api-version=2022-04-01")
	default:
		return false, fmt.Errorf("unsupported kind %q", kind)
	}
}

// Delete revokes an assignment. REQUIRES a write-capable SP.
func (c *Collector) Delete(ctx context.Context, kind, ident string) error {
	switch kind {
	case "entra_role":
		return del(ctx, c.graph, graphBase+"/roleManagement/directory/roleAssignments/"+ident)
	case "rbac":
		return del(ctx, c.arm, armBase+ident+"?api-version=2022-04-01")
	default:
		return fmt.Errorf("unsupported kind %q", kind)
	}
}
