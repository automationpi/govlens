package collect

import (
	"context"
	"encoding/json"
	"strings"
)

// ProbeGrantSP authenticates as the write-capable grant SP and inspects its
// EFFECTIVE permissions at rootScope, confirming two things fail-closed:
//   - it CAN write role assignments (Microsoft.Authorization/roleAssignments/write), and
//   - it is NOT over-permissioned (does not hold '*'/Owner).
//
// It is strictly read-only — it never creates or deletes anything. Returns
// (ok, human-readable note). ok=false with an actionable note on any shortfall.
func ProbeGrantSP(ctx context.Context, sp *SP, rootScope string) (ok bool, note string) {
	arm, err := sp.Token(ctx, armScope)
	if err != nil {
		return false, "authentication failed: " + err.Error()
	}
	if rootScope == "" {
		return false, "no root scope configured"
	}
	url := armBase + rootScope + "/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
	raw, err := pagedValues(ctx, arm, url)
	if err != nil {
		// Auth worked but we couldn't read effective permissions — usually the SP
		// lacks Microsoft.Authorization/permissions/read. Report clearly; stay closed.
		return false, "authenticated, but could not read effective permissions at root scope " +
			"(grant the SP Microsoft.Authorization/permissions/read): " + err.Error()
	}

	hasWrite, tooBroad := false, false
	for _, r := range raw {
		var p struct {
			Actions    []string `json:"actions"`
			NotActions []string `json:"notActions"`
		}
		if err := json.Unmarshal(r, &p); err != nil {
			continue
		}
		denied := lowerSet(p.NotActions)
		for _, a := range p.Actions {
			la := strings.ToLower(strings.TrimSpace(a))
			if la == "*" {
				tooBroad = true
			}
			if grantsRoleAssignmentWrite(la) && !negated(la, denied) {
				hasWrite = true
			}
		}
	}

	switch {
	case tooBroad:
		return false, "over-permissioned: the SP holds '*' (Owner-level). Assign it a roles-only custom role instead."
	case !hasWrite:
		return false, "SP cannot write role assignments at the root scope — grant Microsoft.Authorization/roleAssignments/write."
	default:
		return true, "verified: can write role assignments at " + rootScope + ", and is not over-permissioned."
	}
}

// grantsRoleAssignmentWrite reports whether a single (lowercased) action grants
// the ability to create role assignments.
func grantsRoleAssignmentWrite(la string) bool {
	switch la {
	case "microsoft.authorization/*",
		"microsoft.authorization/roleassignments/*",
		"microsoft.authorization/roleassignments/write":
		return true
	}
	return false
}

func lowerSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[strings.ToLower(strings.TrimSpace(s))] = true
	}
	return m
}

// negated reports whether a granting action is cancelled by a notActions entry.
func negated(la string, denied map[string]bool) bool {
	return denied["microsoft.authorization/*"] ||
		denied["microsoft.authorization/roleassignments/*"] ||
		denied["microsoft.authorization/roleassignments/write"] ||
		denied[la]
}
