package collect

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
)

// ProvisionGrant creates a role assignment (adds access) for principalOid at scope
// with the given roleDefinition. Returns the created assignment's resource id.
// Requires Microsoft.Authorization/roleAssignments/write — the grant SP. It only
// ever CREATES; it never deletes or modifies existing assignments.
func ProvisionGrant(ctx context.Context, sp *SP, roleDefID, principalOid, principalType, scope string) (string, error) {
	arm, err := sp.Token(ctx, armScope)
	if err != nil {
		return "", err
	}
	if roleDefID == "" || principalOid == "" || scope == "" {
		return "", fmt.Errorf("grant requires roleDefID, principalOid and scope")
	}
	name, err := newGUID()
	if err != nil {
		return "", err
	}
	if principalType == "" {
		principalType = "User"
	}
	roleDefinitionID := scope + "/providers/Microsoft.Authorization/roleDefinitions/" + roleDefID
	url := armBase + scope + "/providers/Microsoft.Authorization/roleAssignments/" + name + "?api-version=2022-04-01"
	body := map[string]any{"properties": map[string]any{
		"roleDefinitionId": roleDefinitionID,
		"principalId":      principalOid,
		"principalType":    principalType,
	}}
	var res struct {
		ID string `json:"id"`
	}
	if err := putJSON(ctx, arm, url, body, &res); err != nil {
		return "", err
	}
	if res.ID == "" {
		res.ID = scope + "/providers/Microsoft.Authorization/roleAssignments/" + name
	}
	return res.ID, nil
}

func putJSON(ctx context.Context, token, url string, body, out any) error {
	raw, _ := json.Marshal(body)
	return request(ctx, http.MethodPut, token, url, raw, out)
}

// newGUID returns a random RFC-4122 v4 UUID for the assignment name.
func newGUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
