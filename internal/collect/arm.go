package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/automationpi/govlens/internal/store"
)

type subscription struct {
	ID          string // subscription GUID
	DisplayName string
}

// subscriptions lists every subscription the SP can read (Reader via MG root).
func (c *Collector) subscriptions(ctx context.Context) ([]subscription, error) {
	raw, err := pagedValues(ctx, c.arm, armBase+"/subscriptions?api-version=2020-01-01")
	if err != nil {
		return nil, err
	}
	var out []subscription
	for _, r := range raw {
		var s struct {
			SubscriptionID string `json:"subscriptionId"`
			DisplayName    string `json:"displayName"`
		}
		_ = json.Unmarshal(r, &s)
		out = append(out, subscription{ID: s.SubscriptionID, DisplayName: s.DisplayName})
	}
	return out, nil
}

// subscriptionsUnderMG lists only the subscriptions beneath a management group,
// so collection can be scoped to one MG instead of the whole tenant.
func (c *Collector) subscriptionsUnderMG(ctx context.Context, mgID string) ([]subscription, error) {
	url := fmt.Sprintf("%s/providers/Microsoft.Management/managementGroups/%s/descendants?api-version=2020-05-01", armBase, mgID)
	raw, err := pagedValues(ctx, c.arm, url)
	if err != nil {
		return nil, err
	}
	var out []subscription
	for _, r := range raw {
		var d struct {
			Name       string `json:"name"`
			Type       string `json:"type"`
			Properties struct {
				DisplayName string `json:"displayName"`
			} `json:"properties"`
		}
		_ = json.Unmarshal(r, &d)
		if strings.HasSuffix(d.Type, "/subscriptions") { // skip child management groups
			out = append(out, subscription{ID: d.Name, DisplayName: d.Properties.DisplayName})
		}
	}
	return out, nil
}

// roleAssignments collects RBAC across a subscription, resolving role definition
// names (cached). Principal display names are resolved later in one Graph batch.
func (c *Collector) roleAssignments(ctx context.Context, sub subscription) ([]store.Assignment, error) {
	url := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01", armBase, sub.ID)
	raw, err := pagedValues(ctx, c.arm, url)
	if err != nil {
		return nil, err
	}
	var out []store.Assignment
	for _, r := range raw {
		var a struct {
			ID         string `json:"id"`
			Properties struct {
				RoleDefinitionID string    `json:"roleDefinitionId"`
				PrincipalID      string    `json:"principalId"`
				PrincipalType    string    `json:"principalType"`
				Scope            string    `json:"scope"`
				CreatedOn        time.Time `json:"createdOn"`
				CreatedBy        string    `json:"createdBy"`
			} `json:"properties"`
		}
		_ = json.Unmarshal(r, &a)
		role := c.roleName(ctx, a.Properties.RoleDefinitionID)
		out = append(out, store.Assignment{
			Domain:        "azure",
			Kind:          "rbac",
			Ident:         a.ID,
			Principal:     a.Properties.PrincipalID, // display resolved later
			PrincipalType: a.Properties.PrincipalType,
			Role:          role,
			Scope:         a.Properties.Scope,
			CreatedOn:     a.Properties.CreatedOn,
			CreatedBy:     a.Properties.CreatedBy,
		})
		c.principalIDs[a.Properties.PrincipalID] = struct{}{}
		if a.Properties.CreatedBy != "" {
			c.principalIDs[a.Properties.CreatedBy] = struct{}{} // resolve the creator too
		}
	}
	return out, nil
}

// resourceGroups lists the resource-group names under a subscription, for scoping
// grant requests below the subscription level.
func (c *Collector) resourceGroups(ctx context.Context, sub subscription) ([]string, error) {
	url := fmt.Sprintf("%s/subscriptions/%s/resourcegroups?api-version=2021-04-01", armBase, sub.ID)
	raw, err := pagedValues(ctx, c.arm, url)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range raw {
		var g struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(r, &g); err == nil && g.Name != "" {
			out = append(out, g.Name)
		}
	}
	return out, nil
}

// roleDefinitions lists the RBAC role definitions readable at a subscription
// scope (built-in + that sub's custom roles) and classifies each into a grant
// tier by its permissions. Feeds the self-service grant catalog.
func (c *Collector) roleDefinitions(ctx context.Context, sub subscription) ([]store.CatalogRole, error) {
	url := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01", armBase, sub.ID)
	raw, err := pagedValues(ctx, c.arm, url)
	if err != nil {
		return nil, err
	}
	var out []store.CatalogRole
	for _, r := range raw {
		var d struct {
			Name       string `json:"name"` // the roleDefinition guid
			Properties struct {
				RoleName    string `json:"roleName"`
				Description string `json:"description"`
				Type        string `json:"type"` // BuiltInRole | CustomRole
				Permissions []struct {
					Actions     []string `json:"actions"`
					DataActions []string `json:"dataActions"`
				} `json:"permissions"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(r, &d); err != nil || d.Name == "" {
			continue
		}
		var actions, dataActions []string
		for _, p := range d.Properties.Permissions {
			actions = append(actions, p.Actions...)
			dataActions = append(dataActions, p.DataActions...)
		}
		tier, reason := store.ClassifyTier(actions, dataActions)
		out = append(out, store.CatalogRole{
			RoleDefID:  d.Name,
			RoleName:   d.Properties.RoleName,
			RoleKind:   "rbac",
			IsCustom:   strings.EqualFold(d.Properties.Type, "CustomRole"),
			Deprecated: strings.Contains(strings.ToLower(d.Properties.RoleName+" "+d.Properties.Description), "deprecated"),
			Tier:       tier, TierReason: reason,
		})
	}
	return out, nil
}

// roleName resolves a roleDefinitionId to its display name, cached across subs.
func (c *Collector) roleName(ctx context.Context, roleDefID string) string {
	if roleDefID == "" {
		return ""
	}
	if n, ok := c.roleCache[roleDefID]; ok {
		return n
	}
	var d struct {
		Properties struct {
			RoleName string `json:"roleName"`
		} `json:"properties"`
	}
	name := roleDefID // fallback to the id if lookup fails
	if err := getJSON(ctx, c.arm, armBase+roleDefID+"?api-version=2022-04-01", &d); err == nil && d.Properties.RoleName != "" {
		name = d.Properties.RoleName
	}
	c.roleCache[roleDefID] = name
	return name
}

// policyCompliance summarizes Azure Policy compliance per assignment for a sub.
func (c *Collector) policyCompliance(ctx context.Context, sub subscription) ([]store.Finding, complianceCounts, error) {
	// Use the Microsoft.PolicyInsights provider namespace — its RBAC action
	// (Microsoft.PolicyInsights/policyStates/summarize/action) is what the
	// read-only GovLens Policy Reader custom role grants. (The Microsoft.
	// Authorization/policyStates path checks a different action no read role has.)
	url := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01", armBase, sub.ID)
	var res struct {
		Value []struct {
			PolicyAssignments []struct {
				PolicyAssignmentID string `json:"policyAssignmentId"`
				Results            struct {
					NonCompliantResources int `json:"nonCompliantResources"`
					ResourceDetails       []struct {
						ComplianceState string `json:"complianceState"`
						Count           int    `json:"count"`
					} `json:"resourceDetails"`
				} `json:"results"`
			} `json:"policyAssignments"`
		} `json:"value"`
	}
	if err := postJSON(ctx, c.arm, url, nil, &res); err != nil {
		return nil, complianceCounts{}, err
	}
	var findings []store.Finding
	var cc complianceCounts
	if len(res.Value) == 0 {
		return findings, cc, nil
	}
	for _, pa := range res.Value[0].PolicyAssignments {
		compliant, nonCompliant := 0, pa.Results.NonCompliantResources
		for _, rd := range pa.Results.ResourceDetails {
			if strings.EqualFold(rd.ComplianceState, "compliant") {
				compliant += rd.Count
			}
		}
		cc.compliant += compliant
		cc.nonCompliant += nonCompliant
		cc.total++
		status := "compliant"
		if nonCompliant > 0 {
			status = "non_compliant"
			cc.nonCompliantAssignments++
		}
		findings = append(findings, store.Finding{
			Domain:    "azure",
			Source:    "arm-policy",
			ControlID: pa.PolicyAssignmentID,
			Title:     assignmentName(pa.PolicyAssignmentID),
			Severity:  policySeverity(nonCompliant),
			Status:    status,
			Category:  "Policy",
			Scope:     "/subscriptions/" + sub.ID,
		})
	}
	return findings, cc, nil
}

type complianceCounts struct {
	compliant, nonCompliant, total, nonCompliantAssignments int
}

func assignmentName(id string) string {
	if i := strings.LastIndex(id, "/"); i >= 0 && i < len(id)-1 {
		return id[i+1:]
	}
	return id
}

func policySeverity(nonCompliant int) string {
	switch {
	case nonCompliant == 0:
		return "Info"
	case nonCompliant >= 10:
		return "High"
	case nonCompliant >= 3:
		return "Medium"
	default:
		return "Low"
	}
}
