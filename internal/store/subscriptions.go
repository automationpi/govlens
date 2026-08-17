package store

import (
	"context"
	"strings"
)

// Subscription is an Azure subscription seen by the collector.
type Subscription struct {
	ID   string
	Name string
}

// UpsertSubscription records a subscription's id + name for a tenant.
func (s *Store) UpsertSubscription(ctx context.Context, tenant, subID, name string) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO subscriptions (tenant, sub_id, name) VALUES ($1,$2,$3)
		ON CONFLICT (tenant, sub_id) DO UPDATE SET name = EXCLUDED.name`, tenant, subID, name)
	return err
}

// Subscriptions lists a tenant's subscriptions (name, id) sorted by name.
func (s *Store) Subscriptions(ctx context.Context, tenant string) ([]Subscription, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT sub_id, COALESCE(NULLIF(name,''), sub_id) FROM subscriptions WHERE tenant=$1 ORDER BY 2`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Subscription
	for rows.Next() {
		var sub Subscription
		if err := rows.Scan(&sub.ID, &sub.Name); err != nil {
			return nil, err
		}
		out = append(out, sub)
	}
	return out, rows.Err()
}

// ResourceGroupsBySub returns the tenant's resource groups keyed by subscription id.
func (s *Store) ResourceGroupsBySub(ctx context.Context, tenant string) (map[string][]string, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT sub_id, name FROM resource_groups WHERE tenant=$1 ORDER BY sub_id, name`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var sub, name string
		if err := rows.Scan(&sub, &name); err != nil {
			return nil, err
		}
		out[sub] = append(out[sub], name)
	}
	return out, rows.Err()
}

// ResourceGroupExists reports whether a resource group is known for a subscription.
func (s *Store) ResourceGroupExists(ctx context.Context, tenant, subID, name string) bool {
	var ok bool
	_ = s.Pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM resource_groups WHERE tenant=$1 AND sub_id=$2 AND name=$3)`,
		tenant, subID, name).Scan(&ok)
	return ok
}

// SubscriptionOfScope extracts the subscription id from an ARM scope string
// ("/subscriptions/{id}/..."), or "" if the scope isn't under a subscription.
func SubscriptionOfScope(scope string) string {
	const p = "/subscriptions/"
	i := strings.Index(strings.ToLower(scope), p)
	if i < 0 {
		return ""
	}
	rest := scope[i+len(p):]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		return rest[:j]
	}
	return rest
}
