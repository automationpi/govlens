package store

import (
	"context"
	"strings"
	"time"
)

type ProtectedRole struct {
	Role    string
	AddedBy string
	AddedAt time.Time
}

// ProtectedRoles lists roles that may not be revoked, for the admin page.
func (s *Store) ProtectedRoles(ctx context.Context) ([]ProtectedRole, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT role, COALESCE(added_by,''), added_at FROM protected_roles ORDER BY role`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProtectedRole
	for rows.Next() {
		var p ProtectedRole
		if err := rows.Scan(&p.Role, &p.AddedBy, &p.AddedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ProtectedRoleSet returns a fast lookup set of protected role names.
func (s *Store) ProtectedRoleSet(ctx context.Context) (map[string]bool, error) {
	list, err := s.ProtectedRoles(ctx)
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, p := range list {
		set[p.Role] = true
	}
	return set, nil
}

func (s *Store) AddProtectedRole(ctx context.Context, role, by string) error {
	role = strings.TrimSpace(role)
	if role == "" {
		return nil
	}
	_, err := s.Pool.Exec(ctx,
		`INSERT INTO protected_roles (role, added_by) VALUES ($1,$2) ON CONFLICT DO NOTHING`, role, by)
	return err
}

func (s *Store) RemoveProtectedRole(ctx context.Context, role string) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM protected_roles WHERE role=$1`, role)
	return err
}

// IsRoleProtected reports whether a role is on the non-revocable list.
func (s *Store) IsRoleProtected(ctx context.Context, role string) bool {
	var n int
	_ = s.Pool.QueryRow(ctx, `SELECT count(*) FROM protected_roles WHERE role=$1`, role).Scan(&n)
	return n > 0
}

// --- per-principal-type policy ---

// TypePolicies returns the configured policy for each principal type.
func (s *Store) TypePolicies(ctx context.Context) (map[string]string, error) {
	rows, err := s.Pool.Query(ctx, `SELECT principal_type, policy FROM type_policies`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var t, p string
		if err := rows.Scan(&t, &p); err != nil {
			return nil, err
		}
		out[t] = p
	}
	return out, rows.Err()
}

// TypePolicy returns "" (allow), "blocked", or "global" for a principal type.
func (s *Store) TypePolicy(ctx context.Context, ptype string) string {
	var p string
	_ = s.Pool.QueryRow(ctx, `SELECT policy FROM type_policies WHERE principal_type=$1`, ptype).Scan(&p)
	return p
}

// SetTypePolicy sets (blocked|global) or clears (allow/empty) a type's policy.
func (s *Store) SetTypePolicy(ctx context.Context, ptype, policy, by string) error {
	if policy == "" || policy == "allow" {
		_, err := s.Pool.Exec(ctx, `DELETE FROM type_policies WHERE principal_type=$1`, ptype)
		return err
	}
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO type_policies (principal_type, policy, set_by) VALUES ($1,$2,$3)
		ON CONFLICT (principal_type) DO UPDATE SET policy = EXCLUDED.policy, set_by = EXCLUDED.set_by, set_at = now()`,
		ptype, policy, by)
	return err
}
