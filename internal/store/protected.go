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

// --- protected principals (by exact name or a trailing-'*' wildcard pattern) ---

type ProtectedPrincipal struct {
	Pattern string
	AddedBy string
	AddedAt time.Time
}

// ProtectedPrincipals lists principals (or name patterns) that may not be revoked.
func (s *Store) ProtectedPrincipals(ctx context.Context) ([]ProtectedPrincipal, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT pattern, COALESCE(added_by,''), added_at FROM protected_principals ORDER BY pattern`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProtectedPrincipal
	for rows.Next() {
		var p ProtectedPrincipal
		if err := rows.Scan(&p.Pattern, &p.AddedBy, &p.AddedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ProtectedPrincipalPatterns returns just the patterns, for matching.
func (s *Store) ProtectedPrincipalPatterns(ctx context.Context) ([]string, error) {
	list, err := s.ProtectedPrincipals(ctx)
	if err != nil {
		return nil, err
	}
	pats := make([]string, 0, len(list))
	for _, p := range list {
		pats = append(pats, p.Pattern)
	}
	return pats, nil
}

func (s *Store) AddProtectedPrincipal(ctx context.Context, pattern, by string) error {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil
	}
	_, err := s.Pool.Exec(ctx,
		`INSERT INTO protected_principals (pattern, added_by) VALUES ($1,$2) ON CONFLICT DO NOTHING`, pattern, by)
	return err
}

func (s *Store) RemoveProtectedPrincipal(ctx context.Context, pattern string) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM protected_principals WHERE pattern=$1`, pattern)
	return err
}

// MatchProtectedPrincipal reports whether a principal name matches any protected
// pattern. Matching is case-insensitive; a trailing '*' is a prefix wildcard, so
// "Microsoft*" protects every principal whose name starts with "Microsoft".
func MatchProtectedPrincipal(name string, patterns []string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		switch {
		case p == "":
			continue
		case strings.HasSuffix(p, "*"):
			if strings.HasPrefix(n, strings.TrimSuffix(p, "*")) {
				return true
			}
		case n == p:
			return true
		}
	}
	return false
}

// IsPrincipalProtected reports whether a principal name is protected from revoke.
func (s *Store) IsPrincipalProtected(ctx context.Context, name string) bool {
	pats, err := s.ProtectedPrincipalPatterns(ctx)
	if err != nil {
		return false
	}
	return MatchProtectedPrincipal(name, pats)
}
