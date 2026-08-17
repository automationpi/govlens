package store

import (
	"context"
	"strings"
	"time"
)

// ScopeRole is one scoped grant: scope '*' = tenant-wide, else a subscription id.
type ScopeRole struct {
	Scope string
	Role  string
}

// AppUser is an application user and their scoped role grants.
type AppUser struct {
	Email     string
	Name      string
	Grants    []ScopeRole
	CreatedAt time.Time
}

// UpsertAppUser records a user on login (updating their name).
func (s *Store) UpsertAppUser(ctx context.Context, email, name string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO app_users (email, name) VALUES ($1,$2)
		ON CONFLICT (email) DO UPDATE SET name = EXCLUDED.name, updated_at = now()`, email, name)
	return err
}

// UserGrants returns a user's grants as scope -> roles.
func (s *Store) UserGrants(ctx context.Context, email string) (map[string][]string, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT scope, role FROM user_scope_roles WHERE email=$1`, strings.ToLower(strings.TrimSpace(email)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var scope, role string
		if err := rows.Scan(&scope, &role); err != nil {
			return nil, err
		}
		out[scope] = append(out[scope], role)
	}
	return out, rows.Err()
}

// GrantScopedRole grants (email, scope, role); scope '*' is tenant-wide.
func (s *Store) GrantScopedRole(ctx context.Context, email, scope, role, by string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if _, err := s.Pool.Exec(ctx,
		`INSERT INTO app_users (email) VALUES ($1) ON CONFLICT DO NOTHING`, email); err != nil {
		return err
	}
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO user_scope_roles (email, scope, role, added_by) VALUES ($1,$2,$3,$4)
		ON CONFLICT DO NOTHING`, email, scope, role, by)
	return err
}

func (s *Store) RevokeScopedRole(ctx context.Context, email, scope, role string) error {
	_, err := s.Pool.Exec(ctx,
		`DELETE FROM user_scope_roles WHERE email=$1 AND scope=$2 AND role=$3`,
		strings.ToLower(strings.TrimSpace(email)), scope, role)
	return err
}

// ListUsers returns all app users with their scoped grants, for the admin page.
func (s *Store) ListUsers(ctx context.Context) ([]AppUser, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT u.email, COALESCE(u.name,''), u.created_at, COALESCE(r.scope,''), COALESCE(r.role,'')
		  FROM app_users u
		  LEFT JOIN user_scope_roles r ON r.email = u.email
		 ORDER BY u.email, r.scope, r.role`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var order []string
	byEmail := map[string]*AppUser{}
	for rows.Next() {
		var email, name, scope, role string
		var created time.Time
		if err := rows.Scan(&email, &name, &created, &scope, &role); err != nil {
			return nil, err
		}
		u := byEmail[email]
		if u == nil {
			u = &AppUser{Email: email, Name: name, CreatedAt: created}
			byEmail[email] = u
			order = append(order, email)
		}
		if role != "" {
			u.Grants = append(u.Grants, ScopeRole{Scope: scope, Role: role})
		}
	}
	out := make([]AppUser, 0, len(order))
	for _, e := range order {
		out = append(out, *byEmail[e])
	}
	return out, rows.Err()
}
