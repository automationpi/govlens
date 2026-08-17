package store

import (
	"context"
	"fmt"
	"time"
)

func errNotPending(id int64) error {
	return fmt.Errorf("request %d is not pending (already decided or missing)", id)
}

// RequestableRole is one catalog entry a user may request (post policy + overrides).
type RequestableRole struct {
	RoleDefID string
	RoleName  string
	Tier      string
}

// RequestableRoles lists the roles currently exposable for self-service, honoring
// tier policy and the allow/deny overlay, deprecated roles excluded. Ordered by
// tier (low first) then name.
func (s *Store) RequestableRoles(ctx context.Context, tenant string) ([]RequestableRole, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT c.role_def_id, c.role_name, c.tier
		  FROM role_catalog c
		  LEFT JOIN grant_tier_policy p ON p.tenant=c.tenant AND p.tier=c.tier
		  LEFT JOIN catalog_override o ON o.tenant=c.tenant AND o.role_def_id=c.role_def_id
		 WHERE c.tenant=$1 AND c.deprecated=false
		   AND COALESCE(o.decision,'') <> 'deny'
		   AND (o.decision='allow' OR p.self_service=true)
		 ORDER BY CASE c.tier WHEN 'low' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, c.role_name`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RequestableRole
	for rows.Next() {
		var r RequestableRole
		if err := rows.Scan(&r.RoleDefID, &r.RoleName, &r.Tier); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// IsGrantable re-checks (at provision time) that a role is still exposable for
// self-service under current policy + overrides — so a role locked down after
// approval is never provisioned. Fail-closed: unknown role → false.
func (s *Store) IsGrantable(ctx context.Context, tenant, roleDefID string) bool {
	var ok bool
	_ = s.Pool.QueryRow(ctx, `
		SELECT c.deprecated=false
		   AND COALESCE(o.decision,'') <> 'deny'
		   AND (o.decision='allow' OR p.self_service=true)
		  FROM role_catalog c
		  LEFT JOIN grant_tier_policy p ON p.tenant=c.tenant AND p.tier=c.tier
		  LEFT JOIN catalog_override o ON o.tenant=c.tenant AND o.role_def_id=c.role_def_id
		 WHERE c.tenant=$1 AND c.role_def_id=$2`, tenant, roleDefID).Scan(&ok)
	return ok
}

// TierOf returns the policy tier of a role (empty if unknown).
func (s *Store) TierOf(ctx context.Context, tenant, roleDefID string) string {
	var tier string
	_ = s.Pool.QueryRow(ctx,
		`SELECT tier FROM role_catalog WHERE tenant=$1 AND role_def_id=$2`, tenant, roleDefID).Scan(&tier)
	return tier
}

// NewGrantRequest carries the fields to open a self-service grant request.
type NewGrantRequest struct {
	Tenant             string
	RoleDefID          string
	RoleName           string
	Scope              string
	PrincipalOid       string // grant target (the requester's object id)
	PrincipalName      string
	RequestedBy        string
	Reason             string
	RequestedDays      int
	RequestedPermanent bool
}

// CreateGrantRequest opens a pending grant request.
func (s *Store) CreateGrantRequest(ctx context.Context, n NewGrantRequest) (int64, error) {
	if n.RequestedBy == "" {
		n.RequestedBy = "unknown"
	}
	var days any
	if n.RequestedDays > 0 {
		days = n.RequestedDays
	}
	var id int64
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO access_requests
		  (tenant, action, kind, target_ident, principal, principal_type, principal_oid,
		   role, role_def_id, scope, reason, requested_by, requested_days, requested_permanent)
		VALUES ($1,'grant','rbac','',$2,'User',$3,$4,$5,$6,$7,$8,$9,$10)
		RETURNING id`,
		n.Tenant, n.PrincipalName, n.PrincipalOid, n.RoleName, n.RoleDefID,
		n.Scope, n.Reason, n.RequestedBy, days, n.RequestedPermanent).Scan(&id)
	return id, err
}

const grantCols = `id, tenant, action, kind, target_ident, COALESCE(principal,''), COALESCE(principal_type,''),
	COALESCE(principal_oid,''), COALESCE(role,''), COALESCE(role_def_id,''), COALESCE(scope,''),
	COALESCE(reason,''), requested_by, requested_at, COALESCE(requested_days,0), COALESCE(requested_permanent,false),
	status, COALESCE(decided_by,''), COALESCE(decision_note,''), decided_at, expires_at, processed_at, COALESCE(result,'')`

func scanGrant(rows interface {
	Scan(...any) error
}) (RevokeRequest, error) {
	var r RevokeRequest
	var decidedAt, expiresAt, processedAt *time.Time
	err := rows.Scan(&r.ID, &r.Tenant, &r.Action, &r.Kind, &r.TargetIdent, &r.Principal, &r.PrincipalType,
		&r.PrincipalOid, &r.Role, &r.RoleDefID, &r.Scope, &r.Reason, &r.RequestedBy, &r.RequestedAt,
		&r.RequestedDays, &r.RequestedPermanent, &r.Status, &r.DecidedBy, &r.DecisionNote, &decidedAt, &expiresAt, &processedAt, &r.Result)
	if err != nil {
		return r, err
	}
	if decidedAt != nil {
		r.DecidedAt = *decidedAt
	}
	if expiresAt != nil {
		r.ExpiresAt = *expiresAt
	}
	if processedAt != nil {
		r.ProcessedAt = *processedAt
	}
	return r, nil
}

// GrantRequests lists a tenant's grant requests (status="" for all), newest first.
func (s *Store) GrantRequests(ctx context.Context, tenant, status string) ([]RevokeRequest, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT `+grantCols+` FROM access_requests
		  WHERE tenant=$1 AND action='grant' AND ($2='' OR status=$2)
		  ORDER BY requested_at DESC`, tenant, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RevokeRequest
	for rows.Next() {
		r, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListGrantByStatus returns grant requests of a status across tenants (for the worker).
func (s *Store) ListGrantByStatus(ctx context.Context, status string) ([]RevokeRequest, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT `+grantCols+` FROM access_requests
		  WHERE action='grant' AND status=$1 ORDER BY id`, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RevokeRequest
	for rows.Next() {
		r, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetAccessRequest fetches one request (grant or revoke) by id.
func (s *Store) GetAccessRequest(ctx context.Context, id int64) (RevokeRequest, error) {
	row := s.Pool.QueryRow(ctx, `SELECT `+grantCols+` FROM access_requests WHERE id=$1`, id)
	return scanGrant(row)
}

// RoleCatalogName returns a role's display name and tier from the catalog.
func (s *Store) RoleCatalogName(ctx context.Context, tenant, roleDefID string) (name, tier string) {
	_ = s.Pool.QueryRow(ctx,
		`SELECT role_name, tier FROM role_catalog WHERE tenant=$1 AND role_def_id=$2`, tenant, roleDefID).
		Scan(&name, &tier)
	return name, tier
}

// DecideGrantRequest approves/rejects a pending grant. On approve, expiresAt sets
// the grant's lifetime (nil = permanent). Only transitions from 'pending'.
func (s *Store) DecideGrantRequest(ctx context.Context, id int64, approve bool, decidedBy, note string, expiresAt *time.Time) error {
	status := "rejected"
	if approve {
		status = "approved"
	}
	if decidedBy == "" {
		decidedBy = "unknown"
	}
	tag, err := s.Pool.Exec(ctx, `
		UPDATE access_requests
		   SET status=$2, decided_by=$3, decided_at=now(), decision_note=$4, expires_at=$5
		 WHERE id=$1 AND action='grant' AND status='pending'`, id, status, decidedBy, note, expiresAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errNotPending(id)
	}
	return nil
}

// SetGrantProvisioned records a successful provision: stores the created assignment
// id and flips to 'granted'.
func (s *Store) SetGrantProvisioned(ctx context.Context, id int64, assignmentIdent string) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE access_requests
		   SET status='granted', target_ident=$2, result='granted', processed_at=now()
		 WHERE id=$1`, id, assignmentIdent)
	return err
}

// ExpiredGrants returns granted, time-bound grants whose expiry has passed.
func (s *Store) ExpiredGrants(ctx context.Context) ([]RevokeRequest, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT `+grantCols+` FROM access_requests
		  WHERE action='grant' AND status='granted' AND expires_at IS NOT NULL AND expires_at < now()
		  ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RevokeRequest
	for rows.Next() {
		r, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// MarkGrantExpired flips a granted row to 'expired' after its revocation is enqueued.
func (s *Store) MarkGrantExpired(ctx context.Context, id int64, result string) error {
	_, err := s.Pool.Exec(ctx,
		`UPDATE access_requests SET status='expired', result=$2, processed_at=now() WHERE id=$1`, id, result)
	return err
}

// EnqueueExpiryRevoke opens an already-APPROVED revoke request for an assignment a
// grant created, so the remediator (which holds delete) removes it. Idempotent on
// the open-target unique index.
func (s *Store) EnqueueExpiryRevoke(ctx context.Context, g RevokeRequest) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO access_requests
		  (tenant, action, kind, target_ident, principal, principal_type, role, scope, reason,
		   requested_by, status, decided_by, decided_at, decision_note)
		VALUES ($1,'revoke',$2,$3,$4,$5,$6,$7,'auto-expiry of self-service grant',
		        'grant-expiry','approved','grant-expiry',now(),'expired grant auto-revocation')
		ON CONFLICT DO NOTHING`,
		g.Tenant, g.Kind, g.TargetIdent, g.Principal, g.PrincipalType, g.Role, g.Scope)
	return err
}

// HistoryQuery scopes a request-history lookup by viewer visibility, search, and page.
type HistoryQuery struct {
	ViewerEmail   string
	SeeAll        bool     // global admin/approver → sees everything
	ScopedSubs    []string // subscription ids the viewer administers/approves
	Search        string
	Limit, Offset int
}

// AccessHistory returns decided requests (grant + revoke) the viewer is allowed to
// see, newest first, paginated, with a total count for the pager. Visibility: own
// requests, anything when SeeAll, or requests whose subscription is in ScopedSubs.
func (s *Store) AccessHistory(ctx context.Context, tenant string, q HistoryQuery) ([]RevokeRequest, int, error) {
	if q.ScopedSubs == nil {
		q.ScopedSubs = []string{}
	}
	const where = `tenant=$1 AND status <> 'pending'
		AND ($2 OR requested_by = $3 OR split_part(scope,'/',3) = ANY($4))
		AND ($5='' OR principal ILIKE '%'||$5||'%' OR role ILIKE '%'||$5||'%'
		     OR scope ILIKE '%'||$5||'%' OR requested_by ILIKE '%'||$5||'%')`
	base := []any{tenant, q.SeeAll, q.ViewerEmail, q.ScopedSubs, q.Search}

	var total int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM access_requests WHERE `+where, base...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.Pool.Query(ctx,
		`SELECT `+grantCols+` FROM access_requests WHERE `+where+
			` ORDER BY requested_at DESC LIMIT $6 OFFSET $7`,
		append(append([]any{}, base...), q.Limit, q.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []RevokeRequest
	for rows.Next() {
		r, err := scanGrant(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// PendingGrantCount counts grant requests awaiting review for a tenant.
func (s *Store) PendingGrantCount(ctx context.Context, tenant string) int {
	var n int
	_ = s.Pool.QueryRow(ctx,
		`SELECT count(*) FROM access_requests WHERE tenant=$1 AND action='grant' AND status='pending'`, tenant).Scan(&n)
	return n
}
