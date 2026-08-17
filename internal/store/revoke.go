package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// RevokeRequest is one row of the access-request workflow queue (revoke or grant).
type RevokeRequest struct {
	ID            int64
	Tenant        string
	Action        string // revoke | grant
	Kind          string
	TargetIdent   string
	Principal     string
	PrincipalType string
	PrincipalOid  string // grant: target principal object id
	Role          string
	RoleDefID     string // grant: roleDefinition guid to assign
	Scope         string
	Reason        string
	RequestedBy        string
	RequestedAt        time.Time
	RequestedDays      int
	RequestedPermanent bool // requester proposed no expiry
	Status             string // pending|approved|rejected|processing|done|failed|skipped|granted|expired
	DecidedBy     string
	DecidedAt     time.Time // zero if undecided
	DecisionNote  string
	ExpiresAt     time.Time // grant: zero = permanent
	ProcessedAt   time.Time // zero until the worker acts
	Result        string
}

// Decided reports whether the request has moved past review.
func (r RevokeRequest) Decided() bool { return !r.DecidedAt.IsZero() }

// Processed reports whether the worker has acted on the request.
func (r RevokeRequest) Processed() bool { return !r.ProcessedAt.IsZero() }

// TimelineStep is one stage in a request's lifecycle, for the audit timeline.
// State drives its dot colour: done | current | pending | rejected | failed | skipped.
type TimelineStep struct {
	Label string
	Actor string    // who acted (empty until reached)
	At    time.Time // when it happened (zero until reached)
	Note  string    // decision note / worker result / hint
	State string
}

// Timeline derives the ordered lifecycle of a request from its columns. It is the
// single source of truth for the UI "timemap": to add a workflow stage later
// (e.g. a ticket, a notification, a second-level sign-off) append a step here and
// every request page renders it automatically — no template change needed.
func (r RevokeRequest) Timeline() []TimelineStep {
	if r.Action == "grant" {
		return r.grantTimeline()
	}
	steps := []TimelineStep{{
		Label: "Requested", Actor: r.RequestedBy, At: r.RequestedAt,
		Note: r.Reason, State: "done",
	}}

	// Stage 2 — review.
	switch {
	case r.Status == "rejected":
		steps = append(steps, TimelineStep{Label: "Rejected", Actor: r.DecidedBy,
			At: r.DecidedAt, Note: r.DecisionNote, State: "rejected"})
		return steps // terminal — no execution stage
	case r.Status == "pending":
		steps = append(steps, TimelineStep{Label: "Awaiting review", State: "current"})
		steps = append(steps, TimelineStep{Label: "Removal", State: "pending"})
		return steps
	default: // approved / processing / done / failed / skipped — all were approved
		steps = append(steps, TimelineStep{Label: "Approved", Actor: r.DecidedBy,
			At: r.DecidedAt, Note: r.DecisionNote, State: "done"})
	}

	// Stage 3 — execution by the worker.
	switch r.Status {
	case "approved":
		steps = append(steps, TimelineStep{Label: "Queued for removal", State: "pending",
			Note: "picked up on the next worker cycle"})
	case "processing":
		steps = append(steps, TimelineStep{Label: "Removing…", State: "current"})
	case "done":
		steps = append(steps, TimelineStep{Label: "Removed", At: r.ProcessedAt,
			Note: r.Result, State: "done"})
	case "failed":
		steps = append(steps, TimelineStep{Label: "Failed", At: r.ProcessedAt,
			Note: r.Result, State: "failed"})
	case "skipped":
		steps = append(steps, TimelineStep{Label: "Skipped", At: r.ProcessedAt,
			Note: r.Result, State: "skipped"})
	}
	return steps
}

// grantTimeline is the lifecycle for a grant request:
// Requested → Approved(+expiry) → Granted → (Expires date / Expired).
func (r RevokeRequest) grantTimeline() []TimelineStep {
	steps := []TimelineStep{{
		Label: "Requested", Actor: r.RequestedBy, At: r.RequestedAt, Note: r.Reason, State: "done",
	}}
	switch {
	case r.Status == "rejected":
		steps = append(steps, TimelineStep{Label: "Rejected", Actor: r.DecidedBy,
			At: r.DecidedAt, Note: r.DecisionNote, State: "rejected"})
		return steps
	case r.Status == "pending":
		steps = append(steps, TimelineStep{Label: "Awaiting review", State: "current"})
		steps = append(steps, TimelineStep{Label: "Grant", State: "pending"})
		return steps
	default:
		note := r.DecisionNote
		if r.ExpiresAt.IsZero() {
			note = strings.TrimSpace(note + " · no expiry")
		}
		steps = append(steps, TimelineStep{Label: "Approved", Actor: r.DecidedBy,
			At: r.DecidedAt, Note: note, State: "done"})
	}

	switch r.Status {
	case "approved":
		steps = append(steps, TimelineStep{Label: "Queued to grant", State: "pending",
			Note: "provisioned on the next worker cycle"})
	case "processing":
		steps = append(steps, TimelineStep{Label: "Granting…", State: "current"})
	case "failed":
		steps = append(steps, TimelineStep{Label: "Failed", At: r.ProcessedAt, Note: r.Result, State: "failed"})
	case "skipped":
		steps = append(steps, TimelineStep{Label: "Skipped", At: r.ProcessedAt, Note: r.Result, State: "skipped"})
	case "granted":
		steps = append(steps, TimelineStep{Label: "Granted", At: r.ProcessedAt, Note: r.Result, State: "done"})
		if r.ExpiresAt.IsZero() {
			steps = append(steps, TimelineStep{Label: "No expiry", State: "done"})
		} else {
			steps = append(steps, TimelineStep{Label: "Expires", At: r.ExpiresAt, State: "current"})
		}
	case "expired":
		steps = append(steps, TimelineStep{Label: "Granted", At: r.DecidedAt, State: "done"})
		steps = append(steps, TimelineStep{Label: "Expired — revoked", At: r.ProcessedAt, Note: r.Result, State: "skipped"})
	}
	return steps
}

// NewRevokeRequest carries the fields needed to open a request.
type NewRevokeRequest struct {
	Tenant, Kind, TargetIdent          string
	Principal, PrincipalType, Role      string
	Scope, Reason, RequestedBy          string
	RunID                               int64
}

// CreateRevokeRequest opens a pending request for a target, idempotently: if an
// open request already exists for the same (tenant, target), it returns that id.
func (s *Store) CreateRevokeRequest(ctx context.Context, n NewRevokeRequest) (int64, error) {
	var existing int64
	err := s.Pool.QueryRow(ctx, `
		SELECT id FROM access_requests
		 WHERE tenant=$1 AND target_ident=$2 AND action='revoke'
		   AND status IN ('pending','approved','processing')
		 LIMIT 1`, n.Tenant, n.TargetIdent).Scan(&existing)
	if err == nil {
		return existing, nil // already open
	}
	if n.RequestedBy == "" {
		n.RequestedBy = "unknown"
	}
	var runID any
	if n.RunID > 0 {
		runID = n.RunID
	}
	var id int64
	err = s.Pool.QueryRow(ctx, `
		INSERT INTO access_requests
		  (tenant, run_id, kind, target_ident, principal, principal_type, role, scope, reason, requested_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		RETURNING id`,
		n.Tenant, runID, n.Kind, n.TargetIdent, n.Principal, n.PrincipalType,
		n.Role, n.Scope, n.Reason, n.RequestedBy).Scan(&id)
	return id, err
}

// RevokeRequests lists a tenant's requests (status="" for all), newest first.
func (s *Store) RevokeRequests(ctx context.Context, tenant, status string) ([]RevokeRequest, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, kind, target_ident, COALESCE(principal,''), COALESCE(principal_type,''),
		       COALESCE(role,''), COALESCE(scope,''), COALESCE(reason,''), requested_by, requested_at,
		       status, COALESCE(decided_by,''), COALESCE(decision_note,''), decided_at,
		       processed_at, COALESCE(result,'')
		  FROM access_requests
		 WHERE tenant=$1 AND action='revoke' AND ($2='' OR status=$2)
		 ORDER BY requested_at DESC`, tenant, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RevokeRequest
	for rows.Next() {
		var r RevokeRequest
		var decidedAt, processedAt *time.Time
		if err := rows.Scan(&r.ID, &r.Kind, &r.TargetIdent, &r.Principal, &r.PrincipalType,
			&r.Role, &r.Scope, &r.Reason, &r.RequestedBy, &r.RequestedAt,
			&r.Status, &r.DecidedBy, &r.DecisionNote, &decidedAt, &processedAt, &r.Result); err != nil {
			return nil, err
		}
		if decidedAt != nil {
			r.DecidedAt = *decidedAt
		}
		if processedAt != nil {
			r.ProcessedAt = *processedAt
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RevokeRequestScopeType returns a request's scope and principal type (for authz).
func (s *Store) RevokeRequestScopeType(ctx context.Context, id int64) (scope, ptype string, err error) {
	err = s.Pool.QueryRow(ctx,
		`SELECT COALESCE(scope,''), COALESCE(principal_type,'') FROM access_requests WHERE id=$1`, id).
		Scan(&scope, &ptype)
	return scope, ptype, err
}

// DecideRevokeRequest moves a pending request to approved or rejected. It only
// transitions from 'pending' — a second decision is a no-op error.
func (s *Store) DecideRevokeRequest(ctx context.Context, id int64, approve bool, decidedBy, note string) error {
	status := "rejected"
	if approve {
		status = "approved"
	}
	if decidedBy == "" {
		decidedBy = "unknown"
	}
	tag, err := s.Pool.Exec(ctx, `
		UPDATE access_requests
		   SET status=$2, decided_by=$3, decided_at=now(), decision_note=$4
		 WHERE id=$1 AND status='pending'`, id, status, decidedBy, note)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("request %d is not pending (already decided or missing)", id)
	}
	return nil
}

// ListRevokeByStatus returns all requests of a status across tenants (for the worker).
func (s *Store) ListRevokeByStatus(ctx context.Context, status string) ([]RevokeRequest, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, tenant, kind, target_ident, COALESCE(principal,''), COALESCE(principal_type,''),
		       COALESCE(role,''), COALESCE(scope,''), COALESCE(reason,''), requested_by, requested_at, status
		  FROM access_requests WHERE status=$1 AND action='revoke' ORDER BY id`, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RevokeRequest
	for rows.Next() {
		var r RevokeRequest
		if err := rows.Scan(&r.ID, &r.Tenant, &r.Kind, &r.TargetIdent, &r.Principal, &r.PrincipalType,
			&r.Role, &r.Scope, &r.Reason, &r.RequestedBy, &r.RequestedAt, &r.Status); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetRequestStatus transitions a request and records the worker result.
func (s *Store) SetRequestStatus(ctx context.Context, id int64, status, result string) error {
	_, err := s.Pool.Exec(ctx,
		`UPDATE access_requests SET status=$2, result=$3, processed_at=now() WHERE id=$1`, id, status, result)
	return err
}

// PendingRevokeCount counts requests awaiting review for a tenant.
func (s *Store) PendingRevokeCount(ctx context.Context, tenant string) int {
	var n int
	_ = s.Pool.QueryRow(ctx,
		`SELECT count(*) FROM access_requests WHERE tenant=$1 AND action='revoke' AND status='pending'`, tenant).Scan(&n)
	return n
}

// OpenRevokeTargets returns the set of target idents that already have an open
// request, so the UI can show "marked" instead of a fresh "revoke" action.
func (s *Store) OpenRevokeTargets(ctx context.Context, tenant string) (map[string]string, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT target_ident, status FROM access_requests
		 WHERE tenant=$1 AND action='revoke' AND status IN ('pending','approved','processing')`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var ident, status string
		if err := rows.Scan(&ident, &status); err != nil {
			return nil, err
		}
		out[ident] = status
	}
	return out, rows.Err()
}
