package store

import (
	"context"
	"time"
)

// ReconcileDrift diffs the two most recent runs for a tenant and materializes each
// out-of-band "added" role assignment (one not attributable to a GovLens request)
// as a pending action='drift' request for approver review.
//
// Idempotent and safe:
//   - only kinds collected in BOTH runs are diffed, so a collector that skipped one
//     run does not look like a mass add;
//   - an add is skipped when any access_request already references its assignment id
//     (our own provisioned grants, an existing drift, or a revoke), or matches an
//     in-flight grant by principal+role+scope;
//   - the uq_revoke_open_target unique index plus ON CONFLICT DO NOTHING stop a
//     second pending drift for the same assignment across collection cycles.
//
// Returns the number of new drift requests created.
func (s *Store) ReconcileDrift(ctx context.Context, tenant string) (int, error) {
	runs, err := s.Runs(ctx, tenant)
	if err != nil || len(runs) < 2 {
		return 0, err
	}
	newer, older := runs[len(runs)-1], runs[len(runs)-2]

	var allowed []string
	for kind, src := range kindSource {
		if hasSource(newer, src) && hasSource(older, src) {
			allowed = append(allowed, kind)
		}
	}
	if len(allowed) == 0 {
		return 0, nil
	}

	tag, err := s.Pool.Exec(ctx, `
		INSERT INTO access_requests
		  (tenant, run_id, action, kind, target_ident, principal, principal_type,
		   role, scope, reason, requested_by, status)
		SELECT $1, $2, 'drift', a.kind, a.ident,
		       a.principal, a.principal_type, a.role, a.scope,
		       'created '
		         || COALESCE(to_char(a.created_on,'YYYY-MM-DD HH24:MI"Z"'), 'time unknown')
		         || ' by ' || COALESCE(NULLIF(a.created_by_name,''), NULLIF(a.created_by,''), 'unresolved creator'),
		       'out-of-band', 'pending'
		  FROM assignments a
		 WHERE a.run_id = $2
		   AND a.kind = ANY($4)
		   AND NOT EXISTS (
		        SELECT 1 FROM assignments p
		         WHERE p.run_id = $3 AND p.kind = a.kind AND p.ident = a.ident)
		   AND NOT EXISTS (
		        SELECT 1 FROM access_requests r
		         WHERE r.tenant = $1
		           AND ( r.target_ident = a.ident
		              OR ( r.action = 'grant'
		                   AND r.status IN ('approved','processing','granted')
		                   AND COALESCE(r.principal,'') = COALESCE(a.principal,'')
		                   AND COALESCE(r.role,'')      = COALESCE(a.role,'')
		                   AND COALESCE(r.scope,'')     = COALESCE(a.scope,'') ) ))
		ON CONFLICT DO NOTHING`,
		tenant, newer.ID, older.ID, allowed)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// DriftRequests returns action='drift' requests for a tenant (status "" = all).
func (s *Store) DriftRequests(ctx context.Context, tenant, status string) ([]RevokeRequest, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, kind, target_ident, COALESCE(principal,''), COALESCE(principal_type,''),
		       COALESCE(role,''), COALESCE(scope,''), COALESCE(reason,''), requested_by, requested_at,
		       status, COALESCE(decided_by,''), COALESCE(decision_note,''), decided_at,
		       processed_at, COALESCE(result,'')
		  FROM access_requests
		 WHERE tenant=$1 AND action='drift' AND ($2='' OR status=$2)
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
		r.Action = "drift"
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

// DecideDrift resolves a pending drift request. Approve blesses the out-of-band
// access: with an expiry it becomes governed (status='granted', swept at expiry like
// a grant); without one it is accepted as-is (status='blessed'). Reject records the
// decision and enqueues an approved revoke so the remediator removes the assignment
// (the same mechanism grant-expiry uses), leaving a clean two-row audit trail.
func (s *Store) DecideDrift(ctx context.Context, id int64, approve bool, decidedBy, note string, expiresAt *time.Time) error {
	if !approve {
		return s.rejectDriftAndEnqueueRemoval(ctx, id, decidedBy, note)
	}
	if expiresAt != nil {
		_, err := s.Pool.Exec(ctx, `
			UPDATE access_requests
			   SET status='granted', expires_at=$4, decided_by=$2, decided_at=now(),
			       decision_note=$3, result='blessed (out-of-band, governed)'
			 WHERE id=$1 AND action='drift' AND status='pending'`, id, decidedBy, note, *expiresAt)
		return err
	}
	_, err := s.Pool.Exec(ctx, `
		UPDATE access_requests
		   SET status='blessed', decided_by=$2, decided_at=now(),
		       decision_note=$3, result='blessed (out-of-band, accepted)'
		 WHERE id=$1 AND action='drift' AND status='pending'`, id, decidedBy, note)
	return err
}

// driftTimeline renders the lifecycle of an out-of-band change: detected, reviewed,
// then either kept (optionally governed with an expiry) or rejected + queued for removal.
func (r RevokeRequest) driftTimeline() []TimelineStep {
	steps := []TimelineStep{{
		Label: "Detected out-of-band", Actor: r.RequestedBy, At: r.RequestedAt,
		Note: r.Reason, State: "done",
	}}
	switch r.Status {
	case "pending":
		return append(steps, TimelineStep{Label: "Awaiting review", State: "current"})
	case "rejected":
		steps = append(steps, TimelineStep{Label: "Rejected", Actor: r.DecidedBy,
			At: r.DecidedAt, Note: r.DecisionNote, State: "rejected"})
		return append(steps, TimelineStep{Label: "Removal queued", State: "pending",
			Note: "a revoke was enqueued to remove this access"})
	case "blessed":
		return append(steps, TimelineStep{Label: "Approved — kept", Actor: r.DecidedBy,
			At: r.DecidedAt, Note: r.DecisionNote, State: "done"})
	case "granted": // blessed with an expiry: now a governed, auto-expiring grant
		steps = append(steps, TimelineStep{Label: "Approved — governed", Actor: r.DecidedBy,
			At: r.DecidedAt, Note: r.DecisionNote, State: "done"})
		if !r.ExpiresAt.IsZero() {
			steps = append(steps, TimelineStep{Label: "Expires", At: r.ExpiresAt, State: "current"})
		}
		return steps
	case "expired":
		steps = append(steps, TimelineStep{Label: "Approved — governed", Actor: r.DecidedBy,
			At: r.DecidedAt, Note: r.DecisionNote, State: "done"})
		return append(steps, TimelineStep{Label: "Expired", At: r.ProcessedAt, State: "done"})
	default:
		return append(steps, TimelineStep{Label: "Reviewed", Actor: r.DecidedBy,
			At: r.DecidedAt, Note: r.DecisionNote, State: "done"})
	}
}

func (s *Store) rejectDriftAndEnqueueRemoval(ctx context.Context, id int64, decidedBy, note string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var tenant, kind, ident, principal, ptype, role, scope string
	if err := tx.QueryRow(ctx, `
		UPDATE access_requests
		   SET status='rejected', decided_by=$2, decided_at=now(), decision_note=$3,
		       result='rejected (out-of-band); removal queued'
		 WHERE id=$1 AND action='drift' AND status='pending'
		 RETURNING tenant, kind, target_ident, COALESCE(principal,''), COALESCE(principal_type,''),
		           COALESCE(role,''), COALESCE(scope,'')`,
		id, decidedBy, note).Scan(&tenant, &kind, &ident, &principal, &ptype, &role, &scope); err != nil {
		return err
	}
	// The drift row is now 'rejected' (not open), so this approved revoke does not
	// collide with the uq_revoke_open_target unique index. The remediator picks it up.
	if _, err := tx.Exec(ctx, `
		INSERT INTO access_requests
		  (tenant, action, kind, target_ident, principal, principal_type, role, scope,
		   reason, requested_by, status)
		VALUES ($1,'revoke',$2,$3,$4,$5,$6,$7,'out-of-band access rejected in drift review',$8,'approved')
		ON CONFLICT DO NOTHING`,
		tenant, kind, ident, principal, ptype, role, scope, decidedBy); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
