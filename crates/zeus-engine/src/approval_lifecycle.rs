//! Atomic membership changes for pending transfer approvals.
use std::collections::BTreeSet;
use std::path::Path;
use zeus_journal::{JournalError, JournalResult, WriteTxn};
use zeus_types::event::{ApprovalDecidedData, ApprovalRequestedData};
use zeus_types::*;

/// Remove a canceled job while the same transaction commits S32.
pub(crate) fn leave_pending(
    tx: &mut dyn WriteTxn,
    mut approval: Approval,
    leaving: JobId,
    now: Timestamp,
) -> JournalResult<Vec<EventPayload>> {
    let mut seen = BTreeSet::new();
    let mut remaining = Vec::new();
    if let Some(ids) = approval
        .facts
        .as_ref()
        .and_then(|facts| facts.get("transfer"))
        .and_then(|transfer| transfer["job_ids"].as_array())
    {
        if ids.len() > 50 {
            return Err(JournalError::Invariant("approval membership exceeds limit"));
        }
        for value in ids {
            let id = value
                .as_str()
                .and_then(|id| id.parse::<JobId>().ok())
                .ok_or(JournalError::Invariant("invalid approval member"))?;
            if id != leaving
                && seen.insert(id)
                && let Some(record) = tx.job(id)?
                && record.job.state == JobState::AwaitingApproval
                && record.job.approval_id == Some(approval.id)
            {
                remaining.push(record);
            }
        }
    } else {
        // Legacy approval ports did not attach transfer facts. Preserve their existing batch behavior.
        remaining = tx
            .jobs(&zeus_journal::JobFilter {
                states: Some(vec![JobState::AwaitingApproval]),
                after: None,
                limit: None,
            })?
            .into_iter()
            .filter(|record| {
                record.job.id != leaving && record.job.approval_id == Some(approval.id)
            })
            .collect();
        if !remaining.is_empty() {
            return Ok(Vec::new());
        }
    }
    if remaining.is_empty() {
        return Ok(vec![cancel_in(tx, &mut approval, now, "job_canceled")?]);
    }
    let mut events = Vec::new();
    let revision = match approval
        .revision
        .and_then(|revision| revision.checked_add(1))
    {
        Some(revision) if revision <= 1000 => revision,
        _ => {
            // Exhausted revisions must never make cancellation unavailable. Replace the old binding
            // atomically and preserve its deadline, scopes and every remaining job's grant hints.
            let mut old = approval.clone();
            events.push(cancel_in(tx, &mut old, now, "request_withdrawn")?);
            approval.id = IdGenerator::new().approval_id();
            approval.created_at = now;
            for record in &mut remaining {
                record.job.approval_id = Some(approval.id);
                tx.put_job(record)?;
            }
            1
        }
    };
    let mut facts = serde_json::Value::Object(
        approval
            .facts
            .take()
            .ok_or(JournalError::Invariant("batch facts missing"))?,
    );
    let mut total = 0u64;
    let mut known = false;
    let mut unknown = 0u32;
    let mut directories = Vec::new();
    let mut directory_set = BTreeSet::new();
    let ids: Vec<_> = remaining.iter().map(|record| record.job.id).collect();
    for record in &remaining {
        if let Some(bytes) = record.job.spec.expected_size {
            total = total
                .checked_add(bytes)
                .ok_or(JournalError::Invariant("approval size overflow"))?;
            known = true;
        } else {
            unknown += 1;
        }
        if let Some(directory) = Path::new(&record.internal.dest_path).parent() {
            let directory = directory.to_string_lossy().into_owned();
            if directory_set.insert(directory.clone()) && directories.len() < 8 {
                directories.push(directory);
            }
        }
    }
    let total = known.then_some(total);
    facts["transfer"] = serde_json::json!({
        "job_ids": ids, "total_bytes": total, "unknown_size_count": unknown,
        "dest_dirs": directories,
        "dest_dirs_omitted": directory_set.len().saturating_sub(directories.len())
    });
    let items = facts["items"]
        .as_array_mut()
        .ok_or(JournalError::Invariant("approval items missing"))?;
    // Retain the original daemon-sanitized sample; do not manufacture new remote display strings here.
    items.retain(|item| {
        item["job_id"]
            .as_str()
            .and_then(|id| id.parse::<JobId>().ok())
            .is_some_and(|id| ids.contains(&id))
    });
    let omitted = ids.len().saturating_sub(items.len());
    approval.summary.title = items
        .first()
        .and_then(|item| item["untrusted_name"].as_str())
        .unwrap_or("Review remaining downloads")
        .to_owned();
    approval.summary.url_redacted = items
        .first()
        .and_then(|item| item["untrusted_url"].as_str())
        .map(|url| RedactedUrl::from_raw(url, RedactMode::Strict));
    facts["items_omitted"] = serde_json::json!(omitted);
    facts["approval_id"] = serde_json::json!(approval.id);
    facts["revision"] = serde_json::json!(revision);
    facts["issued_at"] = serde_json::json!(now);
    approval.job_id = ids.first().copied();
    approval.summary.total_bytes = total;
    approval.revision = Some(revision);
    approval.request_hash = Some(
        zeus_verify::canonical::request_hash(&facts)
            .map_err(|_| JournalError::Invariant("approval facts cannot be canonicalized"))?,
    );
    approval.facts = facts.as_object().cloned();
    tx.put_approval(&approval)?;
    let mut public = approval;
    public.facts = None;
    public.agent_says = None;
    events.push(ApprovalRequestedData { approval: public }.into());
    Ok(events)
}

fn cancel_in(
    tx: &mut dyn WriteTxn,
    approval: &mut Approval,
    now: Timestamp,
    reason: &str,
) -> JournalResult<EventPayload> {
    approval.state = ApprovalState::Canceled;
    approval.decided_at = Some(now);
    approval.decision = Some(Decision {
        outcome: DecisionOutcome::Cancel,
        scope: None,
        actor: Actor::system(),
        grant_id: None,
    });
    tx.put_approval(approval)?;
    if approval.revision.is_some() && approval.request_hash.is_some() {
        tx.put_approval_decision(
            approval.id,
            &serde_json::json!({
                "approval_id": approval.id, "revision": approval.revision,
                "request_hash": approval.request_hash, "outcome": "cancel",
                "actor": Actor::system(), "decided_at": now,
                "grant_ids": [], "system_reason": reason
            }),
        )?;
    }
    Ok(ApprovalDecidedData {
        approval_id: approval.id,
        kind: approval.kind,
        outcome: DecisionOutcome::Cancel,
        scope: None,
        actor: Actor::system(),
        grant_id: None,
    }
    .into())
}
