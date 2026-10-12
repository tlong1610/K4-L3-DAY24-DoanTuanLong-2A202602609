# Rego unit test, chạy bằng:  opa test policy/ -v
package lab24.policy_test

import rego.v1

import data.lab24.policy

principals := {
	"support_l1": {"allowed_tools": ["search_docs"], "purposes": ["summarize-tickets", "support-reply"]},
	"dpo": {"allowed_tools": ["search_docs", "read_customer"], "purposes": ["summarize-tickets", "support-reply", "privacy-audit"]},
}

base := {
	"data_classification": "restricted",
	"request_purpose": "support-reply",
	"agent_owner": "lab24-agent/run-b",
	"delegation_depth": 0,
	"egress_enabled": false,
	"principal_id": "dpo",
	"requested_tool": "read_customer",
	"agent_scopes": ["search_docs", "read_customer"],
	"parent_scopes": [],
	"expires_at": "2099-01-01T00:00:00+00:00",
}

decide(changes) := policy.decide(object.union(base, changes), principals)

test_restricted_egress_denied_even_for_dpo if {
	d := decide({"egress_enabled": true})
	not d.allow
	contains(d.reason, "restricted + egress")
}

test_dpo_can_read_customer if {
	d := decide({})
	d.allow
	d.reason != ""
}

test_support_l1_cannot_read_customer if {
	d := decide({"principal_id": "support_l1"})
	not d.allow
	contains(d.reason, "principal.allowed_tools")
}

test_delegation_cannot_expand_parent_scope if {
	d := decide({"delegation_depth": 1, "parent_scopes": ["search_docs"]})
	not d.allow
	contains(d.reason, "parent_scopes")
}

test_expired_run_denied if {
	d := decide({"expires_at": "2000-01-01T00:00:00+00:00"})
	not d.allow
	contains(d.reason, "hết hạn")
}

test_malformed_expiry_denied if {
	not decide({"expires_at": "not-a-date"}).allow
	not decide({"expires_at": ""}).allow
}

test_unknown_principal_denied if {
	d := decide({"principal_id": "nobody"})
	not d.allow
	contains(d.reason, "principal không có")
}

test_wrong_purpose_denied if {
	not decide({"request_purpose": "marketing"}).allow
}

test_public_egress_allowed if {
	d := decide({
		"data_classification": "public", "egress_enabled": true,
		"requested_tool": "search_docs", "request_purpose": "summarize-tickets",
	})
	d.allow
}

test_every_decision_has_reason if {
	every changes in [{}, {"egress_enabled": true}, {"principal_id": "nobody"}, {"data_classification": "secret"}] {
		decide(changes).reason != ""
	}
}
