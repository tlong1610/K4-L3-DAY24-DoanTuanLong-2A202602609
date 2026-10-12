# Bonus — port agent/policy.py sang OPA/Rego.
#
# Cùng thứ tự rule với bản Python: chuỗi `else` đánh giá từ trên xuống, rule
# đầu tiên khớp quyết định kết quả. Không có nhánh nào khớp thì deny (fail closed).
#
#   opa eval -d policy/lab24.rego -I "data.lab24.policy.decisions" < input.json
#
# input = {"principals": <data/principals.json>, "cases": [<PolicyContext>, ...]}
package lab24.policy

import rego.v1

classifications := {"public", "internal", "restricted"}

decisions := [decide(c, input.principals) | some c in input.cases]

decision := decide(input.context, input.principals)

tool_name(c) := c.requested_tool if c.requested_tool != ""

else := "<không rõ tool>"

expiry_ns(c) := time.parse_rfc3339_ns(c.expires_at)

# Tầng scope mà tool còn thiếu, theo đúng thứ tự Python kiểm.
missing_layer(c, p) := "principal.allowed_tools" if {
	not c.requested_tool in p.allowed_tools
} else := "agent_scopes" if {
	not c.requested_tool in c.agent_scopes
} else := "parent_scopes" if {
	c.delegation_depth > 0
	not c.requested_tool in c.parent_scopes
}

decide(c, principals) := {"allow": false, "reason": sprintf("deny %s: dữ liệu restricted không được đi kèm egress (rule tối thiểu restricted + egress)", [tool_name(c)])} if {
	c.data_classification == "restricted"
	c.egress_enabled == true
} else := {"allow": false, "reason": sprintf("deny %s: classification không hợp lệ %v", [tool_name(c), c.data_classification])} if {
	not c.data_classification in classifications
} else := {"allow": false, "reason": sprintf("deny %s: thiếu hoặc sai expires_at %v (cần RFC 3339 có timezone)", [tool_name(c), c.expires_at])} if {
	not expiry_ns(c)
} else := {"allow": false, "reason": sprintf("deny %s: run đã hết hạn lúc %s", [tool_name(c), c.expires_at])} if {
	expiry_ns(c) <= time.now_ns()
} else := {"allow": false, "reason": sprintf("deny %s: principal không có trong data/principals.json (%v)", [tool_name(c), c.principal_id])} if {
	not principals[c.principal_id]
} else := {"allow": false, "reason": sprintf("deny %s: purpose %v không được phép cho principal %s", [tool_name(c), c.request_purpose, c.principal_id])} if {
	not c.request_purpose in principals[c.principal_id].purposes
} else := {"allow": false, "reason": "deny: thiếu requested_tool"} if {
	c.requested_tool == ""
} else := {"allow": false, "reason": sprintf("deny %s: delegation_depth âm (%d)", [tool_name(c), c.delegation_depth])} if {
	c.delegation_depth < 0
} else := {"allow": false, "reason": sprintf("deny %s: không nằm trong %s của %s (depth=%d)", [tool_name(c), missing_layer(c, principals[c.principal_id]), c.principal_id, c.delegation_depth])} if {
	missing_layer(c, principals[c.principal_id])
} else := {"allow": true, "reason": sprintf("allow %s: %s có quyền cho purpose %v, classification=%s, egress=%v, depth=%d", [tool_name(c), c.principal_id, c.request_purpose, c.data_classification, c.egress_enabled, c.delegation_depth])}
