"""Helpers for displaying validated AI evidence references."""

def format_evidence_explanations(ai_result):
    if not isinstance(ai_result, dict) or ai_result.get("status") != "success":
        return []
    return [f"{item['evidence_id']}: {item['explanation']}"
            for item in ai_result.get("evidence", [])
            if isinstance(item, dict) and item.get("evidence_id") and item.get("explanation")]
