"""Human-in-the-loop response recommendation helpers."""

def get_recommendations(ai_result):
    if not isinstance(ai_result, dict) or ai_result.get("status") != "success":
        return []
    # The analyzer forces requires_approval=True; preserve that invariant here too.
    return [{**item, "requires_approval": True}
            for item in ai_result.get("recommendations", []) if isinstance(item, dict)]
