from pathlib import Path
from datetime import datetime
from html import escape, unescape
from html.parser import HTMLParser
import json
import re


def _safe(value):
    """Convert a value to safe HTML text."""
    if value is None:
        return "Unknown"
    return escape(str(value))



# ---------------------------------------------------------------------------
# AI text handling
# The model sometimes returns text containing literal "\n" (backslash + n),
# raw HTML, or Markdown. These helpers normalize all of that into safe HTML.
# ---------------------------------------------------------------------------
_ALLOWED_TAGS = {
    "h1", "h2", "h3", "h4", "h5", "h6", "p", "ul", "ol", "li",
    "strong", "b", "em", "i", "br", "code",
}
_HEADING_MAP = {"h1": "h3", "h2": "h3", "h3": "h3", "h4": "h4", "h5": "h4", "h6": "h4"}
_DROP_CONTENT_TAGS = {"script", "style", "iframe", "object", "embed", "head", "title"}
_REPORT_TITLE_RE = re.compile(r"^\s*(?:\d+\.?\s*)?ai[- ]assisted phishing assessment\s*$", re.I)


class _SafeHTMLSanitizer(HTMLParser):
    """Allow-list sanitizer: keeps basic formatting tags, drops attributes/everything else."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out = []
        self.stack = []
        self.skip = 0
        self._heading_buf = None

    def _emit(self, value):
        if self._heading_buf is not None:
            self._heading_buf.append(value)
        else:
            self.out.append(value)

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in _DROP_CONTENT_TAGS:
            self.skip += 1
            return
        if self.skip or tag not in _ALLOWED_TAGS:
            return
        if tag == "br":
            self._emit("<br>")
            return
        tag = _HEADING_MAP.get(tag, tag)
        if tag in ("h3", "h4"):
            self._heading_buf = []
        self.stack.append(tag)
        if self._heading_buf is None:
            self.out.append(f"<{tag}>")

    def handle_startendtag(self, tag, attrs):
        if tag.lower() == "br":
            self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in _DROP_CONTENT_TAGS:
            self.skip = max(0, self.skip - 1)
            return
        if self.skip or tag not in _ALLOWED_TAGS or tag == "br":
            return
        tag = _HEADING_MAP.get(tag, tag)
        if tag not in self.stack:
            return
        while self.stack:
            top = self.stack.pop()
            if top in ("h3", "h4") and self._heading_buf is not None:
                inner = "".join(self._heading_buf)
                self._heading_buf = None
                plain = re.sub(r"<[^>]+>", "", inner)
                # Drop the model's own title - the report already has a section title.
                if not _REPORT_TITLE_RE.match(unescape(plain)):
                    self.out.append(f"<{top}>{inner}</{top}>")
            else:
                self._emit(f"</{top}>")
            if top == tag:
                break

    def handle_data(self, data):
        if not self.skip:
            self._emit(escape(data))

    def result(self):
        while self.stack:
            top = self.stack.pop()
            if top in ("h3", "h4") and self._heading_buf is not None:
                self.out.append(f"<{top}>{''.join(self._heading_buf)}</{top}>")
                self._heading_buf = None
            else:
                self.out.append(f"</{top}>")
        return "".join(self.out)


def _clean_ai_text(value):
    """Normalize AI text: literal \\n sequences -> real newlines, strip code fences."""
    if value is None:
        return ""
    text = str(value)
    # Escaped newlines/tabs that show up as visible characters (backslash + n).
    text = text.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\r", "\n")
    text = text.replace("\\t", " ")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    # Remove wrapping Markdown code fences such as ```html ... ```.
    text = re.sub(r"^\s*```[a-zA-Z]*\s*\n", "", text)
    text = re.sub(r"\n\s*```\s*$", "", text)
    return text.strip()


_HTML_TAG_RE = re.compile(
    r"</?(?:p|ul|ol|li|h[1-6]|strong|b|em|i|br|div|span|code|section|article)\b[^>]*>", re.I
)


def _looks_like_html(text):
    return bool(_HTML_TAG_RE.search(text or ""))


def _strip_tags(text):
    return unescape(re.sub(r"<[^>]+>", " ", text or ""))


def _plain_ai_text(value):
    """Return single-line plain text (no HTML, no Markdown emphasis)."""
    text = _clean_ai_text(value)
    text = _strip_tags(text) if _looks_like_html(text) else text
    text = re.sub(r"[*_`#]+", "", text)
    return re.sub(r"\s+", " ", text).strip()


def _inline_format(text):
    """Escape text, then apply a tiny safe subset of inline Markdown."""
    out = escape(text)
    out = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", out)
    out = re.sub(r"__(.+?)__", r"<strong>\1</strong>", out)
    out = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"<em>\1</em>", out)
    out = re.sub(r"`(.+?)`", r"<code>\1</code>", out)
    return out


_LIST_ITEM_RE = re.compile(r"^(?:[-*\u2022]\s+|\d+[.)]\s+)")


def _markdown_to_html(text):
    rendered = []
    for block in re.split(r"\n\s*\n", text):
        lines = [line.strip() for line in block.split("\n") if line.strip()]
        if not lines:
            continue
        # Headings
        remaining = []
        for line in lines:
            m = re.match(r"^(#{1,6})\s+(.*)$", line)
            if m:
                if remaining:
                    rendered.append(_markdown_block(remaining))
                    remaining = []
                title = m.group(2).strip()
                if not _REPORT_TITLE_RE.match(title):
                    level = "h3" if len(m.group(1)) <= 3 else "h4"
                    rendered.append(f"<{level}>{_inline_format(title)}</{level}>")
            else:
                remaining.append(line)
        if remaining:
            rendered.append(_markdown_block(remaining))
    return "\n".join(r for r in rendered if r)


def _markdown_block(lines):
    if all(_LIST_ITEM_RE.match(line) for line in lines):
        items = "".join(f"<li>{_inline_format(_LIST_ITEM_RE.sub('', l, 1).strip())}</li>" for l in lines)
        return f'<ul class="ai-rich-list">{items}</ul>'
    return "<p>" + "<br>".join(_inline_format(line) for line in lines) + "</p>"


def _render_ai_rich_text(value):
    """Render AI text (plain, Markdown or HTML) as safe HTML paragraphs/lists."""
    text = _clean_ai_text(value)
    if not text:
        return '<p class="ai-empty-text">No details provided.</p>'

    if _looks_like_html(text):
        parser = _SafeHTMLSanitizer()
        parser.feed(text)
        parser.close()
        html = parser.result()
        # Whitespace-only text between tags is noise.
        html = re.sub(r">\s+<", "><", html).strip()
        html = html.replace("<ul>", '<ul class="ai-rich-list">').replace("<ol>", '<ol class="ai-rich-list">')
        if html:
            return html
        return '<p class="ai-empty-text">No details provided.</p>'

    return _markdown_to_html(text) or '<p class="ai-empty-text">No details provided.</p>'


def _ai_text_to_items(value):
    """Turn a string (plain / bullets / HTML list) into a list of plain item strings."""
    text = _clean_ai_text(value)
    if not text:
        return []
    if _looks_like_html(text):
        li_items = re.findall(r"<li\b[^>]*>(.*?)</li>", text, flags=re.I | re.S)
        if li_items:
            return [re.sub(r"\s+", " ", _strip_tags(i)).strip() for i in li_items if _strip_tags(i).strip()]
        text = re.sub(r"</(?:p|div|h[1-6]|li)>|<br\s*/?>", "\n", text, flags=re.I)
        text = _strip_tags(text)
    items = []
    for line in text.split("\n"):
        line = _LIST_ITEM_RE.sub("", line.strip()).strip()
        if line:
            items.append(line)
    return items


def _flatten_ai_items(value):
    """Accept str / list[str|dict] / dict and return a flat list of str|dict items."""
    if value is None:
        return []
    if isinstance(value, str):
        return _ai_text_to_items(value)
    if isinstance(value, dict):
        return [value]
    flat = []
    for entry in value:
        if isinstance(entry, str):
            flat.extend(_ai_text_to_items(entry))
        elif entry is not None:
            flat.append(entry)
    return flat


_EVIDENCE_ID_RE = re.compile(r"^\**\s*(E\d+)\s*\**\s*[:\-\u2013]\s*(.*)$", re.I | re.S)
_PRIORITY_RE = re.compile(r"^\**\s*(CRITICAL|HIGH|MEDIUM|LOW)\s*\**\s*[:\-\u2013]\s*(.*)$", re.I | re.S)
_APPROVAL_RE = re.compile(r"requires analyst approval|no action was executed", re.I)


def _group_evidence(items):
    """Strings like 'E001: ...' become dict items; continuation lines join the previous one."""
    grouped = []
    for item in items:
        if isinstance(item, str):
            m = _EVIDENCE_ID_RE.match(item)
            if m:
                grouped.append({"evidence_id": m.group(1).upper(), "explanation": m.group(2).strip()})
            elif grouped and isinstance(grouped[-1], dict) and grouped[-1].get("_from_text"):
                grouped[-1]["explanation"] += "\n\n" + item
            else:
                grouped.append(item)
            if grouped and isinstance(grouped[-1], dict) and "evidence_id" in grouped[-1]:
                grouped[-1]["_from_text"] = True
        else:
            grouped.append(item)
    for g in grouped:
        if isinstance(g, dict):
            g.pop("_from_text", None)
    return grouped


def _group_recommendations(items):
    """Strings like 'HIGH: Block ...' become dict items; follow-up lines become the rationale."""
    grouped = []
    for item in items:
        if isinstance(item, str):
            if _APPROVAL_RE.search(item) and len(item) < 120:
                continue  # the report adds its own approval note
            m = _PRIORITY_RE.match(item)
            if m:
                grouped.append({"priority": m.group(1).upper(), "action": m.group(2).strip(), "rationale": "", "_t": True})
            elif grouped and grouped[-1].get("_t"):
                prev = grouped[-1]
                prev["rationale"] = (prev["rationale"] + "\n\n" + item).strip()
            else:
                grouped.append({"priority": "medium", "action": item, "rationale": "", "_t": True})
        else:
            grouped.append(item)
    for g in grouped:
        if isinstance(g, dict):
            g.pop("_t", None)
    return grouped


def _status_class(value):
    """Return a CSS class based on a status/value."""
    text = str(value or "").lower()

    if any(word in text for word in [
        "malicious", "fail", "failed", "error", "high", "suspicious"
    ]):
        return "danger"

    if any(word in text for word in [
        "medium", "redirect", "warning", "pending"
    ]):
        return "warning"

    if any(word in text for word in [
        "pass", "clean", "safe", "success", "low", "not malicious"
    ]):
        return "success"

    return "neutral"


def _badge(value):
    css = _status_class(value)
    return f'<span class="badge {css}">{_safe(value)}</span>'


def _card(title, value, subtitle=""):
    return f"""
    <div class="metric-card">
        <div class="metric-title">{_safe(title)}</div>
        <div class="metric-value">{_safe(value)}</div>
        <div class="metric-subtitle">{_safe(subtitle)}</div>
    </div>
    """


def _list(items, empty_text="No data available."):
    if not items:
        return f'<div class="empty">{_safe(empty_text)}</div>'

    html = ['<ul class="clean-list">']

    for item in items:
        if isinstance(item, dict):
            text = item.get("description") or item.get("message") or json.dumps(
                item, ensure_ascii=False, default=str
            )
        else:
            text = str(item)

        html.append(f"<li>{_safe(text)}</li>")

    html.append("</ul>")
    return "\n".join(html)


def _render_ioc_list(title, values):
    values = values or []

    if not values:
        return ""

    rows = []

    for value in values:
        safe_value = _safe(value)

        if title.lower() == "urls":
            display = (
                f'<a href="{safe_value}" target="_blank" '
                f'rel="noopener noreferrer">{safe_value}</a>'
            )
        else:
            display = safe_value

        rows.append(f"<tr><td>{display}</td></tr>")

    return f"""
    <div class="subsection">
        <h3>{_safe(title)}</h3>
        <table>
            <thead>
                <tr><th>Value</th></tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
    </div>
    """


def _render_attachments(attachments):
    successful = [
        item for item in (attachments or [])
        if item.get("status") == "success"
    ]

    if not successful:
        return '<div class="empty">No successfully analyzed attachments.</div>'

    rows = []

    for item in successful:
        rows.append(
            "<tr>"
            f"<td>{_safe(item.get('filename', 'Unknown'))}</td>"
            f"<td>{_safe(item.get('size', 'Unknown'))}</td>"
            f"<td><code>{_safe(item.get('sha256', 'Unknown'))}</code></td>"
            f"<td><code>{_safe(item.get('md5', 'Unknown'))}</code></td>"
            "</tr>"
        )

    return f"""
    <table>
        <thead>
            <tr>
                <th>Filename</th>
                <th>Size</th>
                <th>SHA-256</th>
                <th>MD5</th>
            </tr>
        </thead>
        <tbody>
            {''.join(rows)}
        </tbody>
    </table>
    """


def _render_threat_intelligence(results, title):
    results = results or []

    if not results:
        return '<div class="empty">No checks were performed.</div>'

    rows = []

    for result in results:
        if not isinstance(result, dict):
            rows.append(
                f"<tr><td colspan='4'>{_safe(result)}</td></tr>"
            )
            continue

        indicator = (
            result.get("url")
            or result.get("hash")
            or result.get("indicator")
            or result.get("type")
            or "Unknown"
        )

        status = result.get("status", "unknown")
        message = result.get("message", "")

        malicious = result.get("malicious")
        suspicious = result.get("suspicious")

        detection = ""

        if malicious is not None or suspicious is not None:
            detection = (
                f"Malicious: {_safe(malicious if malicious is not None else 0)}"
                f"<br>Suspicious: {_safe(suspicious if suspicious is not None else 0)}"
            )

        rows.append(
            "<tr>"
            f"<td>{_safe(indicator)}</td>"
            f"<td>{_badge(status)}</td>"
            f"<td>{detection or '—'}</td>"
            f"<td>{_safe(message) if message else '—'}</td>"
            "</tr>"
        )

    return f"""
    <table>
        <thead>
            <tr>
                <th>Indicator</th>
                <th>Status</th>
                <th>Detection</th>
                <th>Details</th>
            </tr>
        </thead>
        <tbody>
            {''.join(rows)}
        </tbody>
    </table>
    """


def _render_authentication(results):
    results = results or {}

    checks = [
        ("SPF", results.get("spf", "unknown")),
        ("DKIM", results.get("dkim", "unknown")),
        ("DMARC", results.get("dmarc", "unknown")),
    ]

    rows = []

    for name, value in checks:
        rows.append(
            f"""
            <div class="auth-item">
                <span class="auth-name">{name}</span>
                {_badge(value)}
            </div>
            """
        )

    return f'<div class="auth-grid">{"".join(rows)}</div>'


def _render_header_analysis(results):
    results = results or {}
    findings = results.get("findings", [])

    if findings:
        return _list(findings)

    return '<div class="empty success-box">No obvious header anomalies found.</div>'


def _render_evidence(results):
    results = results or {}
    summary = results.get("summary", {})
    correlations = results.get("correlations", [])

    correlation_count = summary.get("correlation_count", len(correlations))
    finding_count = summary.get("finding_count", 0)

    content = f"""
    <div class="evidence-summary">
        {_card("Correlations", correlation_count, "Detected relationships")}
        {_card("Findings", finding_count, "Investigation findings")}
    </div>
    """

    if correlations:
        content += _list(correlations)
    else:
        content += (
            '<div class="empty success-box">'
            "No evidence correlations were identified."
            "</div>"
        )

    return content


def _render_risk(results):
    results = results or {}

    score = results.get("score", 0)
    severity = results.get("severity", "Unknown")
    reasons = results.get("reasons", [])

    try:
        score_number = int(score)
    except (TypeError, ValueError):
        score_number = 0

    score_number = max(0, min(100, score_number))

    if str(severity).lower() == "high":
        risk_class = "risk-high"
    elif str(severity).lower() == "medium":
        risk_class = "risk-medium"
    else:
        risk_class = "risk-low"

    return f"""
    <div class="risk-panel {risk_class}">
        <div>
            <div class="risk-label">Risk Score</div>
            <div class="risk-score">{score_number}<span>/100</span></div>
        </div>
        <div class="risk-severity">
            <div class="risk-label">Severity</div>
            <div class="severity-text">{_safe(severity)}</div>
        </div>
    </div>

    <div class="risk-bar">
        <div class="risk-fill" style="width: {score_number}%"></div>
    </div>

    <h3>Risk Factors</h3>
    {_list(reasons, "No risk factors identified.")}
    """



_RAW_KEYS = ("html", "report", "markdown", "analysis", "assessment", "text", "response", "content", "output")
_STRUCTURED_KEYS = ("verdict", "summary", "evidence_explanations", "evidence", "recommendations")


def _coerce_ai_results(results):
    """Accept dicts, JSON strings, or raw HTML/Markdown strings and return a dict."""
    if results is None:
        return None

    if isinstance(results, str):
        text = _clean_ai_text(results)
        if not text:
            return None
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                results = parsed
        except ValueError:
            pass
        if isinstance(results, str):
            return {"status": "success", "raw": text}

    if not isinstance(results, dict):
        return None

    results = dict(results)
    has_structured = any(results.get(k) for k in _STRUCTURED_KEYS)
    if not has_structured:
        for key in _RAW_KEYS:
            if isinstance(results.get(key), str) and results[key].strip():
                results["raw"] = _clean_ai_text(results[key])
                break
    if "status" not in results and (has_structured or results.get("raw")):
        results["status"] = "success"
    return results


def _parse_confidence(value):
    if isinstance(value, (int, float)):
        number = float(value)
    else:
        match = re.search(r"\d+(?:\.\d+)?", _plain_ai_text(value))
        number = float(match.group()) if match else 0.0
    if 0 < number <= 1 and not isinstance(value, str):
        number *= 100  # 0-1 scale -> percent
    return max(0, min(100, int(round(number))))


def _render_ai_analysis(results, risk_results=None):
    """Render structured AI findings separately from deterministic risk scoring."""
    results = _coerce_ai_results(results)
    if results is None:
        return ""

    status = str(results.get("status", "unknown")).lower()
    content = [
        '<section id="ai-analysis">',
        '<div class="section-title">',
        '<div class="section-number">09</div>',
        '<h2>AI-Assisted Phishing Assessment</h2>',
        '</div>',
    ]

    if status != "success":
        content.append(
            f'<div class="empty">AI analysis status: <strong>{_safe(status)}</strong>'
            f'<p>{_safe(_plain_ai_text(results.get("message", "AI analysis was unavailable.")))}</p></div>'
        )
    elif results.get("raw") and not any(results.get(k) for k in _STRUCTURED_KEYS):
        # Unstructured AI output (HTML / Markdown / plain text): render it cleanly.
        content.append(
            f'<div class="ai-summary-panel">{_render_ai_rich_text(results["raw"])}</div>'
        )
    else:
        verdict = _plain_ai_text(results.get("verdict", "inconclusive"))
        verdict = re.sub(r"^ai verdict\s*:\s*", "", verdict, flags=re.I) or "inconclusive"
        verdict_class = _status_class(verdict)
        confidence_num = _parse_confidence(results.get("confidence", 0))

        risk_results = risk_results or {}
        deterministic_score = risk_results.get("score", "N/A")
        deterministic_severity = risk_results.get("severity", "Unknown")

        content.append(f"""
        <div class="ai-overview-grid">
            <div class="ai-verdict-panel">
                <div class="ai-label">AI Verdict</div>
                <div class="ai-verdict-value"><span class="badge {verdict_class}">{_safe(verdict)}</span></div>
                <p class="ai-muted">Advisory model assessment</p>
            </div>
            <div class="ai-stat-panel">
                <div class="ai-label">Model Confidence</div>
                <div class="ai-big-number">{confidence_num}<span>/100</span></div>
                <div class="ai-progress"><span style="width:{confidence_num}%"></span></div>
                <p class="ai-muted">Model-reported; not a calibrated probability</p>
            </div>
            <div class="ai-stat-panel">
                <div class="ai-label">Deterministic Risk Score</div>
                <div class="ai-big-number">{_safe(deterministic_score)}<span>/100</span></div>
                <p class="ai-muted">Severity: {_safe(deterministic_severity)}</p>
            </div>
        </div>
        <div class="ai-summary-panel">
            <h3>Executive Summary</h3>
            {_render_ai_rich_text(results.get("summary", "No summary returned."))}
        </div>
        """)

        # ---------------- Evidence explanations ----------------
        evidence_items = _group_evidence(
            _flatten_ai_items(results.get("evidence_explanations", results.get("evidence", [])))
        )
        content.append('<h3>Evidence Explanations</h3>')
        if evidence_items:
            content.append('<div class="ai-item-grid">')
            for index, item in enumerate(evidence_items, 1):
                if isinstance(item, dict):
                    evidence_id = item.get("evidence_id") or item.get("id") or f"Finding {index}"
                    title = item.get("title") or item.get("finding") or ""
                    description = item.get("explanation") or item.get("description") or item.get("message") or ""
                    source = item.get("source") or item.get("source_type") or ""
                    severity = item.get("severity") or item.get("priority") or ""
                    details = ""
                    if source:
                        details += f'<div class="ai-item-meta"><strong>Source:</strong> {_safe(source)}</div>'
                    if severity:
                        details += f'<div class="ai-item-meta"><strong>Severity:</strong> {_badge(severity)}</div>'
                    title_html = f'<strong>{_safe(_plain_ai_text(title))}</strong>' if title else ""
                    content.append(
                        f'<article class="ai-item-card">'
                        f'<div class="ai-item-heading"><span class="ai-evidence-id">{_safe(evidence_id)}</span>'
                        f'{title_html}</div>'
                        f'{_render_ai_rich_text(description or "No explanation provided.")}{details}</article>'
                    )
                else:
                    content.append(
                        f'<article class="ai-item-card"><div class="ai-item-heading">'
                        f'<span class="ai-evidence-id">Finding {index}</span></div>'
                        f'{_render_ai_rich_text(item)}</article>'
                    )
            content.append('</div>')
        else:
            content.append('<div class="empty">No evidence explanations were returned.</div>')

        # ---------------- Recommendations ----------------
        recommendations = _group_recommendations(_flatten_ai_items(results.get("recommendations", [])))
        content.append('<h3>Recommended Response Actions</h3>')
        if recommendations:
            content.append('<div class="ai-recommendation-list">')
            for index, item in enumerate(recommendations, 1):
                if isinstance(item, dict):
                    priority_value = _plain_ai_text(item.get("priority", "medium")).upper() or "MEDIUM"
                    action = _plain_ai_text(item.get("action") or item.get("recommendation") or "Review manually")
                    rationale = item.get("rationale") or item.get("reason") or ""
                    priority_class = _status_class(priority_value)
                    content.append(
                        f'<article class="ai-recommendation-card">'
                        f'<div class="ai-recommendation-top"><span class="ai-action-number">{index:02d}</span>'
                        f'<span class="badge {priority_class}">{_safe(priority_value)}</span></div>'
                        f'<h4>{_safe(action)}</h4>'
                        f'{_render_ai_rich_text(rationale) if rationale else ""}'
                        '<p class="ai-approval-note">Requires analyst approval. No action was executed.</p>'
                        '</article>'
                    )
                else:
                    content.append(
                        f'<article class="ai-recommendation-card">{_render_ai_rich_text(item)}'
                        '<p class="ai-approval-note">Requires analyst approval. No action was executed.</p></article>'
                    )
            content.append('</div>')
        else:
            content.append('<div class="empty">No response recommendations were returned.</div>')

        # ---------------- Limitations ----------------
        limitations = _flatten_ai_items(results.get("limitations", []))
        if limitations:
            content.append('<h3>Analysis Limitations</h3><ul class="clean-list">')
            for limitation in limitations:
                text = limitation if isinstance(limitation, str) else json.dumps(limitation, ensure_ascii=False, default=str)
                content.append(f'<li>{_safe(_plain_ai_text(text))}</li>')
            content.append('</ul>')

    content.append(
        '<div class="ai-disclaimer"><strong>Analyst review required.</strong> '
        'AI output is advisory only and does not change the deterministic risk score. '
        'Verify findings against the supporting evidence before taking response actions.</div>'
    )
    content.append('</section>')
    return "\n".join(content)


def generate_report(
    file_name,
    email_details,
    header_results,
    authentication_results,
    ioc_results,
    attachment_results,
    virustotal_results,
    urlscan_results,
    evidence_results,
    risk_results,
    ai_results=None
):
    """
    Generate a clean standalone HTML SOC investigation report.

    This function intentionally accepts the same investigation data that
    main.py already produces. It does not perform any additional analysis.
    """

    email_details = email_details or {}
    ioc_results = ioc_results or {}

    subject = email_details.get("subject", "Unknown Subject")
    sender = email_details.get("from", "Unknown")
    recipient = email_details.get("to", "Unknown")

    urls = ioc_results.get("urls", [])
    domains = ioc_results.get("domains", [])
    ip_addresses = ioc_results.get("ip_addresses", [])
    email_addresses = ioc_results.get("email_addresses", [])

    score = (risk_results or {}).get("score", 0)
    severity = (risk_results or {}).get("severity", "Unknown")

    try:
        score_number = int(score)
    except (TypeError, ValueError):
        score_number = 0

    score_number = max(0, min(100, score_number))

    # Make the whole report background red for critical-risk reports.
    body_class = "critical-risk" if score_number >= 80 else ""

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC Phishing Investigation - {_safe(file_name)}</title>

<style>
:root {{
    --bg: #070b14;
    --bg-soft: #0b1220;
    --panel: rgba(15, 23, 42, .82);
    --panel-solid: #0f172a;
    --panel-light: #131e31;
    --border: rgba(148, 163, 184, .16);
    --border-strong: rgba(148, 163, 184, .28);
    --text: #f1f5f9;
    --muted: #94a3b8;
    --accent: #38bdf8;
    --green: #22c55e;
    --yellow: #f59e0b;
    --red: #ef4444;
    --red-dark: #7f1d1d;
    --purple: #a78bfa;
    --shadow: 0 18px 50px rgba(0, 0, 0, .28);
}}

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    min-height: 100vh;
    background:
        radial-gradient(circle at 8% 0%, rgba(56,189,248,.12), transparent 28%),
        radial-gradient(circle at 92% 4%, rgba(129,140,248,.12), transparent 26%),
        linear-gradient(180deg, #080d18 0%, var(--bg) 55%, #060a12 100%);
    color: var(--text);
    font-family: "Segoe UI", Inter, Arial, sans-serif;
    line-height: 1.55;
}}

body.critical-risk {{
    background:
        radial-gradient(circle at 8% 0%, rgba(239,68,68,.38), transparent 30%),
        radial-gradient(circle at 92% 4%, rgba(185,28,28,.28), transparent 28%),
        linear-gradient(180deg, #25080b 0%, #10070a 55%, #080407 100%);
}}

body::before {{
    content: "";
    position: fixed;
    inset: 0;
    pointer-events: none;
    background-image: linear-gradient(rgba(255,255,255,.018) 1px, transparent 1px),
                      linear-gradient(90deg, rgba(255,255,255,.018) 1px, transparent 1px);
    background-size: 42px 42px;
    mask-image: linear-gradient(to bottom, black, transparent 85%);
    z-index: -1;
}}

.container {{
    max-width: 1320px;
    margin: 0 auto;
    padding: 34px 24px 70px;
}}

.hero {{
    position: relative;
    overflow: hidden;
    background:
        linear-gradient(135deg, rgba(15,23,42,.94), rgba(17,24,39,.78));
    border: 1px solid var(--border);
    border-radius: 24px;
    padding: 30px;
    box-shadow: var(--shadow);
    margin-bottom: 24px;
    backdrop-filter: blur(16px);
}}

.hero::after {{
    content: "";
    position: absolute;
    width: 280px;
    height: 280px;
    right: -90px;
    top: -130px;
    background: radial-gradient(circle, rgba(56,189,248,.20), transparent 68%);
    pointer-events: none;
}}

body.critical-risk .hero {{
    border-color: rgba(239,68,68,.42);
    background: linear-gradient(135deg, rgba(69,10,10,.92), rgba(31,12,16,.86));
}}

body.critical-risk .hero::after {{
    background: radial-gradient(circle, rgba(239,68,68,.30), transparent 68%);
}}

.hero-top {{
    display: flex;
    justify-content: space-between;
    gap: 20px;
    align-items: flex-start;
}}

.logo {{
    width: 58px;
    height: 58px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 16px;
    background: linear-gradient(135deg, #0ea5e9, #6366f1);
    color: white;
    font-size: 26px;
    font-weight: 900;
    box-shadow: 0 10px 28px rgba(14,165,233,.22);
}}

body.critical-risk .logo {{
    background: linear-gradient(135deg, #ef4444, #991b1b);
    box-shadow: 0 10px 30px rgba(239,68,68,.28);
}}

h1 {{
    margin: 0 0 7px;
    font-size: 30px;
}}

.hero p {{
    color: var(--muted);
    margin: 4px 0;
}}

.report-meta {{
    margin-top: 22px;
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
    gap: 12px;
}}

.meta {{
    background: rgba(255,255,255,.035);
    border: 1px solid var(--border);
    padding: 13px 15px;
    border-radius: 12px;
}}

.meta-label {{
    color: var(--muted);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: .08em;
}}

.meta-value {{
    margin-top: 4px;
    font-weight: 600;
    word-break: break-word;
}}

section {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 26px;
    margin: 18px 0;
    box-shadow: 0 14px 38px rgba(0,0,0,.18);
    backdrop-filter: blur(14px);
}}

section:hover {{
    border-color: var(--border-strong);
}}

.section-title {{
    display: flex;
    align-items: center;
    gap: 13px;
    margin-bottom: 21px;
    padding-bottom: 14px;
    border-bottom: 1px solid rgba(148,163,184,.10);
}}

.section-number {{
    width: 34px;
    height: 34px;
    border-radius: 10px;
    background: rgba(56,189,248,.13);
    color: var(--accent);
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 800;
}}

h2 {{
    margin: 0;
    font-size: 21px;
}}

h3 {{
    margin-top: 24px;
    color: #cbd5e1;
}}

.metrics {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(175px, 1fr));
    gap: 13px;
}}

.metric-card {{
    position: relative;
    overflow: hidden;
    background: linear-gradient(145deg, rgba(19,30,49,.96), rgba(12,19,32,.96));
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 19px;
    box-shadow: 0 8px 24px rgba(0,0,0,.14);
}}

.metric-card::before {{
    content: "";
    position: absolute;
    left: 0;
    top: 0;
    width: 3px;
    height: 100%;
    background: var(--accent);
    opacity: .75;
}}

.metric-title {{
    color: var(--muted);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: .06em;
}}

.metric-value {{
    font-size: 27px;
    font-weight: 800;
    margin-top: 5px;
}}

.metric-subtitle {{
    color: var(--muted);
    font-size: 12px;
    margin-top: 3px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    overflow: hidden;
    border-radius: 12px;
    margin-top: 12px;
}}

th {{
    background: rgba(30,41,59,.88);
    color: #cbd5e1;
    text-align: left;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .08em;
}}

th, td {{
    padding: 12px 13px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
    word-break: break-word;
}}

td {{
    color: #dbe4ef;
}}

tr:hover td {{
    background: rgba(255,255,255,.025);
}}

a {{
    color: var(--accent);
    text-decoration: none;
}}

a:hover {{
    text-decoration: underline;
}}

code {{
    color: #c4b5fd;
    font-family: Consolas, monospace;
    font-size: 12px;
}}

.badge {{
    display: inline-block;
    padding: 5px 10px;
    border-radius: 999px;
    font-size: 10px;
    font-weight: 900;
    text-transform: uppercase;
    letter-spacing: .07em;
    border: 1px solid transparent;
}}

.badge.success {{
    background: rgba(34,197,94,.13);
    color: #4ade80;
}}

.badge.warning {{
    background: rgba(245,158,11,.13);
    color: #fbbf24;
}}

.badge.danger {{
    background: rgba(239,68,68,.13);
    color: #f87171;
}}

.badge.neutral {{
    background: rgba(148,163,184,.13);
    color: #cbd5e1;
}}

.auth-grid {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 14px;
}}

.auth-item {{
    background: var(--panel-light);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 17px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}}

.auth-name {{
    font-size: 17px;
    font-weight: 700;
}}

.clean-list {{
    padding-left: 0;
    list-style: none;
    margin: 12px 0;
}}

.clean-list li {{
    background: var(--panel-light);
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent);
    border-radius: 10px;
    padding: 12px 15px;
    margin: 9px 0;
}}

.empty {{
    color: var(--muted);
    background: rgba(148,163,184,.05);
    border: 1px dashed var(--border);
    border-radius: 12px;
    padding: 16px;
}}

.success-box {{
    border-left: 3px solid var(--green);
}}

.evidence-summary {{
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 14px;
    margin-bottom: 18px;
}}

.risk-panel {{
    position: relative;
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 28px 30px;
    border-radius: 20px;
    border: 1px solid var(--border);
    overflow: hidden;
}}

.risk-panel::after {{
    content: "";
    position: absolute;
    width: 220px;
    height: 220px;
    right: -90px;
    top: -100px;
    border-radius: 50%;
    background: rgba(255,255,255,.035);
}}

.risk-high {{
    background:
        linear-gradient(135deg, rgba(127,29,29,.48), rgba(69,10,10,.22));
    border-color: rgba(239,68,68,.52);
    box-shadow: 0 12px 34px rgba(127,29,29,.20);
}}

.risk-medium {{
    background:
        linear-gradient(135deg, rgba(120,53,15,.38), rgba(69,45,10,.18));
    border-color: rgba(245,158,11,.48);
}}

.risk-low {{
    background:
        linear-gradient(135deg, rgba(20,83,45,.32), rgba(10,55,34,.16));
    border-color: rgba(34,197,94,.42);
}}

.risk-label {{
    color: var(--muted);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: .08em;
}}

.risk-score {{
    font-size: 54px;
    line-height: 1;
    font-weight: 900;
    letter-spacing: -.04em;
    text-shadow: 0 4px 18px rgba(0,0,0,.28);
}}

.risk-score span {{
    color: var(--muted);
    font-size: 17px;
}}

.severity-text {{
    font-size: 25px;
    font-weight: 800;
}}

.risk-bar {{
    height: 9px;
    background: #1e293b;
    border-radius: 999px;
    margin: 15px 0 25px;
    overflow: hidden;
}}

.risk-fill {{
    height: 100%;
    background: linear-gradient(90deg, #22c55e, #f59e0b, #ef4444);
    border-radius: inherit;
}}

.subsection {{
    margin-top: 22px;
}}

.footer {{
    text-align: center;
    color: #64748b;
    padding-top: 28px;
    font-size: 12px;
}}

.critical-banner {{
    display: flex;
    align-items: center;
    gap: 13px;
    padding: 15px 18px;
    margin: 0 0 20px;
    border: 1px solid rgba(239,68,68,.48);
    border-radius: 15px;
    background: linear-gradient(90deg, rgba(127,29,29,.50), rgba(69,10,10,.22));
    box-shadow: 0 10px 28px rgba(127,29,29,.16);
}}

.critical-banner strong {{
    display: block;
    color: #fca5a5;
    font-size: 12px;
    letter-spacing: .08em;
}}

.critical-banner span:not(.critical-dot) {{
    display: block;
    color: #fecaca;
    font-size: 12px;
    margin-top: 2px;
}}

.critical-dot {{
    width: 10px;
    height: 10px;
    flex: 0 0 10px;
    border-radius: 50%;
    background: #ef4444;
    box-shadow: 0 0 0 6px rgba(239,68,68,.12), 0 0 18px rgba(239,68,68,.65);
}}


.ai-overview-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 14px;
    margin: 8px 0 20px;
}}
.ai-verdict-panel, .ai-stat-panel, .ai-summary-panel, .ai-item-card, .ai-recommendation-card {{
    background: linear-gradient(145deg, rgba(19,30,49,.96), rgba(12,19,32,.96));
    border: 1px solid var(--border);
    border-radius: 15px;
    padding: 18px;
    min-width: 0;
}}
.ai-verdict-panel {{ border-left: 3px solid var(--purple); }}
.ai-label, .ai-muted, .ai-item-meta {{ color: var(--muted); font-size: 12px; }}
.ai-label {{ text-transform: uppercase; letter-spacing: .07em; }}
.ai-verdict-value {{ margin-top: 12px; font-size: 22px; font-weight: 800; }}
.ai-big-number {{ font-size: 34px; font-weight: 850; margin-top: 6px; }}
.ai-big-number span {{ font-size: 15px; color: var(--muted); }}
.ai-muted {{ margin: 7px 0 0; }}
.ai-progress {{ height: 6px; background: #1e293b; border-radius: 999px; overflow: hidden; margin-top: 8px; }}
.ai-progress span {{ display: block; height: 100%; background: linear-gradient(90deg, #38bdf8, #a78bfa); border-radius: inherit; }}
.ai-summary-panel {{ margin: 16px 0 22px; border-left: 3px solid var(--accent); }}
.ai-summary-panel h3 {{ margin-top: 0; }}
.ai-summary-panel p, .ai-item-card p, .ai-recommendation-card p {{ overflow-wrap: anywhere; }}
.ai-summary-panel p, .ai-item-card p, .ai-recommendation-card p {{
    margin: 8px 0;
    line-height: 1.7;
    overflow-wrap: anywhere;
    white-space: normal;
}}
.ai-rich-list {{ margin: 10px 0; padding-left: 22px; }}
.ai-rich-list li {{ margin: 7px 0; padding-left: 3px; overflow-wrap: anywhere; }}
.ai-empty-text {{ color: var(--muted); }}

.ai-item-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; }}
.ai-item-card {{ margin: 0; }}
.ai-item-heading {{ display: flex; flex-wrap: wrap; align-items: center; gap: 9px; margin-bottom: 8px; }}
.ai-evidence-id, .ai-action-number {{ color: var(--accent); font-size: 11px; font-weight: 800; letter-spacing: .05em; }}
.ai-item-meta {{ margin-top: 8px; }}
.ai-recommendation-list {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; }}
.ai-recommendation-card {{ border-top: 2px solid var(--yellow); }}
.ai-recommendation-top {{ display: flex; align-items: center; justify-content: space-between; gap: 8px; }}
.ai-recommendation-card h4 {{ margin: 12px 0 7px; font-size: 16px; }}
.ai-approval-note {{ border-top: 1px solid var(--border); padding-top: 9px; color: var(--muted); font-size: 12px; }}
.ai-disclaimer {{ margin-top: 20px; padding: 15px 17px; border: 1px solid rgba(245,158,11,.35); border-left: 3px solid var(--yellow); border-radius: 12px; color: #cbd5e1; background: rgba(245,158,11,.06); }}

@media (max-width: 700px) {{
    .hero-top {{
        flex-direction: column;
    }}

    .auth-grid,
    .evidence-summary {{
        grid-template-columns: 1fr;
    }}

    .risk-panel {{
        flex-direction: column;
        align-items: flex-start;
        gap: 18px;
    }}

    .container {{
        padding: 20px 13px 45px;
    }}

    .hero, section {{
        padding: 20px;
        border-radius: 17px;
    }}

    .critical-banner {{
        align-items: flex-start;
    }}

    th, td {{
        padding: 9px;
    }}
}}

@media print {{
    body {{
        background: white;
        color: #111827;
    }}

    body::before {{
        display: none;
    }}

    section, .hero {{
        box-shadow: none;
        break-inside: avoid;
    }}
}}
</style>
</head>

<body class="{body_class}">
<div class="container">

<header class="hero">
    <div class="hero-top">
        <div style="display:flex;gap:17px;align-items:flex-start;">
            <div class="logo">S</div>
            <div>
                <h1>SOC Phishing Email Investigation</h1>
                <p>Enterprise Email Security Investigation Report</p>
                <p>Generated: {_safe(generated_at)}</p>
            </div>
        </div>
        <div>
            {_badge(severity)}
        </div>
    </div>

    <div class="report-meta">
        <div class="meta">
            <div class="meta-label">Source File</div>
            <div class="meta-value">{_safe(file_name)}</div>
        </div>

        <div class="meta">
            <div class="meta-label">Subject</div>
            <div class="meta-value">{_safe(subject)}</div>
        </div>

        <div class="meta">
            <div class="meta-label">From</div>
            <div class="meta-value">{_safe(sender)}</div>
        </div>

        <div class="meta">
            <div class="meta-label">To</div>
            <div class="meta-value">{_safe(recipient)}</div>
        </div>
    </div>
</header>

{f'<div class="critical-banner"><span class="critical-dot"></span><div><strong>CRITICAL RISK DETECTED</strong><span>Automated investigation score is {score_number}/100. Review the evidence before taking response actions.</span></div></div>' if score_number >= 80 else ''}

<section>
    <div class="section-title">
        <div class="section-number">01</div>
        <h2>Investigation Overview</h2>
    </div>

    <div class="metrics">
        {_card("Risk Score", f"{score}/100", severity)}
        {_card("URLs", len(urls), "Extracted indicators")}
        {_card("Domains", len(domains), "Extracted indicators")}
        {_card("IP Addresses", len(ip_addresses), "Extracted indicators")}
        {_card("Email Addresses", len(email_addresses), "Extracted indicators")}
        {_card("Attachments", len(attachment_results or []), "Analyzed files")}
    </div>
</section>

<section>
    <div class="section-title">
        <div class="section-number">02</div>
        <h2>Header Analysis</h2>
    </div>

    {_render_header_analysis(header_results)}
</section>

<section>
    <div class="section-title">
        <div class="section-number">03</div>
        <h2>Email Authentication</h2>
    </div>

    {_render_authentication(authentication_results)}
</section>

<section>
    <div class="section-title">
        <div class="section-number">04</div>
        <h2>Indicators of Compromise</h2>
    </div>

    {_render_ioc_list("URLs", urls)}
    {_render_ioc_list("Domains", domains)}
    {_render_ioc_list("IP Addresses", ip_addresses)}
    {_render_ioc_list("Email Addresses", email_addresses)}

    {('<div class="empty">No IOCs were extracted.</div>'
      if not any([urls, domains, ip_addresses, email_addresses]) else '')}
</section>

<section>
    <div class="section-title">
        <div class="section-number">05</div>
        <h2>Attachment Analysis</h2>
    </div>

    {_render_attachments(attachment_results)}
</section>

<section>
    <div class="section-title">
        <div class="section-number">06</div>
        <h2>Threat Intelligence</h2>
    </div>

    <div class="subsection">
        <h3>VirusTotal</h3>
        {_render_threat_intelligence(virustotal_results, "VirusTotal")}
    </div>

    <div class="subsection">
        <h3>urlscan.io</h3>
        {_render_threat_intelligence(urlscan_results, "urlscan.io")}
    </div>
</section>

<section>
    <div class="section-title">
        <div class="section-number">07</div>
        <h2>Evidence Correlation</h2>
    </div>

    {_render_evidence(evidence_results)}
</section>

<section>
    <div class="section-title">
        <div class="section-number">08</div>
        <h2>Risk Assessment</h2>
    </div>

    {_render_risk(risk_results)}
</section>

{_render_ai_analysis(ai_results, risk_results)}

<section>
    <div class="section-title">
        <div class="section-number">10</div>
        <h2>Analyst Notes</h2>
    </div>

    <div class="empty">
        This report contains automated investigation results.
        Final incident classification and response actions should be
        confirmed by a SOC analyst.
    </div>
</section>

<div class="footer">
    SOC Phishing Investigation Platform &bull;
    Automated Investigation Report
</div>

</div>
</body>
</html>
"""

    return html


def save_report(report):
    """Save the generated HTML report and return its path."""

    reports_dir = Path(__file__).resolve().parent.parent / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    report_path = reports_dir / f"phishing-investigation-{timestamp}.html"

    report_path.write_text(report, encoding="utf-8")

    return str(report_path)


if __name__ == "__main__":
    print("report_generator.py loaded successfully.")
    print("Output format: HTML")
