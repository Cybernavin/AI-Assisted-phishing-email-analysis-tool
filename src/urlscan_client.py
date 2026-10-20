import time
import requests

API_KEY = "-94311f7abbac"
BASE_URL = "https://urlscan.io"


def get_headers():
    return {
        "api-key": API_KEY,
        "Content-Type": "application/json"
    }


def submit_url(url):
    endpoint = f"{BASE_URL}/api/v1/scan"

    data = {
        "url": url,
        "visibility": "private"
    }

    try:
        response = requests.post(
            endpoint,
            headers=get_headers(),
            json=data,
            timeout=30
        )

        if response.status_code in [200, 201]:
            result = response.json()

            return {
                "status": "submitted",
                "type": "url",
                "url": url,
                "scan_id": result.get("uuid"),
                "result_url": result.get("result"),
                "api_url": result.get("api")
            }

        if response.status_code == 429:
            return {
                "status": "rate_limited",
                "type": "url",
                "url": url,
                "message": "urlscan.io API rate limit reached."
            }

        return {
            "status": "error",
            "type": "url",
            "url": url,
            "message": (
                f"urlscan.io returned HTTP {response.status_code}: "
                f"{response.text[:300]}"
            )
        }

    except requests.RequestException as error:
        return {
            "status": "error",
            "type": "url",
            "url": url,
            "message": str(error)
        }


def get_scan_result(scan_id):
    if not scan_id:
        return {
            "status": "error",
            "message": "No scan ID was provided."
        }

    endpoint = f"{BASE_URL}/api/v1/result/{scan_id}/"

    try:
        response = requests.get(
            endpoint,
            headers={"api-key": API_KEY},
            timeout=30
        )

        if response.status_code == 200:
            return {
                "status": "found",
                "data": response.json()
            }

        if response.status_code == 404:
            return {"status": "pending"}

        if response.status_code == 429:
            return {
                "status": "rate_limited",
                "message": "urlscan.io API rate limit reached."
            }

        return {
            "status": "error",
            "message": f"urlscan.io returned HTTP {response.status_code}"
        }

    except requests.RequestException as error:
        return {
            "status": "error",
            "message": str(error)
        }


def parse_scan_result(url, scan_result):
    data = scan_result.get("data", {})

    page = data.get("page", {})
    verdicts = data.get("verdicts", {})
    stats = data.get("stats", {})

    if not isinstance(page, dict):
        page = {}

    if not isinstance(verdicts, dict):
        verdicts = {}

    if not isinstance(stats, dict):
        stats = {}

    urlscan_verdict = verdicts.get("urlscan", {})

    if not isinstance(urlscan_verdict, dict):
        urlscan_verdict = {}

    engines_verdict = verdicts.get("engines", {})

    if not isinstance(engines_verdict, dict):
        engines_verdict = {}

    # urlscan's explicit malicious field is preferred.
    # If it is absent, use the urlscan verdict score.
    explicit_malicious = urlscan_verdict.get("malicious")

    if explicit_malicious is None:
        explicit_malicious = verdicts.get("malicious")

    score = urlscan_verdict.get("score")

    if explicit_malicious is not None:
        malicious = bool(explicit_malicious)
    elif isinstance(score, (int, float)):
        malicious = score > 0
    else:
        stats_malicious = stats.get("malicious", 0)
        malicious = (
            isinstance(stats_malicious, (int, float))
            and stats_malicious > 0
        )

    suspicious = stats.get("suspicious", 0)

    if not isinstance(suspicious, (int, float)):
        suspicious = 0

    categories = urlscan_verdict.get("categories", [])

    if not isinstance(categories, list):
        categories = []

    redirected = bool(page.get("redirected", False))

    return {
        "status": "found",
        "type": "url",
        "url": url,
        "scan_id": data.get("task", {}).get("uuid"),
        "domain": page.get("domain"),
        "ip": page.get("ip"),
        "country": page.get("country"),
        "server": page.get("server"),
        "page_title": page.get("title"),
        "malicious": malicious,
        "urlscan_malicious": malicious,
        "verdict_score": score,
        "categories": categories,
        "suspicious": suspicious,
        "engines": engines_verdict,
        "redirected": redirected,
        "result": data
    }


def scan_url(url, wait_seconds=10, max_attempts=10):
    submission = submit_url(url)

    if submission["status"] != "submitted":
        return submission

    scan_id = submission.get("scan_id")

    if not scan_id:
        return {
            "status": "error",
            "type": "url",
            "url": url,
            "message": "urlscan.io did not return a scan ID."
        }

    print(f"    urlscan scan submitted: {scan_id}")
    print(
        f"    Waiting {wait_seconds} seconds "
        f"for urlscan.io..."
    )

    time.sleep(wait_seconds)

    for attempt in range(1, max_attempts + 1):
        result = get_scan_result(scan_id)

        if result["status"] == "found":
            parsed_result = parse_scan_result(url, result)

            parsed_result["result_url"] = submission.get(
                "result_url"
            )

            return parsed_result

        if result["status"] == "rate_limited":
            return {
                "status": "rate_limited",
                "type": "url",
                "url": url,
                "scan_id": scan_id
            }

        if result["status"] == "error":
            return {
                "status": "error",
                "type": "url",
                "url": url,
                "scan_id": scan_id,
                "message": result.get(
                    "message",
                    "Unknown error"
                )
            }

        if attempt < max_attempts:
            print(
                f"    Scan still processing..."
                f" ({attempt}/{max_attempts})"
            )
            time.sleep(5)

    return {
        "status": "pending",
        "type": "url",
        "url": url,
        "scan_id": scan_id,
        "result_url": submission.get("result_url"),
        "message": (
            "urlscan.io scan did not finish "
            "within the configured polling period."
        )
    }
