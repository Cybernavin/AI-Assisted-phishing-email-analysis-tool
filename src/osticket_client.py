"""
osTicket API client for the Phishing Investigation SOC project.

Creates phishing-investigation tickets in osTicket through the
built-in JSON API.

Tested configuration:
    osTicket URL:
        http://127.0.0.1/osTicket

    Help Topic:
        Phishing Email Investigation
        ID = 12

    Department:
        SOC — Phishing Investigation
        ID = 4
"""

import json
import urllib.error
import urllib.request
from typing import Optional


# ============================================================
# osTicket CONFIGURATION
# ============================================================

OSTICKET_URL = "http://127.0.0.1/osTicket"

# ------------------------------------------------------------
# PUT YOUR REAL API KEY HERE
# ------------------------------------------------------------

OSTICKET_API_KEY = "TCVS1ZLGJ2NLQ1ZLL7DR3YMBFBW0"


# ------------------------------------------------------------
# Existing osTicket client
# ------------------------------------------------------------

OSTICKET_SUBMITTER_NAME = "SOC Test User"

OSTICKET_SUBMITTER_EMAIL = "test@gmail.com.com"


# ------------------------------------------------------------
# Phishing Investigation Help Topic
#
# Phishing Email Investigation = ID 12
# This Help Topic belongs to:
# SOC — Phishing Investigation = Department 4
# ------------------------------------------------------------

OSTICKET_TOPIC_ID = 12


# ------------------------------------------------------------
# Optional staff assignment
#
# Leave as None until we know the actual SOC Administrator
# staff ID.
# ------------------------------------------------------------

OSTICKET_STAFF_ID = 1


# ------------------------------------------------------------
# Optional team assignment
# ------------------------------------------------------------

OSTICKET_TEAM_ID = None


# ============================================================
# API URL
# ============================================================

def _build_api_url() -> str:
    """
    Build the osTicket ticket creation API endpoint.
    """

    base_url = OSTICKET_URL.rstrip("/")

    return f"{base_url}/api/tickets.json"


# ============================================================
# API KEY
# ============================================================

def _get_api_key() -> str:
    """
    Return the configured API key.
    """

    api_key = OSTICKET_API_KEY.strip()

    if not api_key:

        raise RuntimeError(
            "OSTICKET_API_KEY is empty."
        )

    if api_key == "PASTE_YOUR_API_KEY_HERE":

        raise RuntimeError(
            "Replace PASTE_YOUR_API_KEY_HERE "
            "with your real osTicket API key."
        )

    return api_key


# ============================================================
# SUBMITTER
# ============================================================

def _get_submitter() -> tuple[str, str]:
    """
    Return the osTicket client name and email.
    """

    name = OSTICKET_SUBMITTER_NAME.strip()

    email = OSTICKET_SUBMITTER_EMAIL.strip()

    if not name:

        raise RuntimeError(
            "OSTICKET_SUBMITTER_NAME cannot be empty."
        )

    if not email:

        raise RuntimeError(
            "OSTICKET_SUBMITTER_EMAIL cannot be empty."
        )

    return name, email


# ============================================================
# SEVERITY → osTicket PRIORITY
# ============================================================

def _severity_to_priority(
    severity: str
) -> Optional[int]:
    """
    Convert SOC severity to osTicket priority ID.

    Default osTicket priorities:

        1 = Low
        2 = Normal
        3 = High
    """

    severity = (
        severity or ""
    ).strip().lower()

    if severity == "high":

        return 3

    if severity == "medium":

        return 2

    if severity == "low":

        return 1

    return None


# ============================================================
# BUILD PAYLOAD
# ============================================================

def _build_payload(
    title: str,
    description: str,
    severity: str = "Medium",
    risk_score: int = 0,
    source_file: str = ""
) -> dict:
    """
    Build the JSON payload sent to osTicket.
    """

    submitter_name, submitter_email = _get_submitter()

    # --------------------------------------------------------
    # Basic ticket data
    # --------------------------------------------------------

    payload = {

        "alert": False,

        "autorespond": False,

        "source": "API",

        "name": submitter_name,

        "email": submitter_email,

        "subject": title,

        "message": description,

        # IMPORTANT:
        # osTicket API expects topicId.
        "topicId": OSTICKET_TOPIC_ID
    }

    # --------------------------------------------------------
    # Priority
    # --------------------------------------------------------

    priority_id = _severity_to_priority(
        severity
    )

    if priority_id is not None:

        # IMPORTANT:
        # osTicket API uses priorityId.
        payload["priorityId"] = priority_id

    # --------------------------------------------------------
    # Optional staff assignment
    # --------------------------------------------------------

    if OSTICKET_STAFF_ID is not None:

        payload["staffId"] = OSTICKET_STAFF_ID

    # --------------------------------------------------------
    # Optional team assignment
    # --------------------------------------------------------

    if OSTICKET_TEAM_ID is not None:

        payload["teamId"] = OSTICKET_TEAM_ID

    # --------------------------------------------------------
    # SOC metadata
    # --------------------------------------------------------

    payload["message"] = (
        f"{description}\n\n"
        "========================================\n"
        "SOC AUTOMATION METADATA\n"
        "========================================\n"
        f"Risk Score: {risk_score}/100\n"
        f"Severity: {severity}\n"
        f"Source File: {source_file or 'Unknown'}\n"
        f"Help Topic ID: {OSTICKET_TOPIC_ID}\n"
        "Department: SOC — Phishing Investigation\n"
    )

    return payload


# ============================================================
# CREATE TICKET
# ============================================================

def create_ticket(
    title: str,
    description: str,
    severity: str = "Medium",
    risk_score: int = 0,
    source_file: str = ""
) -> dict:
    """
    Create an osTicket incident.

    Returns:
        Dictionary containing the ticket number and status.
    """

    # --------------------------------------------------------
    # API key
    # --------------------------------------------------------

    api_key = _get_api_key()

    # --------------------------------------------------------
    # API URL
    # --------------------------------------------------------

    api_url = _build_api_url()

    # --------------------------------------------------------
    # Build payload
    # --------------------------------------------------------

    payload = _build_payload(
        title=title,
        description=description,
        severity=severity,
        risk_score=risk_score,
        source_file=source_file
    )

    # --------------------------------------------------------
    # Convert to JSON
    # --------------------------------------------------------

    request_data = json.dumps(
        payload
    ).encode("utf-8")

    # --------------------------------------------------------
    # HTTP request
    # --------------------------------------------------------

    request = urllib.request.Request(

        api_url,

        data=request_data,

        method="POST",

        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-API-Key": api_key
        }
    )

    # --------------------------------------------------------
    # Send request
    # --------------------------------------------------------

    try:

        with urllib.request.urlopen(
            request,
            timeout=30
        ) as response:

            response_body = response.read().decode(
                "utf-8",
                errors="replace"
            ).strip()

            status_code = response.getcode()

            # ------------------------------------------------
            # Successful ticket creation
            # ------------------------------------------------

            if status_code not in (200, 201):

                raise RuntimeError(
                    f"osTicket returned HTTP "
                    f"{status_code}: "
                    f"{response_body}"
                )

            if not response_body:

                raise RuntimeError(
                    "osTicket accepted the request "
                    "but returned an empty ticket number."
                )

            # ------------------------------------------------
            # IMPORTANT:
            #
            # osTicket API returns the EXTERNAL ticket
            # NUMBER here.
            #
            # Example:
            #
            # 441223
            #
            # This is NOT necessarily the internal
            # ticket_id.
            # ------------------------------------------------

            ticket_number = response_body

            return {

                "status": "success",

                "ticket_number": ticket_number,

                "message":
                    "osTicket ticket created successfully.",

                "help_topic_id":
                    OSTICKET_TOPIC_ID,

                "department":
                    "SOC — Phishing Investigation"

            }

    # --------------------------------------------------------
    # HTTP error
    # --------------------------------------------------------

    except urllib.error.HTTPError as error:

        error_body = error.read().decode(
            "utf-8",
            errors="replace"
        )

        raise RuntimeError(
            f"osTicket API returned HTTP "
            f"{error.code}: {error_body}"
        ) from error

    # --------------------------------------------------------
    # Connection error
    # --------------------------------------------------------

    except urllib.error.URLError as error:

        raise RuntimeError(
            f"Could not connect to osTicket at "
            f"{api_url}: {error.reason}"
        ) from error


# ============================================================
# LOCAL TEST
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 60)
    print("          osTicket API Client")
    print("=" * 60)

    print(
        f"API URL: {_build_api_url()}"
    )

    if (
        OSTICKET_API_KEY
        == "PASTE_YOUR_API_KEY_HERE"
    ):

        print(
            "API Key: NOT CONFIGURED"
        )

    else:

        print(
            "API Key: CONFIGURED"
        )

    print(
        f"Submitter: "
        f"{OSTICKET_SUBMITTER_NAME}"
    )

    print(
        f"Email: "
        f"{OSTICKET_SUBMITTER_EMAIL}"
    )

    print(
        f"Help Topic ID: "
        f"{OSTICKET_TOPIC_ID}"
    )

    print(
        "Department: "
        "SOC — Phishing Investigation"
    )

    print("=" * 60)