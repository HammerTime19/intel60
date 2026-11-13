"""Intel60 web push alerts.

Runs after the site is deployed, so a tapped notification always opens a live story.
Reads the new card ids (PUSH_IDS) and, once a day, the morning-summary window (PUSH_DIGEST_SINCE)
from the update job, matches them against each subscriber's choices, and sends notifications.
Subscribers whose browser has dropped the subscription are removed.
"""

import json
import os
import re
import sys
from pathlib import Path

import requests
from pywebpush import WebPushException, webpush

ROOT = Path(__file__).resolve().parent.parent
CARDS_PATH = ROOT / "docs" / "cards.json"
SITE = "https://intel60.app"
PUSH_API = os.environ.get("PUSH_API", "").rstrip("/")
BUNDLE_AFTER = 2   # more matches than this in one run become a single notification
TTL = 12 * 3600    # drop undelivered alerts after 12 hours


def log(msg):
    print(msg, flush=True)


def admin(method, path, **kwargs):
    resp = requests.request(method, f"{PUSH_API}{path}", timeout=30,
                            headers={"Authorization": "Bearer " + os.environ["PUSH_ADMIN_TOKEN"].strip()}, **kwargs)
    resp.raise_for_status()
    return resp.json()


def exploited(card):
    return any(v.get("kev") for v in (card.get("cve_info") or {}).values())


def matches(card, sub):
    text = f"{card['headline']} {card['summary']}"
    return (("critical" in sub["t"] and card["severity"] == "critical")
            or ("exploited" in sub["t"] and exploited(card))
            or ("vendors" in sub["t"] and any(re.search(rf"(^|[^\w]){re.escape(v)}(?![\w])", text, re.I) for v in sub.get("v", []))))


def label(card):
    if card["severity"] == "critical":
        return "Critical"
    return "Exploited" if exploited(card) else "Watchlist"


def messages(cards, digest=False):
    """One notification per story, or one bundle when there are several."""
    cards = sorted(cards, key=lambda c: c["published"], reverse=True)
    cards.sort(key=lambda c: c["severity"] != "critical")  # stable: critical first, newest first
    if digest:
        return [{"title": f"Morning brief: {len(cards)} {'story' if len(cards) == 1 else 'stories'} for you",
                 "body": "\n".join("• " + c["headline"] for c in cards[:3]), "url": "/#/news", "tag": "intel60-digest"}]
    if len(cards) > BUNDLE_AFTER:
        return [{"title": f"{len(cards)} new alerts on Intel60",
                 "body": "\n".join("• " + c["headline"] for c in cards[:3]), "url": "/#/news", "tag": "intel60-bundle"}]
    return [{"title": f"{label(c)}: {c['headline']}", "body": c["summary"], "url": f"/#{c['id']}", "tag": f"intel60-{c['id']}"}
            for c in cards]


def main():
    ids = [i for i in os.environ.get("PUSH_IDS", "").split(",") if i]
    digest_since = os.environ.get("PUSH_DIGEST_SINCE", "")
    if not (ids or digest_since):
        return log("push: nothing to send")
    if not (PUSH_API and os.environ.get("PUSH_ADMIN_TOKEN") and os.environ.get("VAPID_PRIVATE_KEY")):
        return log("push: not configured (PUSH_API, PUSH_ADMIN_TOKEN, VAPID_PRIVATE_KEY)")

    cards = json.loads(CARDS_PATH.read_text(encoding="utf-8"))["cards"]
    new = [c for c in cards if c["id"] in set(ids)]
    recent = [c for c in cards if digest_since and c["added"] > digest_since]
    subs = admin("GET", "/list")["subscriptions"]
    log(f"push: {len(new)} new cards, {len(recent) if digest_since else 0} for the summary, {len(subs)} subscribers")

    sent, dead = 0, []
    for sub in subs:
        if sub.get("d"):  # morning summary only
            mine = [c for c in recent if matches(c, sub)] if digest_since else []
            batch = messages(mine, digest=True) if mine else []
        else:
            mine = [c for c in new if matches(c, sub)]
            batch = messages(mine) if mine else []
        for msg in batch:
            try:
                webpush({"endpoint": sub["e"], "keys": sub["k"]}, json.dumps(msg), ttl=TTL,
                        vapid_private_key=os.environ["VAPID_PRIVATE_KEY"].strip(), vapid_claims={"sub": SITE})
                sent += 1
            except WebPushException as e:
                status = getattr(e.response, "status_code", None)
                if status in (404, 410):  # the browser dropped this subscription
                    dead.append(sub["e"])
                    break
                log(f"  ! push failed ({status}): {str(e)[:200]}")
    if dead:
        admin("POST", "/remove", json={"endpoints": dead})
    log(f"push: {sent} sent, {len(dead)} expired subscriptions removed")


if __name__ == "__main__":
    try:
        main()
    except requests.RequestException as e:
        sys.exit(f"push: subscription service unreachable: {e}")
