"""Intel60 web push alerts.

Runs after the site is deployed, so a tapped notification always opens a live story.
Reads the new card ids (PUSH_IDS), stories that just became trending (PUSH_TRENDING) and, once a day, the morning-summary window (PUSH_DIGEST_SINCE)
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

import config

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


def outlets(card):
    return 1 + len(card.get("also") or [])


def reason(card, sub, trending=False):
    """Why this story should alert this subscriber ("Critical", "Exploited", "Watchlist", "Trending"), or None."""
    text = f"{card['headline']} {card['summary']}"
    if "critical" in sub["t"] and card["severity"] == "critical":
        return "Critical"
    if "exploited" in sub["t"] and exploited(card):
        return "Exploited"
    if "vendors" in sub["t"] and any(re.search(rf"(^|[^\w]){re.escape(v)}(?![\w])", text, re.I) for v in sub.get("v", [])):
        return "Watchlist"
    if "trending" in sub["t"] and trending:
        return "Trending"
    return None


def messages(items, digest=False):
    """items: (card, reason) pairs. One notification per story, or one bundle when there are several."""
    items = sorted(items, key=lambda i: i[0]["published"], reverse=True)
    items.sort(key=lambda i: i[0]["severity"] != "critical")  # stable: critical first, newest first
    lines = "\n".join("• " + c["headline"] for c, _ in items[:3])
    if digest:
        return [{"title": f"Morning brief: {len(items)} {'story' if len(items) == 1 else 'stories'} for you",
                 "body": lines, "url": "/#/news", "tag": "intel60-digest"}]
    if len(items) > BUNDLE_AFTER:
        return [{"title": f"{len(items)} new alerts on Intel60", "body": lines, "url": "/#/news", "tag": "intel60-bundle"}]
    return [{"title": f"{why}: {c['headline']}",
             "body": (f"🔥 Covered by {outlets(c)} outlets. " if why == "Trending" else "") + c["summary"],
             "url": f"/#{c['id']}", "tag": f"intel60-{c['id']}"}
            for c, why in items]


def send(sub, msg):
    """Sends one notification: "sent", "dead" (the browser dropped the subscription) or "failed"."""
    try:
        webpush({"endpoint": sub["e"], "keys": sub["k"]}, json.dumps(msg), ttl=TTL,
                vapid_private_key=os.environ["VAPID_PRIVATE_KEY"].strip(), vapid_claims={"sub": SITE})
        return "sent"
    except WebPushException as e:
        status = getattr(e.response, "status_code", None)
        if status in (404, 410):
            return "dead"
        log(f"  ! push failed ({status}): {str(e)[:200]}")
        return "failed"


def send_test():
    """A test notification for setting up alerts; refuses once real readers have subscribed."""
    subs = admin("GET", "/list")["subscriptions"]
    if len(subs) > 2:
        return log(f"push test: skipped, {len(subs)} subscribers (only sent while there are 2 or fewer)")
    msg = {"title": "Intel60 alerts are working ✅", "body": "You'll get a notification like this when a story matches your alert choices.",
           "url": "/", "tag": "intel60-test"}
    results = [send(s, msg) for s in subs]
    log(f"push test: sent to {results.count('sent')} of {len(subs)} subscribers ({', '.join(results) or 'none subscribed'})")


def main():
    ids = {i for i in os.environ.get("PUSH_IDS", "").split(",") if i}
    trending_ids = {i for i in os.environ.get("PUSH_TRENDING", "").split(",") if i}
    digest_since = os.environ.get("PUSH_DIGEST_SINCE", "")
    test = os.environ.get("PUSH_TEST") == "true"
    if not (ids or trending_ids or digest_since or test):
        return log("push: nothing to send")
    if not (PUSH_API and os.environ.get("PUSH_ADMIN_TOKEN") and os.environ.get("VAPID_PRIVATE_KEY")):
        return log("push: not configured (PUSH_API, PUSH_ADMIN_TOKEN, VAPID_PRIVATE_KEY)")

    if test:
        return send_test()
    cards = json.loads(CARDS_PATH.read_text(encoding="utf-8"))["cards"]
    new = [c for c in cards if c["id"] in ids]
    newly_trending = [c for c in cards if c["id"] in trending_ids and c["id"] not in ids]
    recent = [c for c in cards if digest_since and c["added"] > digest_since]
    subs = admin("GET", "/list")["subscriptions"]
    log(f"push: {len(new)} new cards, {len(newly_trending)} newly trending, "
        f"{len(recent) if digest_since else 0} for the summary, {len(subs)} subscribers")

    sent, dead = 0, []
    for sub in subs:
        if sub.get("d"):  # morning summary only
            mine = [(c, r) for c in recent if (r := reason(c, sub, trending=outlets(c) >= config.TRENDING_SOURCES))]
            batch = messages(mine, digest=True) if mine and digest_since else []
        else:
            mine = [(c, r) for c in new if (r := reason(c, sub, trending=c["id"] in trending_ids))]
            # an older story that just became trending; skip it if it already alerted as critical, exploited or watchlist
            mine += [(c, "Trending") for c in newly_trending if reason(c, sub, trending=True) == "Trending"]
            batch = messages(mine) if mine else []
        for msg in batch:
            result = send(sub, msg)
            if result == "dead":
                dead.append(sub["e"])
                break
            sent += result == "sent"
    if dead:
        admin("POST", "/remove", json={"endpoints": dead})
    log(f"push: {sent} sent, {len(dead)} expired subscriptions removed")


if __name__ == "__main__":
    try:
        main()
    except requests.RequestException as e:
        sys.exit(f"push: subscription service unreachable: {e}")
