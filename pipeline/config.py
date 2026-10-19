"""Intel60 settings. Edit this file to change sources, filters and alerts."""

# News sources (name, RSS URL)
FEEDS = [
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("SecurityWeek", "https://www.securityweek.com/feed/"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml"),
    ("The Record", "https://therecord.media/feed"),
    ("CyberScoop", "https://cyberscoop.com/feed/"),
    ("SANS ISC", "https://isc.sans.edu/rssfeed_full.xml"),
]

# CISA Known Exploited Vulnerabilities catalog (JSON)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Titles matching any of these are dropped before the AI sees them (saves money)
EXCLUDE_PATTERNS = [
    r"\bwebinar\b", r"\bsponsored\b", r"\bpodcast\b", r"\bdeals?\b.*\boff\b",
    r"\d+% off", r"\bweek in review\b", r"\bweekly recap\b", r"\bon-demand\b",
    r"\bwhitepaper\b", r"\bgiveaway\b",
]

# Stories mentioning these get a watchlist tag. High-severity matches also push a notification.
WATCHLIST = [
    "Microsoft 365", "Entra", "Exchange", "Google Workspace", "Chromebook",
    "K-12", "school district", "PowerSchool", "Fortinet", "FortiGate",
    "Palo Alto", "Cisco", "Ivanti", "Citrix", "SonicWall", "AWS",
]

# AI provider: "github" (free, no key), "gemini" (free key) or "anthropic" (paid, ~$3-5/month).
# Can also be set without editing code via the AI_PROVIDER repository variable.
AI_PROVIDER = "github"
MODELS = {
    "github": "openai/gpt-4o-mini",          # GitHub Models, uses the Actions token
    "gemini": "gemini-2.5-flash-lite",       # needs GEMINI_API_KEY secret
    "anthropic": "claude-haiku-4-5-20251001",  # needs ANTHROPIC_API_KEY secret
}
# USD per million tokens (input, output), used for the cost shown in the app
PRICES = {"github": (0, 0), "gemini": (0, 0), "anthropic": (1.00, 5.00)}
CALL_DELAY_SECONDS = 5    # pause between AI calls to stay under free-tier per-minute limits
BATCH_SIZE = 8            # stories per API call
MAX_TEXT_CHARS = 1200     # article text sent per story
MAX_PER_RUN = 60          # safety cap on stories processed per run

# Story selection
MAX_ITEM_AGE_HOURS = 48   # ignore older stories
FIRST_RUN_ITEMS = 15      # on the very first run, only summarize this many

# Card retention in the app
RETENTION_DAYS = 14
MAX_CARDS = 300

# Notifications
TIMEZONE = "America/New_York"
NOTIFY_MAX_PER_RUN = 4    # extra critical stories are grouped into one alert
QUIET_HOURS = (23, 6)     # 11pm to 6am: alerts arrive silently
DIGEST_HOUR = 7           # morning summary notification (local hour); None to disable

# CVE details: CVSS from NVD, exploit probability from FIRST EPSS, KEV status from CISA
CVE_LOOKUPS_PER_RUN = 12  # NVD allows ~5 requests per 30 seconds without a key
CVE_RECHECK_HOURS = 6     # new CVEs often have no score yet; check again after this long
CVE_RECHECK_DAYS = 7      # stop rechecking cards older than this
DEADLINE_WINDOW_DAYS = 30 # patch-deadline tracker: KEV additions from this many days back

# Owner alerts (sent to the NTFY_ADMIN_TOPIC secret, never to readers' topic)
FEED_DOWN_AFTER_RUNS = 6  # alert when a feed has failed this many runs in a row (~3 hours)

# Spending reports to the owner (admin topic). Readers never see costs.
COST_REPORT_WEEKDAY = 0   # weekly month-to-date report: 0 = Monday; None to disable
COST_REPORT_HOUR = 9      # local hour for the weekly report
BUDGET_ALERT_USD = 8.00   # alert once a month when estimated AI spend passes this; None to disable
