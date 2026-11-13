"""Intel60 static pages.

Writes a page per story (docs/story/<id>.html) and per CVE (docs/cve/<CVE>.html), plus
docs/sitemap.xml and docs/robots.txt, so search engines and link previews can see each
story. Runs after brief.py. Pages stay after a story leaves the feed, so links never break;
pipeline/archive.json remembers every story and CVE seen, for the CVE pages and the sitemap.
"""

import datetime as dt
import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
CARDS_PATH = DOCS / "cards.json"
DEADLINES_PATH = DOCS / "deadlines.json"
ARCHIVE_PATH = ROOT / "pipeline" / "archive.json"
SITE = "https://intel60.app"

SEV_LABEL = {"critical": "Critical", "high": "High", "info": "Info"}


# ---------- helpers ----------

def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def esc(text):
    return html.escape(str(text or ""), quote=True)


def write_if_changed(path, text):
    """Only touches files whose content changed, so a quiet run commits nothing."""
    if path.exists() and path.read_text(encoding="utf-8") == text:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return True


def nice_date(iso_str):
    d = dt.datetime.strptime(iso_str[:10], "%Y-%m-%d")
    return f"{d:%b} {d.day}, {d.year}"


def describe(text, limit=155):
    text = " ".join(str(text or "").split())
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0].rstrip(",.;:") + "…"


def epss_text(epss):
    pct = epss * 100
    return f"{pct:.1f}%" if pct < 1 else f"{round(pct)}%"


def json_ld(data):
    return json.dumps(data, ensure_ascii=False).replace("</", "<\\/")


# ---------- page template ----------

STYLE = """
:root {
  --paper: #E7ECF0; --card: #F8FAFB; --ink: #17212B; --muted: #586572; --rule: #CBD3DB;
  --critical: #C8102E; --high: #B86E00; --info: #3D6A99; --medium: #8A7400; --on-sev: #FFFFFF;
  color-scheme: light dark;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --paper: #0F161F; --card: #18222D; --ink: #E5EAEF; --muted: #94A2AF; --rule: #2B3746;
    --critical: #F04A5E; --high: #F0A22B; --info: #74A3D8; --medium: #E3C94F; --on-sev: #0F161F;
  }
}
:root[data-theme="dark"] {
  --paper: #0F161F; --card: #18222D; --ink: #E5EAEF; --muted: #94A2AF; --rule: #2B3746;
  --critical: #F04A5E; --high: #F0A22B; --info: #74A3D8; --medium: #E3C94F; --on-sev: #0F161F;
  color-scheme: dark;
}
:root[data-theme="light"] { color-scheme: light; }
* { box-sizing: border-box; margin: 0; }
body { background: var(--paper); color: var(--ink); font-family: "Archivo", system-ui, sans-serif; line-height: 1.55; }
a { color: inherit; }
.wrap { max-width: 46rem; margin: 0 auto; padding: 0 1rem; }
header.top { border-bottom: 1px solid var(--rule); }
header.top .wrap { display: flex; align-items: center; justify-content: space-between; gap: 1rem; height: 3.75rem; }
.logo { font-weight: 800; font-size: 1.375rem; font-variation-settings: "wdth" 75; text-decoration: none; letter-spacing: -0.01em; }
.logo span { color: var(--critical); }
.btn { display: inline-block; padding: 0.5rem 1rem; border-radius: 999px; border: 1px solid var(--rule); font-weight: 700; font-size: 0.9375rem; text-decoration: none; white-space: nowrap; }
.btn.primary { background: var(--ink); color: var(--paper); border-color: var(--ink); }
main { padding: 2.5rem 0 3rem; }
.meta { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem 0.875rem; font-size: 0.875rem; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted); }
.sev { padding: 0.25rem 0.625rem; border-radius: 6px; background: var(--sev, var(--info)); color: var(--on-sev); letter-spacing: 0.1em; }
[data-sev="critical"] { --sev: var(--critical); } [data-sev="high"] { --sev: var(--high); }
[data-sev="info"] { --sev: var(--info); } [data-sev="medium"] { --sev: var(--medium); }
h1 { font-size: clamp(2rem, 6vw, 3rem); line-height: 1.02; font-weight: 800; font-variation-settings: "wdth" 75; margin: 1rem 0 1.25rem; letter-spacing: -0.01em; }
.lede { font-size: 1.1875rem; line-height: 1.65; }
section { margin-top: 2.25rem; }
h2 { font-size: 0.8125rem; font-weight: 700; letter-spacing: 0.14em; text-transform: uppercase; color: var(--muted); margin-bottom: 0.75rem; }
.list { list-style: none; padding: 0; border-top: 1px solid var(--rule); }
.list li { border-bottom: 1px solid var(--rule); padding: 0.875rem 0; display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.375rem 0.75rem; }
.list a { font-weight: 700; }
.chip { font-size: 0.8125rem; font-weight: 700; padding: 0.125rem 0.5rem; border-radius: 6px; border: 1px solid var(--rule); color: var(--muted); }
.chip.kev { border-color: var(--critical); color: var(--critical); }
.muted { color: var(--muted); }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr)); gap: 0.75rem; }
.tile { background: var(--card); border: 1px solid var(--rule); border-radius: 12px; padding: 1rem 1.125rem; }
.tile b { display: block; font-size: 1.875rem; line-height: 1.1; font-variation-settings: "wdth" 80; }
.tile span { font-size: 0.875rem; color: var(--muted); }
.cta { margin-top: 2.75rem; background: var(--card); border: 1px solid var(--rule); border-radius: 14px; padding: 1.5rem; }
.cta p { margin: 0.375rem 0 1rem; color: var(--muted); }
.cta .row { display: flex; flex-wrap: wrap; gap: 0.625rem; }
footer { border-top: 1px solid var(--rule); padding: 1.5rem 0 2.5rem; font-size: 0.875rem; color: var(--muted); }
footer a { margin-right: 1rem; }
"""


def page(title, description, path, body, og_type="article", ld=None):
    url = f"{SITE}{path}"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<meta name="description" content="{esc(description)}">
<link rel="canonical" href="{url}">
<meta property="og:type" content="{og_type}">
<meta property="og:site_name" content="Intel60">
<meta property="og:title" content="{esc(title)}">
<meta property="og:description" content="{esc(description)}">
<meta property="og:url" content="{url}">
<meta property="og:image" content="{SITE}/og-image.png">
<meta name="twitter:card" content="summary_large_image">
<link rel="icon" href="/icons/icon-192.png">
<script>try {{ const t = localStorage.getItem("intel60:theme"); if (t === "light" || t === "dark") document.documentElement.dataset.theme = t; }} catch {{}}</script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Archivo:wdth,wght@62..125,400..800&display=swap" rel="stylesheet">
<style>{STYLE}</style>
{f'<script type="application/ld+json">{json_ld(ld)}</script>' if ld else ""}
</head>
<body>
<header class="top"><div class="wrap">
  <a class="logo" href="/">Intel<span>60</span></a>
  <a class="btn primary" href="/">Open Intel60</a>
</div></header>
<main><div class="wrap">
{body}
  <aside class="cta">
    <b>Every security story, in 60 words.</b>
    <p>Intel60 turns news from 8 trusted outlets and CISA into severity-rated briefs every 30 minutes. Free, no sign-up, no ads.</p>
    <div class="row"><a class="btn primary" href="/">Read today's briefs</a><a class="btn" href="/#alerts">Get alerts on this device</a></div>
  </aside>
</div></main>
<footer><div class="wrap">
  <a href="/">Intel60</a><a href="/#/news">News</a><a href="/cve/">All CVEs</a><a href="/#/deadlines">Patch deadlines</a><a href="/#/about">About</a>
</div></footer>
</body>
</html>
"""


# ---------- pages ----------

def cve_chips(info):
    chips = []
    if info.get("cvss") is not None:
        chips.append(f'<span class="chip">CVSS {info["cvss"]:.1f}</span>')
    if info.get("epss") is not None:
        chips.append(f'<span class="chip">EPSS {epss_text(info["epss"])}</span>')
    if info.get("kev"):
        chips.append('<span class="chip kev">Exploited (CISA KEV)</span>')
    return " ".join(chips)


def story_page(c, cves):
    sev = c.get("severity") or "info"
    title = f"{c['headline']} | Intel60"
    description = describe(c["summary"])
    sources = [{"source": c["source"], "url": c["url"]}] + (c.get("also") or [])
    body = [f"""  <article>
    <div class="meta"><span class="sev" data-sev="{esc(sev)}">{esc(SEV_LABEL.get(sev, "Info"))}</span><span>{esc(c.get("category"))}</span><time datetime="{esc(c["published"])}">{nice_date(c["published"])}</time></div>
    <h1>{esc(c["headline"])}</h1>
    <p class="lede">{esc(c["summary"])}</p>
  </article>"""]
    if c.get("cves"):
        rows = "".join(f'<li><a href="/cve/{esc(v)}">{esc(v)}</a> {cve_chips(cves.get(v, {}))}</li>' for v in c["cves"])
        body.append(f'  <section><h2>Vulnerabilities</h2><ul class="list">{rows}</ul></section>')
    rows = "".join(f'<li><a href="{esc(s["url"])}" rel="noopener">{esc(s["source"])}</a><span class="muted">Read the original article</span></li>' for s in sources)
    body.append(f'  <section><h2>{"Sources" if len(sources) > 1 else "Source"}</h2><ul class="list">{rows}</ul>'
                f'<p class="muted" style="margin-top:0.75rem">AI-written summary. Check the original reporting before acting.</p></section>')
    ld = {
        "@context": "https://schema.org", "@type": "NewsArticle",
        "headline": c["headline"], "description": c["summary"],
        "datePublished": c["published"], "dateModified": c.get("added") or c["published"],
        "url": f"{SITE}/story/{c['id']}", "image": f"{SITE}/og-image.png",
        "isBasedOn": [s["url"] for s in sources],
        "publisher": {"@type": "Organization", "name": "Intel60", "url": SITE},
    }
    return page(title, description, f"/story/{c['id']}", "\n".join(body), ld=ld)


def cve_page(cve, info, stories):
    facts = []
    if info.get("cvss") is not None:
        facts.append(f"CVSS {info['cvss']:.1f}" + (f" ({info['sev']})" if info.get("sev") else ""))
    if info.get("epss") is not None:
        facts.append(f"EPSS {epss_text(info['epss'])} chance of exploitation in the next 30 days")
    if info.get("kev"):
        facts.append("in CISA's Known Exploited Vulnerabilities catalog" + (f", patch due {nice_date(info['due'])}" if info.get("due") else ""))
    name = info.get("name")
    title = f"{cve}{': ' + name if name else ''} | Intel60"
    description = describe(f"{cve}{': ' + name if name else ''}. " + (". ".join(facts) + ". " if facts else "")
                           + (info.get("desc") or stories[0][1].get("summary") or ""))

    tiles = []
    if info.get("cvss") is not None:
        tiles.append(f'<div class="tile" data-sev="{esc(info.get("sev") or "")}"><b>{info["cvss"]:.1f}</b><span>CVSS base score{" · " + esc(info["sev"]) if info.get("sev") else ""} (NVD)</span></div>')
    if info.get("epss") is not None:
        tiles.append(f'<div class="tile"><b>{epss_text(info["epss"])}</b><span>Chance of exploitation in the next 30 days (FIRST EPSS)</span></div>')
    if info.get("kev"):
        tiles.append(f'<div class="tile"><b style="color:var(--critical)">Exploited</b><span>In CISA KEV{" · federal patch deadline " + nice_date(info["due"]) if info.get("due") else ""}</span></div>')
    else:
        tiles.append('<div class="tile"><b>Not in KEV</b><span>No confirmed exploitation in CISA\'s catalog yet</span></div>')

    # what the flaw is (NVD's official wording) and what happened (the newest Intel60 brief)
    about = []
    if info.get("desc"):
        about.append(f'<section><h2>What is it?</h2><p class="lede">{esc(info["desc"])}</p>'
                     f'<p class="muted" style="margin-top:0.5rem">Official description from NVD.</p></section>')
    latest = next((s for _, s in stories if s.get("summary")), None)
    if latest:
        about.append(f'<section><h2>What happened</h2><p class="lede">{esc(latest["summary"])}</p>'
                     f'<p class="muted" style="margin-top:0.5rem">From the Intel60 brief of {nice_date(latest["date"])}. AI-written summary: check the sources before acting.</p></section>')
    about = "\n  ".join(about)

    rows = "".join(
        f'<li><span class="sev" data-sev="{esc(s["sev"])}" style="font-size:0.75rem">{esc(SEV_LABEL.get(s["sev"], "Info"))}</span>'
        f'<a href="/story/{esc(sid)}">{esc(s["headline"])}</a><span class="muted">{nice_date(s["date"])}</span></li>'
        for sid, s in stories)
    body = f"""  <div class="meta"><span>Vulnerability</span></div>
  <h1>{esc(cve)}</h1>
  {f'<p class="lede">{esc(name)}</p>' if name else ""}
  <section><div class="tiles">{"".join(tiles)}</div></section>
  {about}
  <section><h2>Intel60 briefs</h2><ul class="list">{rows}</ul></section>
  <section><h2>Official records</h2><ul class="list">
    <li><a href="https://nvd.nist.gov/vuln/detail/{esc(cve)}" rel="noopener">NVD</a><span class="muted">Scores, affected versions and references</span></li>
    <li><a href="https://www.cve.org/CVERecord?id={esc(cve)}" rel="noopener">CVE.org</a><span class="muted">The official CVE record</span></li>
    {f'<li><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={esc(cve)}" rel="noopener">CISA KEV</a><span class="muted">Required action and due date</span></li>' if info.get("kev") else ""}
  </ul></section>"""
    return page(title, description, f"/cve/{cve}", body, og_type="website")


def cve_index(archive, by_cve):
    """The /cve/ page: every tracked CVE, exploited ones first, then newest first."""
    cves = archive["cves"]
    order = sorted(by_cve, key=lambda v: cves.get(v, {}).get("date", ""), reverse=True)
    order = sorted(order, key=lambda v: not cves.get(v, {}).get("kev"))  # stable: exploited first, each group newest first
    rows = "".join(
        f'<li><a href="/cve/{esc(v)}">{esc(v)}</a> {cve_chips(cves.get(v, {}))}'
        f'<span class="muted" style="flex-basis:100%">{esc(cves.get(v, {}).get("name") or by_cve[v][0][1]["headline"])}</span></li>'
        for v in order)
    exploited = sum(1 for v in order if cves.get(v, {}).get("kev"))
    body = f"""  <div class="meta"><span>Vulnerabilities</span></div>
  <h1>Every CVE in the news</h1>
  <p class="lede">{len(order)} vulnerabilities Intel60 has covered, with CVSS and EPSS scores. {exploited} are in CISA's Known Exploited Vulnerabilities catalog and are listed first.</p>
  <section><ul class="list">{rows}</ul></section>"""
    description = f"{len(order)} vulnerabilities in the security news, with CVSS, EPSS and CISA KEV exploitation status, plus a 60-word brief on each."
    return page("Every CVE in the news: scores and exploitation status | Intel60", description, "/cve/", body, og_type="website")


def sitemap(archive):
    urls = [f"  <url><loc>{SITE}/</loc></url>", f"  <url><loc>{SITE}/cve/</loc></url>"]
    for sid, s in sorted(archive["stories"].items(), key=lambda kv: kv[1]["date"], reverse=True):
        urls.append(f"  <url><loc>{SITE}/story/{sid}</loc><lastmod>{s['date']}</lastmod></url>")
    for cve, info in sorted(archive["cves"].items()):
        urls.append(f"  <url><loc>{SITE}/cve/{cve}</loc><lastmod>{info['date']}</lastmod></url>")
    return ('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
            + "\n".join(urls) + "\n</urlset>\n")


# ---------- main ----------

def main():
    cards = load_json(CARDS_PATH, {}).get("cards", [])
    kev = {i["cve"]: i for i in load_json(DEADLINES_PATH, {}).get("items", [])}
    archive = load_json(ARCHIVE_PATH, {"stories": {}, "cves": {}})

    # remember every story and the latest facts about every CVE
    for c in cards:
        archive["stories"][c["id"]] = {"headline": c["headline"], "summary": c["summary"], "sev": c.get("severity") or "info",
                                       "date": c["published"][:10], "cves": c.get("cves") or []}
        for cve in c.get("cves") or []:
            info = archive["cves"].setdefault(cve, {})
            info.update({k: v for k, v in (c.get("cve_info") or {}).get(cve, {}).items() if v is not None and k != "pct"})
            if cve in kev:
                info.update({"kev": True, "due": kev[cve]["due"], "name": kev[cve]["name"]})
            info["date"] = max(info.get("date", ""), c["published"][:10])

    by_cve = {}
    for sid, s in archive["stories"].items():
        for cve in s["cves"]:
            by_cve.setdefault(cve, []).append((sid, s))

    written = 0
    for c in cards:
        written += write_if_changed(DOCS / "story" / f"{c['id']}.html", story_page(c, archive["cves"]))
    for cve, stories in by_cve.items():
        stories.sort(key=lambda kv: kv[1]["date"], reverse=True)
        written += write_if_changed(DOCS / "cve" / f"{cve}.html", cve_page(cve, archive["cves"].get(cve, {}), stories))
    write_if_changed(DOCS / "cve" / "index.html", cve_index(archive, by_cve))
    write_if_changed(DOCS / "sitemap.xml", sitemap(archive))
    write_if_changed(DOCS / "robots.txt", f"User-agent: *\nAllow: /\n\nSitemap: {SITE}/sitemap.xml\n")
    ARCHIVE_PATH.write_text(json.dumps(archive, ensure_ascii=False, indent=0, sort_keys=True), encoding="utf-8")
    print(f"pages: {written} written, {len(archive['stories'])} stories and {len(archive['cves'])} CVEs in the sitemap")


if __name__ == "__main__":
    main()
