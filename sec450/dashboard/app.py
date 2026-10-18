"""Analyst dashboard: `python -m streamlit run sec450/dashboard/app.py`.

Reads everything through the authenticated, audited /v1 API (DD-10, DD-12)
and puts anything that needs a human decision at the top.
"""
from __future__ import annotations

from datetime import timedelta

import pandas as pd
import streamlit as st

from sec450.config import SEVERITY_ORDER, Config, load_config
from sec450.dashboard.client import ApiClient, ApiError
from sec450.dashboard.review import cluster_review_reasons, system_alerts
from sec450.timeutil import Clock, iso

SEVERITY_ICON = {"low": "⚪", "medium": "🟡", "high": "🟠", "critical": "🔴"}
REVIEW_BG = "background-color: rgba(255, 75, 75, 0.18)"

st.set_page_config(page_title="SEC450 Log Review", page_icon="🛡️", layout="wide")


@st.cache_resource
def get_config() -> Config:
    return load_config()


@st.cache_resource
def get_client() -> ApiClient:
    return ApiClient(get_config().dashboard)


@st.cache_data(ttl=get_config().dashboard.refresh_seconds, show_spinner=False)
def _fetch(path: str, items: tuple) -> dict:
    return get_client().get(path, **dict(items))


def fetch(path: str, **params) -> dict:
    # Cached per query so reruns from widget clicks don't burn the 60/min rate limit.
    return _fetch(path, tuple(sorted(params.items())))


def time_window(hours: int, refresh_seconds: int) -> tuple[str, str]:
    # Rounded to the refresh interval so repeated reruns produce the same (cacheable) query.
    now = Clock().now()
    end = now - timedelta(seconds=now.timestamp() % refresh_seconds) + timedelta(seconds=refresh_seconds)
    return iso(end - timedelta(hours=hours)), iso(end)


def sidebar(cfg: Config) -> dict:
    st.sidebar.header("Filters")
    max_hours = cfg.api.max_span_days * 24
    hours = st.sidebar.select_slider(
        "Look back (hours)", options=[h for h in (1, 6, 12, 24, 72, 168, max_hours) if h <= max_hours],
        value=min(cfg.dashboard.lookback_hours, max_hours))
    source_ip = st.sidebar.text_input("Source IP").strip() or None
    user = st.sidebar.text_input("User").strip() or None
    severity = st.sidebar.selectbox("Severity", ["any", *SEVERITY_ORDER])
    if st.sidebar.button("Refresh now"):
        _fetch.clear()
    st.sidebar.caption(f"Auto-refreshes every {cfg.dashboard.refresh_seconds} s. "
                       "Every view is recorded in the API audit log.")
    return {"hours": hours, "source_ip": source_ip, "user": user,
            "severity": None if severity == "any" else severity, "limit": cfg.api.max_limit}


def render_review_card(cluster: dict, reasons: list[str], report: dict | None) -> None:
    sev = cluster["severity"]
    with st.container(border=True):
        left, right = st.columns([3, 1])
        left.markdown(f"#### {SEVERITY_ICON[sev]} Cluster {cluster['cluster_id']} · {cluster['rule_id']} · "
                      f"`{cluster['group_key']}`")
        right.markdown(f"**{sev.upper()}** · {cluster['state'].replace('_', ' ')}")
        st.caption(f"{cluster['event_count']} events, {cluster['window_start']} → {cluster['window_end']}"
                   + (f" · continues cluster {cluster['prev_cluster_id']}" if cluster["prev_cluster_id"] else ""))
        for reason in reasons:
            st.markdown(f"- ⚠️ {reason}")
        ai = cluster.get("ai_assessment")
        if ai:
            st.info(f"**{ai['label']}** — {ai['classification']} (recommends {ai['recommended_severity']})\n\n"
                    f"{ai['explanation']}")
        if report:
            body = report["body"]
            with st.expander(f"Report {report['report_id']} — {body['summary']}"):
                st.json({k: body[k] for k in ("requester", "data_destination", "matched_rule", "integrity")},
                        expanded=False)
                st.dataframe(pd.DataFrame(body["timeline"]), hide_index=True, width="stretch")
                st.code("\n".join(line["text"] for line in body["raw_lines"]), language=None)


def render_events(events: list[dict], flagged_ips: set[str]) -> None:
    if not events:
        st.write("No events in this range.")
        return
    df = pd.DataFrame(events)

    def why(row: pd.Series) -> str:
        notes = []
        if row["client_ip"] in flagged_ips:
            notes.append("source in review cluster")
        if row["clock_anomaly"]:
            notes.append("clock anomaly")
        return ", ".join(notes)

    df.insert(0, "review", df.apply(why, axis=1))
    only_flagged = st.toggle("Only rows needing review")
    if only_flagged:
        df = df[df["review"] != ""]
    styled = df.style.apply(lambda row: [REVIEW_BG if row["review"] else ""] * len(row), axis=1)
    st.dataframe(styled, hide_index=True, width="stretch",
                 column_order=["review", "ts", "source", "host", "client_ip", "username", "action", "target",
                               "outcome", "status_code", "bytes_sent", "country", "asn", "clock_anomaly"])


def main() -> None:
    cfg = get_config()
    st.title("🛡️ SEC450 Log Review")
    filters = sidebar(cfg)

    @st.fragment(run_every=cfg.dashboard.refresh_seconds)
    def body() -> None:
        params = {k: v for k, v in filters.items() if k != "hours"}
        params["start"], params["end"] = time_window(filters["hours"], cfg.dashboard.refresh_seconds)
        try:
            events = fetch("/v1/events", **params)
            clusters = fetch("/v1/clusters", **params)
            reports = fetch("/v1/reports", **{**params, "limit": min(100, cfg.api.max_limit)})
            integrity = fetch("/v1/integrity")
        except ApiError as exc:
            st.error(str(exc))
            return

        alerts = system_alerts(integrity, clusters["collection_gaps"], events["events"])
        reports_by_cluster = {r["cluster_id"]: r for r in reports["reports"]}
        review = [(c, reasons) for c in clusters["clusters"] if (reasons := cluster_review_reasons(c))]
        # Most severe first, newest first within a severity (the API already returns newest first).
        review.sort(key=lambda cr: SEVERITY_ORDER[cr[0]["severity"]], reverse=True)

        for alert in alerts:
            st.error(alert, icon="🚨")
        m = st.columns(4)
        m[0].metric("Events", events["count"])
        m[1].metric("Clusters", clusters["count"])
        m[2].metric("Need human review", len(review))
        m[3].metric("Integrity", integrity["batches"]["status"])
        if events["count"] == cfg.api.max_limit:
            st.caption(f"Showing the newest {cfg.api.max_limit} events; narrow the filters to see more.")

        tab_review, tab_events, tab_clusters = st.tabs(
            [f"Needs review ({len(review)})", f"Events ({events['count']})", f"All clusters ({clusters['count']})"])
        with tab_review:
            if not review and not alerts:
                st.success("Nothing needs human review in this range.")
            for cluster, reasons in review:
                render_review_card(cluster, reasons, reports_by_cluster.get(cluster["cluster_id"]))
        with tab_events:
            render_events(events["events"], {c["group_key"] for c, _ in review})
        with tab_clusters:
            if clusters["clusters"]:
                df = pd.DataFrame(clusters["clusters"]).drop(columns=["ai_assessment"])
                df.insert(0, "needs_review", [bool(cluster_review_reasons(c)) for c in clusters["clusters"]])
                st.dataframe(df, hide_index=True, width="stretch")
            else:
                st.write("No clusters in this range.")
        st.caption(f"Updated {iso(Clock().now())}")

    body()


main()
