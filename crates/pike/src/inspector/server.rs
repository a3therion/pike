use axum::{
    extract::State,
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        Html,
    },
    routing::{get, post},
    Json, Router,
};
use futures::stream::Stream;
use serde_json::json;
use std::convert::Infallible;
use std::sync::Arc;
use tower::ServiceBuilder;

use super::storage::RequestStore;

pub struct InspectorServer {
    store: Arc<RequestStore>,
    port: u16,
}

impl InspectorServer {
    pub fn new(store: Arc<RequestStore>, port: u16) -> Self {
        Self { store, port }
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        let app = Router::new()
            .route("/", get(Self::handle_root))
            .route("/api/requests", get(Self::handle_requests))
            .route("/api/requests/stream", get(Self::handle_stream))
            .route("/api/requests/clear", post(Self::handle_clear))
            .layer(ServiceBuilder::new())
            .with_state(self.store);

        let addr = format!("127.0.0.1:{}", self.port);
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        println!("Inspector server running on http://{}", addr);

        axum::serve(listener, app).await?;

        Ok(())
    }

    async fn handle_root() -> Html<&'static str> {
        Html(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pike Inspector</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Geist+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        *, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --bg: oklch(0.207 0.008 67);
            --surface: oklch(0.224 0.009 75);
            --border: oklch(0.268 0.012 67);
            --accent: oklch(0.714 0.154 59);
            --text: oklch(0.91 0.016 74);
            --dim: oklch(0.603 0.023 72);
            --green: oklch(0.658 0.134 151);
            --blue: oklch(0.693 0.165 254);
            --amber: oklch(0.714 0.154 59);
            --red: oklch(0.654 0.176 30);
            --purple: oklch(0.70 0.12 310);
            --font: 'Geist Mono', 'SF Mono', 'Cascadia Code', 'Consolas', monospace;
            --radius: 8px;
        }
        body {
            font-family: var(--font);
            background: var(--bg);
            color: var(--text);
            height: 100vh;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }
        header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px 20px;
            border-bottom: 1px solid var(--border);
            background: var(--surface);
        }
        .logo {
            font-size: 13px;
            font-weight: 600;
            letter-spacing: 0.5px;
            color: var(--accent);
        }
        .header-right {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .req-count {
            font-size: 11px;
            color: var(--dim);
        }
        .status {
            font-size: 11px;
            color: var(--green);
            display: flex;
            align-items: center;
            gap: 4px;
        }
        .status.disconnected { color: var(--red); }
        .toolbar {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 10px 20px;
            border-bottom: 1px solid var(--border);
            background: var(--surface);
        }
        .toolbar select,
        .toolbar input {
            background: var(--bg);
            border: 1px solid var(--border);
            color: var(--text);
            font-family: var(--font);
            font-size: 11px;
            padding: 6px 10px;
            border-radius: var(--radius);
            outline: none;
            transition: border-color 0.15s;
        }
        .toolbar select:focus,
        .toolbar input:focus {
            border-color: var(--accent);
        }
        .toolbar input { flex: 1; min-width: 120px; }
        .toolbar input::placeholder { color: var(--dim); }
        .toolbar button {
            background: transparent;
            border: 1px solid var(--border);
            color: var(--dim);
            font-family: var(--font);
            font-size: 11px;
            padding: 6px 12px;
            border-radius: var(--radius);
            cursor: pointer;
            transition: all 0.15s;
        }
        .toolbar button:hover {
            border-color: var(--accent);
            color: var(--accent);
        }
        .table-container {
            flex: 1;
            overflow-y: auto;
            scrollbar-width: thin;
            scrollbar-color: var(--border) transparent;
        }
        .table-container::-webkit-scrollbar { width: 6px; }
        .table-container::-webkit-scrollbar-track { background: transparent; }
        .table-container::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
        }
        thead {
            position: sticky;
            top: 0;
            z-index: 2;
        }
        th {
            background: var(--surface);
            color: var(--dim);
            font-weight: 500;
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            padding: 8px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border);
            white-space: nowrap;
        }
        td {
            padding: 7px 16px;
            border-bottom: 1px solid var(--border);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        td.path {
            max-width: 360px;
            color: var(--text);
        }
        tr {
            cursor: pointer;
            transition: background 0.1s;
        }
        tbody tr:hover { background: oklch(0.24 0.01 70); }
        tbody tr.active { background: oklch(0.28 0.03 60); }
        .badge {
            display: inline-block;
            border-radius: 3px;
            padding: 1px 6px;
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 0.3px;
        }
        .m-GET    { background: var(--green); color: oklch(0.207 0.008 67); }
        .m-POST   { background: var(--blue); color: #fff; }
        .m-PUT    { background: var(--amber); color: oklch(0.207 0.008 67); }
        .m-DELETE { background: var(--red); color: #fff; }
        .m-PATCH  { background: var(--purple); color: #fff; }
        .m-HEAD   { background: var(--dim); color: #fff; }
        .m-OPTIONS{ background: var(--dim); color: #fff; }
        .s2xx { color: var(--green); }
        .s3xx { color: var(--blue); }
        .s4xx { color: var(--amber); }
        .s5xx { color: var(--red); }
        .time-col { color: var(--dim); }
        .dur-col { color: var(--dim); }
        .size-col { color: var(--dim); }
        #detail-panel {
            position: fixed;
            right: 0;
            top: 0;
            bottom: 0;
            width: 420px;
            background: var(--surface);
            border-left: 1px solid var(--border);
            z-index: 10;
            transform: translateX(100%);
            transition: transform 0.2s ease;
            display: flex;
            flex-direction: column;
            overflow-y: auto;
            scrollbar-width: thin;
            scrollbar-color: var(--border) transparent;
        }
        #detail-panel.open {
            transform: translateX(0);
        }
        .detail-header {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 16px 20px;
            border-bottom: 1px solid var(--border);
        }
        .detail-header .path {
            flex: 1;
            font-size: 12px;
            color: var(--text);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .detail-header button {
            background: transparent;
            border: none;
            color: var(--dim);
            font-size: 16px;
            cursor: pointer;
            padding: 2px 6px;
            border-radius: 3px;
            transition: all 0.15s;
        }
        .detail-header button:hover {
            color: var(--text);
            background: var(--bg);
        }
        .detail-grid {
            display: grid;
            grid-template-columns: auto 1fr;
            gap: 6px 16px;
            padding: 16px 20px;
            font-size: 12px;
            border-bottom: 1px solid var(--border);
        }
        .detail-grid .label {
            color: var(--dim);
            font-size: 11px;
        }
        .detail-section {
            padding: 12px 20px;
            border-bottom: 1px solid var(--border);
        }
        .detail-section h4 {
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            color: var(--dim);
            margin-bottom: 8px;
        }
        .detail-section pre {
            font-family: var(--font);
            font-size: 11px;
            color: var(--text);
            background: var(--bg);
            padding: 10px;
            border-radius: var(--radius);
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }
        .empty-state {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 80px 20px;
            color: var(--dim);
        }
        .empty-state .icon { font-size: 32px; margin-bottom: 12px; opacity: 0.4; }
        .empty-state p { font-size: 12px; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        .status .dot { animation: pulse 2s ease-in-out infinite; }
    </style>
</head>
<body>
    <header>
        <span class="logo">&#9889; Pike Inspector</span>
        <div class="header-right">
            <span class="req-count" id="req-count"></span>
            <span class="status" id="status"><span class="dot">&#9679;</span>&nbsp;Live</span>
        </div>
    </header>
    <div class="toolbar">
        <select id="method-filter">
            <option value="all">All Methods</option>
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
            <option value="DELETE">DELETE</option>
            <option value="PATCH">PATCH</option>
        </select>
        <select id="status-filter">
            <option value="all">All Status</option>
            <option value="2xx">2xx Success</option>
            <option value="3xx">3xx Redirect</option>
            <option value="4xx">4xx Client Error</option>
            <option value="5xx">5xx Server Error</option>
        </select>
        <input id="path-search" placeholder="Filter by path...">
        <button id="clear-btn">Clear</button>
    </div>
    <div class="table-container">
        <table id="requests-table">
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Method</th>
                    <th>Path</th>
                    <th>Status</th>
                    <th>Duration</th>
                    <th>Size</th>
                </tr>
            </thead>
            <tbody id="tbody"></tbody>
        </table>
        <div class="empty-state" id="empty">
            <div class="icon">&#9889;</div>
            <p>Waiting for requests&hellip;</p>
        </div>
    </div>
    <div id="detail-panel">
    </div>
    <script>
        let allRequests = [];
        let activeId = null;
        let evtSource = null;

        async function fetchRequests() {
            try {
                const res = await fetch('/api/requests');
                const data = await res.json();
                allRequests = data.requests || [];
                renderTable();
            } catch(e) {}
        }

        function connectSSE() {
            evtSource = new EventSource('/api/requests/stream');
            evtSource.onopen = function() {
                var s = document.getElementById('status');
                s.innerHTML = '<span class="dot">&#9679;</span>&nbsp;Live';
                s.className = 'status';
            };
            evtSource.onmessage = function(e) {
                try {
                    var r = JSON.parse(e.data);
                    allRequests.push(r);
                    renderTable();
                } catch(err) {}
            };
            evtSource.onerror = function() {
                var s = document.getElementById('status');
                s.innerHTML = '&#9679; Disconnected';
                s.className = 'status disconnected';
            };
        }

        function fmtSize(body) {
            if (!body) return '-';
            var n = body.length;
            if (n < 1024) return n + ' B';
            if (n < 1048576) return (n/1024).toFixed(1) + ' KB';
            return (n/1048576).toFixed(1) + ' MB';
        }

        function headerEntries(headers) {
            if (!headers) return [];
            if (Array.isArray(headers)) {
                return headers
                    .filter(function(entry) { return entry && entry.name; })
                    .map(function(entry) { return [entry.name, entry.value || '']; });
            }
            return Object.entries(headers);
        }

        function renderTable() {
            var method = document.getElementById('method-filter').value;
            var status = document.getElementById('status-filter').value;
            var path = document.getElementById('path-search').value.toLowerCase();

            var cnt = document.getElementById('req-count');
            cnt.textContent = allRequests.length + ' request' + (allRequests.length !== 1 ? 's' : '');

            var filtered = allRequests.filter(function(r) {
                if (method && method !== 'all' && r.method !== method) return false;
                if (status === '2xx' && !(r.response_status >= 200 && r.response_status < 300)) return false;
                if (status === '3xx' && !(r.response_status >= 300 && r.response_status < 400)) return false;
                if (status === '4xx' && !(r.response_status >= 400 && r.response_status < 500)) return false;
                if (status === '5xx' && !(r.response_status >= 500)) return false;
                if (path && !r.path.toLowerCase().includes(path)) return false;
                return true;
            });

            var empty = document.getElementById('empty');
            empty.style.display = filtered.length === 0 ? 'flex' : 'none';

            var tbody = document.getElementById('tbody');
            tbody.innerHTML = filtered.map(function(r) {
                var sc = r.response_status;
                var cls = sc >= 500 ? 's5xx' : sc >= 400 ? 's4xx' : sc >= 300 ? 's3xx' : 's2xx';
                var mcls = 'm-' + r.method;
                var t = new Date(r.timestamp).toLocaleTimeString();
                var act = r.id === activeId ? ' active' : '';
                return '<tr class="' + act + '" onclick="showDetail(\'' + r.id + '\')">'+
                    '<td class="time-col">' + t + '</td>'+
                    '<td><span class="badge ' + mcls + '">' + r.method + '</span></td>'+
                    '<td class="path">' + r.path + '</td>'+
                    '<td class="' + cls + '">' + sc + '</td>'+
                    '<td class="dur-col">' + r.duration_ms + 'ms</td>'+
                    '<td class="size-col">' + fmtSize(r.response_body) + '</td>'+
                    '</tr>';
            }).join('');
        }

        function showDetail(id) {
            var r = allRequests.find(function(x) { return x.id === id; });
            if (!r) return;
            activeId = id;
            renderTable();
            var panel = document.getElementById('detail-panel');
            var sc = r.response_status;
            var cls = sc >= 500 ? 's5xx' : sc >= 400 ? 's4xx' : sc >= 300 ? 's3xx' : 's2xx';
            var html = '<div class="detail-header">'+
                '<span class="badge m-' + r.method + '">' + r.method + '</span>'+
                '<span class="path">' + r.path + '</span>'+
                '<button onclick="closeDetail()">&#10005;</button>'+
                '</div>';
            html += '<div class="detail-grid">'+
                '<span class="label">Status</span><span class="' + cls + '">' + r.response_status + '</span>'+
                '<span class="label">Duration</span><span>' + r.duration_ms + 'ms</span>'+
                '<span class="label">Request Body</span><span>' + fmtSize(r.body) + '</span>'+
                '<span class="label">Response Body</span><span>' + fmtSize(r.response_body) + '</span>'+
                '<span class="label">Time</span><span>' + new Date(r.timestamp).toLocaleString() + '</span>'+
                '</div>';
            var reqHeaderEntries = headerEntries(r.headers);
            if (reqHeaderEntries.length) {
                html += '<div class="detail-section"><h4>Request Headers</h4>'+
                    '<pre>' + reqHeaderEntries.map(function(e){ return e[0]+': '+e[1]; }).join('\n') + '</pre></div>';
            }
            if (r.body) {
                html += '<div class="detail-section"><h4>Request Body</h4><pre>' + r.body + '</pre></div>';
            }
            var respHeaderEntries = headerEntries(r.response_headers);
            if (respHeaderEntries.length) {
                html += '<div class="detail-section"><h4>Response Headers</h4>'+
                    '<pre>' + respHeaderEntries.map(function(e){ return e[0]+': '+e[1]; }).join('\n') + '</pre></div>';
            }
            if (r.response_body) {
                html += '<div class="detail-section"><h4>Response Body</h4><pre>' + r.response_body + '</pre></div>';
            }
            panel.innerHTML = html;
            panel.classList.add('open');
        }

        function closeDetail() {
            activeId = null;
            document.getElementById('detail-panel').classList.remove('open');
            renderTable();
        }

        document.addEventListener('DOMContentLoaded', function() {
            fetchRequests();
            connectSSE();

            ['method-filter', 'status-filter', 'path-search'].forEach(function(id) {
                document.getElementById(id).addEventListener('input', renderTable);
            });

            document.getElementById('clear-btn').addEventListener('click', function() {
                fetch('/api/requests/clear', { method: 'POST' }).then(function() {
                    allRequests = [];
                    document.getElementById('path-search').value = '';
                    document.getElementById('method-filter').value = 'all';
                    document.getElementById('status-filter').value = 'all';
                    renderTable();
                });
            });

            document.addEventListener('keydown', function(e) {
                if (e.key === 'Escape') closeDetail();
            });
        });
    </script>
</body>
</html>"#,
        )
    }

    async fn handle_requests(
        State(store): State<Arc<RequestStore>>,
    ) -> (StatusCode, Json<serde_json::Value>) {
        let requests = store.get_all();
        (
            StatusCode::OK,
            Json(json!({
                "requests": requests,
                "count": requests.len()
            })),
        )
    }

    async fn handle_stream(
        State(store): State<Arc<RequestStore>>,
    ) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
        let mut rx = store.subscribe();

        let stream = async_stream::stream! {
            loop {
                match rx.recv().await {
                    Ok(req) => {
                        if let Ok(data) = serde_json::to_string(&req) {
                            yield Ok(Event::default().data(data));
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        };

        Sse::new(stream).keep_alive(KeepAlive::default())
    }

    async fn handle_clear(State(store): State<Arc<RequestStore>>) -> StatusCode {
        store.clear();
        StatusCode::OK
    }
}
