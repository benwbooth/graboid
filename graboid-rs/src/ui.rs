use std::collections::{BTreeMap, HashMap};

use html_compile::compile::build_component;
use html_compile::types::{Attribute, Child, Component};
use serde_json::Value;

use crate::models::{NoteEntry, NoteStats};
use crate::state::GitInfo;

const BASE_CSS: &str = include_str!("ui_assets/base.css");
const BASE_JS: &str = include_str!("ui_assets/base.js");
const INDEX_JS: &str = include_str!("ui_assets/index.js");
const CONFIG_JS: &str = include_str!("ui_assets/config.js");
const JOBS_JS: &str = include_str!("ui_assets/jobs.js");
const LOGIN_CSS: &str = include_str!("ui_assets/login.css");

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub path: String,
    pub scheme: String,
    pub netloc: String,
    pub query_params: HashMap<String, String>,
}

#[derive(Debug, Clone)]
struct UiElement {
    tag: &'static str,
    attrs: Vec<(&'static str, String)>,
    content: UiContent,
}

#[derive(Debug, Clone)]
enum UiContent {
    Empty,
    Text(String),
    Children(Vec<UiElement>),
}

impl UiElement {
    fn new(tag: &'static str) -> Self {
        Self {
            tag,
            attrs: Vec::new(),
            content: UiContent::Empty,
        }
    }

    fn with_attr(mut self, label: &'static str, value: impl Into<String>) -> Self {
        self.attrs.push((label, value.into()));
        self
    }

    fn maybe_attr(
        mut self,
        condition: bool,
        label: &'static str,
        value: impl Into<String>,
    ) -> Self {
        if condition {
            self.attrs.push((label, value.into()));
        }
        self
    }

    fn with_text(mut self, text: impl Into<String>) -> Self {
        self.content = UiContent::Text(text.into());
        self
    }

    fn with_children(mut self, children: Vec<UiElement>) -> Self {
        self.content = UiContent::Children(children);
        self
    }

    fn render(&self) -> String {
        let component = self.to_component();
        build_component(&component)
    }

    fn to_component<'a>(&'a self) -> Component<'a> {
        let meta = if self.attrs.is_empty() {
            None
        } else {
            Some(
                self.attrs
                    .iter()
                    .map(|(label, value)| Attribute {
                        label,
                        value: value.as_str(),
                    })
                    .collect(),
            )
        };

        let child = match &self.content {
            UiContent::Empty => Child::NoChild,
            UiContent::Text(value) => Child::Text(value.as_str()),
            UiContent::Children(nodes) => Child::ComponentVec(
                nodes
                    .iter()
                    .map(|node| Box::new(node.to_component()))
                    .collect(),
            ),
        };

        Component {
            tag: self.tag,
            meta,
            child,
        }
    }
}

fn el(tag: &'static str) -> UiElement {
    UiElement::new(tag)
}

fn text_el(tag: &'static str, text: impl Into<String>) -> UiElement {
    UiElement::new(tag).with_text(text)
}

fn nav_link(path: &str, label: &str, active_path: &str) -> UiElement {
    el("a")
        .with_attr("href", path)
        .maybe_attr(active_path == path, "class", "active")
        .with_text(label)
}

fn option(value: &str, label: &str, selected: bool) -> UiElement {
    el("option")
        .with_attr("value", value)
        .maybe_attr(selected, "selected", "selected")
        .with_text(label)
}

fn labeled_control(label_for: &str, label: &str, control: UiElement) -> Vec<UiElement> {
    vec![text_el("label", label).with_attr("for", label_for), control]
}

fn input_base(input_type: &str, name: &str, id: &str, value: &str) -> UiElement {
    el("input")
        .with_attr("type", input_type)
        .with_attr("name", name)
        .with_attr("id", id)
        .with_attr("value", escape_html_attr(value))
}

fn render_login_page_content(error: bool) -> Vec<UiElement> {
    let mut children = vec![el("div").with_attr("class", "logo").with_children(vec![
        text_el("h1", "Graboid"),
        text_el("p", "Browser automation agent"),
    ])];

    if error {
        children.push(
            el("div")
                .with_attr("class", "error")
                .with_text("Invalid username or password"),
        );
    }

    children.push(
        el("form")
            .with_attr("method", "POST")
            .with_attr("action", "/login")
            .with_children(vec![
                el("div").with_attr("class", "form-group").with_children({
                    let mut items = Vec::new();
                    items.extend(labeled_control(
                        "username",
                        "Username",
                        input_base("text", "username", "username", "")
                            .with_attr("required", "required")
                            .with_attr("autofocus", "autofocus"),
                    ));
                    items
                }),
                el("div").with_attr("class", "form-group").with_children({
                    let mut items = Vec::new();
                    items.extend(labeled_control(
                        "password",
                        "Password",
                        input_base("password", "password", "password", "")
                            .with_attr("required", "required"),
                    ));
                    items
                }),
                text_el("button", "Sign In").with_attr("type", "submit"),
            ]),
    );

    vec![
        el("div")
            .with_attr("class", "login-container")
            .with_children(children),
    ]
}

pub fn render_login_page(error: bool) -> String {
    let body_nodes = render_login_page_content(error);
    render_document("Login - Graboid", LOGIN_CSS, false, body_nodes, &[])
}

pub fn render_index_page(
    request: &RequestContext,
    git: &GitInfo,
    is_running: bool,
    current_task: &str,
) -> String {
    let status_text = if is_running {
        format!("Running: {current_task}")
    } else {
        "Idle".to_string()
    };

    let content = vec![
        text_el("h1", "Dashboard"),
        el("div").with_attr("class", "grid").with_children(vec![
            el("div").with_attr("class", "card").with_children(vec![
                text_el("h2", "Quick Actions"),
                text_el(
                    "p",
                    "Browse websites and download content using AI-powered automation.",
                )
                .with_attr("style", "color: var(--text-dim); margin-bottom: 1rem;"),
                text_el("a", "Open Browser View")
                    .with_attr("href", "/browser")
                    .with_attr("class", "btn"),
                text_el("a", "Configure")
                    .with_attr("href", "/config")
                    .with_attr("class", "btn secondary")
                    .with_attr("style", "margin-left: 0.5rem;"),
            ]),
            el("div").with_attr("class", "card").with_children(vec![
                text_el("h2", "Status"),
                el("div")
                    .with_attr(
                        "style",
                        "display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem;",
                    )
                    .with_children(vec![
                        el("div")
                            .with_attr("class", "status-dot")
                            .with_attr("id", "dashboard-status-dot"),
                        text_el("span", escape_html(&status_text))
                            .with_attr("id", "dashboard-status-text"),
                    ]),
                el("div")
                    .with_attr("id", "download-stats")
                    .with_attr("hx-get", "/api/status")
                    .with_attr("hx-trigger", "every 5s")
                    .with_attr("hx-swap", "innerHTML")
                    .with_children(vec![
                        text_el("p", "Loading status...")
                            .with_attr("style", "color: var(--text-dim);"),
                    ]),
            ]),
        ]),
        el("div").with_attr("class", "card").with_children(vec![
            text_el("h2", "Recent Activity"),
            el("div")
                .with_attr("id", "messages")
                .with_attr("class", "messages")
                .with_children(vec![
                    text_el(
                        "p",
                        "No recent activity. Start a download to see updates here.",
                    )
                    .with_attr("style", "color: var(--text-dim);"),
                ]),
        ]),
        el("div").with_attr("class", "card").with_children(vec![
            text_el("h2", "Agent Notes"),
            el("div")
                .with_attr("hx-get", "/api/notes/stats")
                .with_attr("hx-trigger", "load")
                .with_attr("hx-swap", "innerHTML")
                .with_children(vec![
                    text_el("p", "Loading...").with_attr("style", "color: var(--text-dim);"),
                ]),
        ]),
    ];

    render_app_page(
        request,
        git,
        "Dashboard - Graboid",
        content,
        Some(INDEX_JS.to_string()),
    )
}

pub fn render_config_page(
    request: &RequestContext,
    git: &GitInfo,
    config: &serde_json::Map<String, Value>,
    config_path: &str,
) -> String {
    let saved = request
        .query_params
        .get("saved")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);

    let content = render_config_content(config, config_path, saved);
    render_app_page(
        request,
        git,
        "Configuration - Graboid",
        content,
        Some(CONFIG_JS.to_string()),
    )
}

pub fn render_notes_page(
    request: &RequestContext,
    git: &GitInfo,
    stats: &NoteStats,
    domains: &[String],
    domain_notes: &BTreeMap<String, Vec<NoteEntry>>,
) -> String {
    let content = render_notes_content(stats, domains, domain_notes);
    render_app_page(request, git, "Agent Notes - Graboid", content, None)
}

pub fn render_browser_page(request: &RequestContext, git: &GitInfo) -> String {
    let content = vec![
        text_el("h1", "Browser View"),
        el("div").with_attr("class", "grid-2").with_children(vec![
            el("div").with_children(vec![
                el("div")
                    .with_attr("class", "card")
                    .with_attr("style", "padding: 0; overflow: hidden;")
                    .with_children(vec![
                        el("div")
                            .with_attr("id", "browser-view")
                            .with_children(vec![
                                el("img")
                                    .with_attr("id", "browser-screenshot")
                                    .with_attr("style", "display: none;")
                                    .with_attr("alt", "Browser Screenshot"),
                                el("div")
                                    .with_attr("id", "browser-placeholder")
                                    .with_attr("class", "placeholder")
                                    .with_children(vec![
                                        text_el("p", "No browser session active"),
                                        text_el(
                                            "p",
                                            "Start a browse task to see the browser here",
                                        )
                                        .with_attr(
                                            "style",
                                            "font-size: 0.875rem; margin-top: 0.5rem;",
                                        ),
                                    ]),
                            ]),
                    ]),
                el("div").with_attr("class", "card").with_children(vec![
                    el("div")
                        .with_attr("style", "display: flex; align-items: center; gap: 1rem;")
                        .with_children(vec![
                            text_el("span", "URL:")
                                .with_attr("style", "color: var(--text-dim);"),
                            text_el("code", "-")
                                .with_attr("id", "browser-url")
                                .with_attr("style", "flex: 1; color: var(--accent);"),
                        ]),
                ]),
            ]),
            el("div").with_children(vec![
                el("div").with_attr("class", "card").with_children(vec![
                    text_el("h2", "Agent Messages"),
                    el("div")
                        .with_attr("id", "messages")
                        .with_attr("class", "messages")
                        .with_attr("style", "max-height: 600px;")
                        .with_children(vec![
                            text_el("p", "Waiting for agent activity...")
                                .with_attr("style", "color: var(--text-dim);"),
                        ]),
                ]),
                el("div").with_attr("class", "card").with_children(vec![
                    text_el("h2", "Controls"),
                    text_el("p", "Run tasks from the command line:")
                        .with_attr("style", "color: var(--text-dim); margin-bottom: 1rem;"),
                    text_el(
                        "code",
                        "graboid browse https://example.com \"find download links\"",
                    )
                    .with_attr(
                        "style",
                        "display: block; background: var(--bg); padding: 1rem; border-radius: 0.25rem; margin-bottom: 1rem;",
                    ),
                    text_el(
                        "p",
                        "The browser view will update automatically when a task starts.",
                    )
                    .with_attr("style", "color: var(--text-dim); font-size: 0.875rem;"),
                ]),
            ]),
        ]),
    ];

    render_app_page(request, git, "Browser View - Graboid", content, None)
}

pub fn render_jobs_page(request: &RequestContext, git: &GitInfo, api_key: &str) -> String {
    let content = render_jobs_content(request, api_key);
    let mut script = JOBS_JS.replace("__API_KEY__", &escape_js_string(api_key));
    script.push_str("\nrefreshJobs();\n");

    render_app_page(request, git, "Jobs - Graboid", content, Some(script))
}

fn render_app_page(
    request: &RequestContext,
    git: &GitInfo,
    title: &str,
    content: Vec<UiElement>,
    page_script: Option<String>,
) -> String {
    let mut body_nodes = vec![render_nav(request, git), el("main").with_children(content)];

    let mut scripts = vec![BASE_JS.to_string()];
    if let Some(script) = page_script {
        scripts.push(script);
    }

    for script in scripts {
        body_nodes.push(el("script").with_text(script));
    }

    render_document(title, BASE_CSS, true, body_nodes, &[])
}

fn render_document(
    title: &str,
    css: &str,
    include_htmx: bool,
    body_nodes: Vec<UiElement>,
    scripts: &[String],
) -> String {
    let mut head_children = vec![
        el("meta").with_attr("charset", "UTF-8"),
        el("meta")
            .with_attr("name", "viewport")
            .with_attr("content", "width=device-width, initial-scale=1.0"),
        text_el("title", escape_html(title)),
    ];

    if include_htmx {
        head_children.push(el("script").with_attr("src", "https://unpkg.com/htmx.org@1.9.10"));
    }

    head_children.push(el("style").with_text(css.to_string()));

    let mut body_children = body_nodes;
    for script in scripts {
        body_children.push(el("script").with_text(script.clone()));
    }

    let html = el("html").with_attr("lang", "en").with_children(vec![
        el("head").with_children(head_children),
        el("body").with_children(body_children),
    ]);

    format!("<!DOCTYPE html>\n{}", html.render())
}

fn render_nav(request: &RequestContext, git: &GitInfo) -> UiElement {
    let mut children = vec![
        text_el("span", "Graboid").with_attr("class", "logo"),
        el("span")
            .with_attr("class", "backend-status")
            .with_attr("id", "backend-status")
            .with_attr("title", "Backend disconnected"),
    ];

    if let Some(version) = render_version(git) {
        children.push(version);
    }

    children.extend([
        nav_link("/", "Dashboard", &request.path),
        nav_link("/jobs", "Jobs", &request.path),
        nav_link("/browser", "Browser", &request.path),
        nav_link("/notes", "Notes", &request.path),
        nav_link("/config", "Config", &request.path),
        el("div")
            .with_attr("class", "status-indicator")
            .with_children(vec![
                el("div")
                    .with_attr("class", "status-dot")
                    .with_attr("id", "status-dot"),
                text_el("span", "Idle").with_attr("id", "status-text"),
            ]),
        text_el("a", "Logout")
            .with_attr("href", "/logout")
            .with_attr("class", "logout"),
    ]);

    el("nav").with_children(children)
}

fn render_version(git: &GitInfo) -> Option<UiElement> {
    if git.backend.hash.trim().is_empty() && git.frontend.hash.trim().is_empty() {
        return None;
    }

    let title = format!(
        "Backend build {} {} | Frontend assets {} {}",
        git.backend.timestamp, git.backend.tz, git.frontend.timestamp, git.frontend.tz
    );

    let backend_line = el("span")
        .with_attr("class", "version-line")
        .with_children(vec![
            text_el(
                "span",
                format!(
                    "BE {} {} {} (",
                    escape_html(&git.backend.hash),
                    escape_html(&git.backend.timestamp),
                    escape_html(&git.backend.tz)
                ),
            ),
            el("span")
                .with_attr("class", "version-relative")
                .with_attr("data-epoch", git.backend.epoch.to_string()),
            text_el("span", ")"),
        ]);

    let frontend_line = el("span")
        .with_attr("class", "version-line")
        .with_children(vec![
            text_el(
                "span",
                format!(
                    "FE {} {} {} (",
                    escape_html(&git.frontend.hash),
                    escape_html(&git.frontend.timestamp),
                    escape_html(&git.frontend.tz)
                ),
            ),
            el("span")
                .with_attr("class", "version-relative")
                .with_attr("data-epoch", git.frontend.epoch.to_string()),
            text_el("span", ")"),
        ]);

    Some(
        el("span")
            .with_attr("class", "version")
            .with_attr("id", "build-version")
            .with_attr("data-backend-hash", escape_html_attr(&git.backend.hash))
            .with_attr("data-backend-epoch", git.backend.epoch.to_string())
            .with_attr("data-frontend-hash", escape_html_attr(&git.frontend.hash))
            .with_attr("data-frontend-epoch", git.frontend.epoch.to_string())
            .with_attr("title", escape_html_attr(&title))
            .with_children(vec![backend_line, el("br"), frontend_line]),
    )
}

fn render_jobs_content(request: &RequestContext, api_key: &str) -> Vec<UiElement> {
    let endpoint_url = format!(
        "{}://{}",
        escape_html(&request.scheme),
        escape_html(&request.netloc)
    );

    let example_request = format!(
        "curl -X POST {endpoint_url}/api/v1/jobs \\\n  -H \"X-API-Key: YOUR_KEY\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{{\n    \"prompt\": \"Download latest release\",\n    \"source_url\": \"https://example.com\"\n  }}'"
    );

    vec![
        text_el("h1", "Job Queue"),
        el("div").with_attr("class", "grid-2").with_children(vec![
            el("div").with_attr("class", "card").with_children(vec![
                text_el("h2", "Submit New Job"),
                el("form").with_attr("id", "job-form").with_children({
                    let mut fields = Vec::new();
                    fields.extend(labeled_control(
                        "prompt",
                        "Task Description",
                        el("textarea")
                            .with_attr("id", "prompt")
                            .with_attr("name", "prompt")
                            .with_attr("rows", "3")
                            .with_attr(
                                "placeholder",
                                "Find and download the latest release of...",
                            )
                            .with_attr("required", "required"),
                    ));
                    fields.extend(labeled_control(
                        "source_url",
                        "Starting URL (optional)",
                        el("input")
                            .with_attr("type", "url")
                            .with_attr("id", "source_url")
                            .with_attr("name", "source_url")
                            .with_attr("placeholder", "https://example.com"),
                    ));
                    fields.extend(labeled_control(
                        "destination_path",
                        "Destination Path",
                        input_base("text", "destination_path", "destination_path", "./downloads")
                            .with_attr("placeholder", "./downloads"),
                    ));
                    fields.push(
                        el("div").with_attr("class", "grid-2").with_children(vec![
                            el("div").with_children({
                                let mut left = Vec::new();
                                left.extend(labeled_control(
                                    "file_operation",
                                    "File Operation",
                                    el("select")
                                        .with_attr("id", "file_operation")
                                        .with_attr("name", "file_operation")
                                        .with_children(vec![
                                            option("copy", "Copy", true),
                                            option("hardlink", "Hard Link", false),
                                            option("symlink", "Symbolic Link", false),
                                            option("reflink", "Reflink (CoW)", false),
                                            option("path_only", "Path Only", false),
                                        ]),
                                ));
                                left
                            }),
                            el("div").with_children({
                                let mut right = Vec::new();
                                right.extend(labeled_control(
                                    "priority",
                                    "Priority",
                                    input_base("number", "priority", "priority", "0")
                                        .with_attr("min", "-10")
                                        .with_attr("max", "10"),
                                ));
                                right
                            }),
                        ]),
                    );
                    fields.extend(labeled_control(
                        "file_filter",
                        "File Filter (glob patterns, one per line)",
                        el("textarea")
                            .with_attr("id", "file_filter")
                            .with_attr("name", "file_filter")
                            .with_attr("rows", "2")
                            .with_attr("placeholder", "*.mkv&#10;*.mp4"),
                    ));
                    fields.push(text_el("button", "Submit Job").with_attr("type", "submit"));
                    fields
                }),
                el("div")
                    .with_attr("id", "submit-result")
                    .with_attr("style", "margin-top: 1rem;"),
            ]),
            el("div").with_attr("class", "card").with_children(vec![
                text_el("h2", "API Access"),
                text_el("p", "Use the API to submit jobs programmatically.")
                    .with_attr("style", "color: var(--text-dim); margin-bottom: 1rem;"),
                text_el("label", "API Key"),
                el("div")
                    .with_attr("style", "display: flex; gap: 0.5rem; margin-bottom: 1rem;")
                    .with_children(vec![
                        el("input")
                            .with_attr("type", "password")
                            .with_attr("id", "api-key")
                            .with_attr("value", escape_html_attr(api_key))
                            .with_attr("readonly", "readonly")
                            .with_attr("style", "font-family: monospace; flex: 1;"),
                        text_el("button", "Show")
                            .with_attr("type", "button")
                            .with_attr("onclick", "toggleApiKey()")
                            .with_attr("class", "secondary")
                            .with_attr("style", "padding: 0.5rem 1rem;"),
                        text_el("button", "Copy")
                            .with_attr("type", "button")
                            .with_attr("onclick", "copyApiKey()")
                            .with_attr("class", "secondary")
                            .with_attr("style", "padding: 0.5rem 1rem;"),
                    ]),
                text_el("label", "Example Request"),
                text_el("pre", example_request).with_attr(
                    "style",
                    "background: var(--bg); padding: 1rem; border-radius: 0.25rem; overflow-x: auto; font-size: 0.8rem;",
                ),
                text_el("label", "Endpoints").with_attr("style", "margin-top: 1rem;"),
                el("table")
                    .with_attr("style", "font-size: 0.875rem;")
                    .with_children(vec![
                        el("tr").with_children(vec![
                            el("td").with_children(vec![text_el("code", "POST /api/v1/jobs")]),
                            text_el("td", "Submit job"),
                        ]),
                        el("tr").with_children(vec![
                            el("td").with_children(vec![text_el("code", "GET /api/v1/jobs")]),
                            text_el("td", "List jobs"),
                        ]),
                        el("tr").with_children(vec![
                            el("td").with_children(vec![text_el("code", "GET /api/v1/jobs/{id}")]),
                            text_el("td", "Get job details"),
                        ]),
                        el("tr").with_children(vec![
                            el("td")
                                .with_children(vec![text_el("code", "DELETE /api/v1/jobs/{id}")]),
                            text_el("td", "Cancel job"),
                        ]),
                        el("tr").with_children(vec![
                            el("td")
                                .with_children(vec![text_el("code", "GET /api/v1/jobs/{id}/stream")]),
                            text_el("td", "SSE progress stream"),
                        ]),
                    ]),
            ]),
        ]),
        el("div").with_attr("class", "card").with_children(vec![
            text_el("h2", "Job Queue"),
            el("div")
                .with_attr("style", "margin-bottom: 1rem;")
                .with_children(vec![
                    text_el("button", "Refresh")
                        .with_attr("type", "button")
                        .with_attr("onclick", "refreshJobs()")
                        .with_attr("class", "secondary"),
                ]),
            el("table").with_attr("id", "jobs-table").with_children(vec![
                el("thead").with_children(vec![el("tr").with_children(vec![
                    text_el("th", "ID"),
                    text_el("th", "Status"),
                    text_el("th", "Progress"),
                    text_el("th", "Task"),
                    text_el("th", "Created"),
                    text_el("th", "Actions"),
                ])]),
                el("tbody").with_attr("id", "jobs-tbody").with_children(vec![
                    el("tr").with_children(vec![
                        text_el("td", "No jobs in queue")
                            .with_attr("colspan", "6")
                            .with_attr(
                                "style",
                                "text-align: center; color: var(--text-dim); padding: 2rem;",
                            ),
                    ]),
                ]),
            ]),
        ]),
        el("div")
            .with_attr("id", "job-modal")
            .with_attr(
                "style",
                "display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.8); z-index: 1000; padding: 2rem;",
            )
            .with_children(vec![
                el("div")
                    .with_attr(
                        "style",
                        "max-width: 800px; margin: 0 auto; background: var(--bg-card); border-radius: 0.5rem; padding: 1.5rem; max-height: 90vh; overflow-y: auto;",
                    )
                    .with_children(vec![
                        el("div")
                            .with_attr(
                                "style",
                                "display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;",
                            )
                            .with_children(vec![
                                text_el("h2", "Job Details"),
                                text_el("button", "Close")
                                    .with_attr("type", "button")
                                    .with_attr("onclick", "closeModal()")
                                    .with_attr("class", "secondary"),
                            ]),
                        el("div").with_attr("id", "job-details"),
                    ]),
            ]),
    ]
}

fn render_config_content(
    config: &serde_json::Map<String, Value>,
    config_path: &str,
    saved: bool,
) -> Vec<UiElement> {
    let torrent_client = cfg_string(config, "torrent_client", "embedded");

    let qb_host = cfg_string(config, "qbittorrent_host", "localhost");
    let qb_port = cfg_i64(config, "qbittorrent_port", 8080);
    let qb_username = cfg_string(config, "qbittorrent_username", "admin");
    let qb_password = cfg_string(config, "qbittorrent_password", "adminadmin");

    let transmission_host = cfg_string(config, "transmission_host", "localhost");
    let transmission_port = cfg_i64(config, "transmission_port", 9091);
    let transmission_username = cfg_string(config, "transmission_username", "");
    let transmission_password = cfg_string(config, "transmission_password", "");

    let deluge_host = cfg_string(config, "deluge_host", "localhost");
    let deluge_port = cfg_i64(config, "deluge_port", 58846);
    let deluge_username = cfg_string(config, "deluge_username", "localclient");
    let deluge_password = cfg_string(config, "deluge_password", "deluge");

    let rtorrent_url = cfg_string(config, "rtorrent_url", "");

    let aria2_host = cfg_string(config, "aria2_host", "localhost");
    let aria2_port = cfg_i64(config, "aria2_port", 6800);
    let aria2_secret = cfg_string(config, "aria2_secret", "");

    let llm_provider = cfg_string(config, "llm_provider", "claude_code");
    let llm_model = cfg_string(config, "llm_model", "sonnet");

    let browser_mode = cfg_string(config, "browser_mode", "chrome");
    let browser_use_mcp_command = cfg_string(config, "browser_use_mcp_command", "uvx");
    let browser_use_mcp_args = cfg_string(config, "browser_use_mcp_args", "browser-use[mcp]");

    let headless = cfg_bool(config, "headless", true);
    let download_dir = cfg_string(config, "download_dir", "./downloads");
    let download_allow_insecure = cfg_bool(config, "download_allow_insecure", true);
    let download_retry_attempts = cfg_i64(config, "download_retry_attempts", 2);
    let download_retry_backoff_sec = cfg_f64(config, "download_retry_backoff_sec", 2.0);
    let download_max_parallel = cfg_i64(config, "download_max_parallel", 4);
    let path_mappings = cfg_path_mappings(config);
    let log_level = cfg_string(config, "log_level", "INFO");

    let mut nodes = vec![text_el("h1", "Configuration")];

    if saved {
        nodes.push(
            text_el("div", "Configuration saved successfully.").with_attr("class", "alert success"),
        );
    }

    let mut torrent_card_children = vec![
        text_el("h2", "Torrent Client"),
        text_el("label", "Client").with_attr("for", "torrent_client"),
        el("select")
            .with_attr("name", "torrent_client")
            .with_attr("id", "torrent_client")
            .with_children(vec![
                option("auto", "Auto (fallback chain)", torrent_client == "auto"),
                option(
                    "embedded",
                    "Embedded (librqbit feature)",
                    torrent_client == "embedded",
                ),
                option(
                    "qbittorrent",
                    "qBittorrent",
                    torrent_client == "qbittorrent",
                ),
                option(
                    "transmission",
                    "Transmission",
                    torrent_client == "transmission",
                ),
                option("deluge", "Deluge", torrent_client == "deluge"),
                option("rtorrent", "rTorrent", torrent_client == "rtorrent"),
                option("aria2", "aria2", torrent_client == "aria2"),
            ]),
        text_el("h3", "qBittorrent Settings")
            .with_attr("style", "margin: 1.5rem 0 1rem; font-size: 1rem;"),
    ];

    torrent_card_children.extend(labeled_control(
        "qbittorrent_host",
        "Host",
        input_base("text", "qbittorrent_host", "qbittorrent_host", &qb_host),
    ));
    torrent_card_children.extend(labeled_control(
        "qbittorrent_port",
        "Port",
        input_base(
            "number",
            "qbittorrent_port",
            "qbittorrent_port",
            &qb_port.to_string(),
        ),
    ));
    torrent_card_children.extend(labeled_control(
        "qbittorrent_username",
        "Username",
        input_base(
            "text",
            "qbittorrent_username",
            "qbittorrent_username",
            &qb_username,
        ),
    ));
    torrent_card_children.extend(labeled_control(
        "qbittorrent_password",
        "Password",
        input_base(
            "password",
            "qbittorrent_password",
            "qbittorrent_password",
            &qb_password,
        ),
    ));

    torrent_card_children.push(
        text_el("h3", "Transmission Settings")
            .with_attr("style", "margin: 1.5rem 0 1rem; font-size: 1rem;"),
    );
    torrent_card_children.extend(labeled_control(
        "transmission_host",
        "Host",
        input_base(
            "text",
            "transmission_host",
            "transmission_host",
            &transmission_host,
        ),
    ));
    torrent_card_children.extend(labeled_control(
        "transmission_port",
        "Port",
        input_base(
            "number",
            "transmission_port",
            "transmission_port",
            &transmission_port.to_string(),
        ),
    ));
    torrent_card_children.extend(labeled_control(
        "transmission_username",
        "Username",
        input_base(
            "text",
            "transmission_username",
            "transmission_username",
            &transmission_username,
        ),
    ));
    torrent_card_children.extend(labeled_control(
        "transmission_password",
        "Password",
        input_base(
            "password",
            "transmission_password",
            "transmission_password",
            &transmission_password,
        ),
    ));

    torrent_card_children.push(
        text_el("h3", "Deluge Settings")
            .with_attr("style", "margin: 1.5rem 0 1rem; font-size: 1rem;"),
    );
    torrent_card_children.extend(labeled_control(
        "deluge_host",
        "Host",
        input_base("text", "deluge_host", "deluge_host", &deluge_host),
    ));
    torrent_card_children.extend(labeled_control(
        "deluge_port",
        "Port",
        input_base(
            "number",
            "deluge_port",
            "deluge_port",
            &deluge_port.to_string(),
        ),
    ));
    torrent_card_children.extend(labeled_control(
        "deluge_username",
        "Username",
        input_base(
            "text",
            "deluge_username",
            "deluge_username",
            &deluge_username,
        ),
    ));
    torrent_card_children.extend(labeled_control(
        "deluge_password",
        "Password",
        input_base(
            "password",
            "deluge_password",
            "deluge_password",
            &deluge_password,
        ),
    ));

    torrent_card_children.push(
        text_el("h3", "rTorrent Settings")
            .with_attr("style", "margin: 1.5rem 0 1rem; font-size: 1rem;"),
    );
    torrent_card_children.extend(labeled_control(
        "rtorrent_url",
        "XML-RPC URL",
        input_base("text", "rtorrent_url", "rtorrent_url", &rtorrent_url)
            .with_attr("placeholder", "http://localhost:8000/RPC2"),
    ));

    torrent_card_children.push(
        text_el("h3", "aria2 Settings")
            .with_attr("style", "margin: 1.5rem 0 1rem; font-size: 1rem;"),
    );
    torrent_card_children.extend(labeled_control(
        "aria2_host",
        "Host",
        input_base("text", "aria2_host", "aria2_host", &aria2_host),
    ));
    torrent_card_children.extend(labeled_control(
        "aria2_port",
        "Port",
        input_base(
            "number",
            "aria2_port",
            "aria2_port",
            &aria2_port.to_string(),
        ),
    ));
    torrent_card_children.extend(labeled_control(
        "aria2_secret",
        "Secret Token",
        input_base("password", "aria2_secret", "aria2_secret", &aria2_secret),
    ));
    torrent_card_children.push(
        text_el("button", "Test Connection")
            .with_attr("type", "button")
            .with_attr("class", "secondary")
            .with_attr("id", "test-torrent")
            .with_attr("style", "margin-top: 0.5rem;"),
    );
    torrent_card_children.push(
        el("div")
            .with_attr("id", "torrent-result")
            .with_attr("style", "margin-top: 0.5rem; font-size: 0.875rem;"),
    );

    let mut provider_card_children = vec![
        text_el("h2", "LLM Provider"),
        text_el("label", "Provider").with_attr("for", "llm_provider"),
        el("select")
            .with_attr("name", "llm_provider")
            .with_attr("id", "llm_provider")
            .with_children(vec![
                option(
                    "claude_code",
                    "Claude Code (Max subscription)",
                    llm_provider == "claude_code",
                ),
                option("anthropic", "Anthropic API", llm_provider == "anthropic"),
                option("openai", "OpenAI", llm_provider == "openai"),
                option("ollama", "Ollama (local)", llm_provider == "ollama"),
                option("google", "Google Gemini", llm_provider == "google"),
                option("openrouter", "OpenRouter", llm_provider == "openrouter"),
            ]),
    ];

    provider_card_children.extend(labeled_control(
        "llm_model",
        "Model",
        input_base("text", "llm_model", "llm_model", &llm_model)
            .with_attr("list", "model-list")
            .with_attr("placeholder", "sonnet, opus, gpt-4o, llama3.2, etc."),
    ));
    provider_card_children.push(el("datalist").with_attr("id", "model-list"));
    provider_card_children.push(
        text_el("button", "Test Connection")
            .with_attr("type", "button")
            .with_attr("class", "secondary")
            .with_attr("id", "test-llm")
            .with_attr("style", "margin-top: 0.5rem;"),
    );
    provider_card_children.push(
        el("div")
            .with_attr("id", "llm-result")
            .with_attr("style", "margin-top: 0.5rem; font-size: 0.875rem;"),
    );

    provider_card_children.push(text_el("h2", "Browser").with_attr("style", "margin-top: 1.5rem;"));
    provider_card_children.extend(labeled_control(
        "browser_mode",
        "Browser Mode",
        el("select")
            .with_attr("name", "browser_mode")
            .with_attr("id", "browser_mode")
            .with_children(vec![
                option(
                    "chrome",
                    "Claude Chrome Integration",
                    browser_mode == "chrome",
                ),
                option(
                    "browser_use",
                    "browser-use (Playwright)",
                    browser_mode == "browser_use",
                ),
            ]),
    ));
    provider_card_children.extend(labeled_control(
        "browser_use_mcp_command",
        "browser-use MCP Command",
        input_base(
            "text",
            "browser_use_mcp_command",
            "browser_use_mcp_command",
            &browser_use_mcp_command,
        )
        .with_attr("placeholder", "uvx"),
    ));
    provider_card_children.extend(labeled_control(
        "browser_use_mcp_args",
        "browser-use MCP Args",
        input_base(
            "text",
            "browser_use_mcp_args",
            "browser_use_mcp_args",
            &browser_use_mcp_args,
        )
        .with_attr("placeholder", "browser-use[mcp]"),
    ));
    provider_card_children.push(
        text_el("div", "Used only when Browser Mode is set to browser-use.").with_attr(
            "style",
            "font-size: 0.75rem; color: var(--text-dim); margin-top: 0.25rem;",
        ),
    );
    provider_card_children.push(
        el("label")
            .with_attr(
                "style",
                "display: flex; align-items: center; gap: 0.5rem; cursor: pointer; margin-top: 0.5rem;",
            )
            .with_children(vec![
                el("input")
                    .with_attr("type", "checkbox")
                    .with_attr("name", "headless")
                    .with_attr("id", "headless")
                    .with_attr("style", "width: auto;")
                    .maybe_attr(headless, "checked", "checked"),
                text_el("span", "Headless mode (use Xvfb for Chrome)"),
            ]),
    );

    provider_card_children.push(text_el("h2", "Paths").with_attr("style", "margin-top: 1.5rem;"));
    provider_card_children.extend(labeled_control(
        "download_dir",
        "Download Directory",
        input_base("text", "download_dir", "download_dir", &download_dir),
    ));
    provider_card_children.push(
        el("label")
            .with_attr(
                "style",
                "display: flex; align-items: center; gap: 0.5rem; cursor: pointer;",
            )
            .with_children(vec![
                el("input")
                    .with_attr("type", "checkbox")
                    .with_attr("name", "download_allow_insecure")
                    .with_attr("id", "download_allow_insecure")
                    .with_attr("style", "width: auto;")
                    .maybe_attr(download_allow_insecure, "checked", "checked"),
                text_el("span", "Allow insecure downloads (skip TLS verification)"),
            ]),
    );

    provider_card_children.push(el("div").with_attr("class", "grid-2").with_children(vec![
        el("div").with_children({
            let mut left = Vec::new();
            left.extend(labeled_control(
                "download_retry_attempts",
                "Download Retry Attempts",
                input_base(
                    "number",
                    "download_retry_attempts",
                    "download_retry_attempts",
                    &download_retry_attempts.to_string(),
                )
                .with_attr("min", "1")
                .with_attr("max", "10"),
            ));
            left
        }),
        el("div").with_children({
            let mut right = Vec::new();
            right.extend(labeled_control(
                "download_retry_backoff_sec",
                "Retry Backoff (seconds)",
                input_base(
                    "number",
                    "download_retry_backoff_sec",
                    "download_retry_backoff_sec",
                    &download_retry_backoff_sec.to_string(),
                )
                .with_attr("step", "0.5")
                .with_attr("min", "0"),
            ));
            right
        }),
    ]));

    provider_card_children.extend(labeled_control(
        "download_max_parallel",
        "Max Parallel Downloads",
        input_base(
            "number",
            "download_max_parallel",
            "download_max_parallel",
            &download_max_parallel.to_string(),
        )
        .with_attr("min", "1")
        .with_attr("max", "32"),
    ));

    provider_card_children.extend(labeled_control(
        "path_mappings",
        "Path Mappings (one per line, host:container)",
        el("textarea")
            .with_attr("name", "path_mappings")
            .with_attr("id", "path_mappings")
            .with_attr("rows", "4")
            .with_attr("placeholder", "/mnt/downloads:/downloads")
            .with_text(escape_html(&path_mappings)),
    ));

    provider_card_children.push(text_el("h2", "Logging").with_attr("style", "margin-top: 1.5rem;"));
    provider_card_children.extend(labeled_control(
        "log_level",
        "Log Level",
        el("select")
            .with_attr("name", "log_level")
            .with_attr("id", "log_level")
            .with_children(vec![
                option("DEBUG", "Debug", log_level == "DEBUG"),
                option("INFO", "Info", log_level == "INFO"),
                option("WARNING", "Warning", log_level == "WARNING"),
                option("ERROR", "Error", log_level == "ERROR"),
            ]),
    ));

    nodes.push(
        el("form")
            .with_attr("method", "post")
            .with_attr("action", "/config")
            .with_children(vec![
                el("div").with_attr("class", "grid-2").with_children(vec![
                    el("div")
                        .with_attr("class", "card")
                        .with_children(torrent_card_children),
                    el("div")
                        .with_attr("class", "card")
                        .with_children(provider_card_children),
                ]),
                el("div").with_attr("class", "card").with_children(vec![
                    el("div")
                        .with_attr(
                            "style",
                            "display: flex; justify-content: space-between; align-items: center;",
                        )
                        .with_children(vec![
                            el("div").with_children(vec![
                                text_el("span", "Config file: ")
                                    .with_attr("style", "color: var(--text-dim);"),
                                text_el("code", escape_html(config_path)),
                            ]),
                            text_el("button", "Save Configuration").with_attr("type", "submit"),
                        ]),
                ]),
            ]),
    );

    nodes
}

fn render_notes_content(
    stats: &NoteStats,
    domains: &[String],
    domain_notes: &BTreeMap<String, Vec<NoteEntry>>,
) -> Vec<UiElement> {
    let stats_table = el("table").with_children(vec![
        el("tr").with_children(vec![
            text_el("td", "Total Notes").with_attr("style", "color: var(--text-dim);"),
            text_el("td", stats.total_notes.to_string()),
        ]),
        el("tr").with_children(vec![
            text_el("td", "Domains").with_attr("style", "color: var(--text-dim);"),
            text_el("td", stats.domains.to_string()),
        ]),
        el("tr").with_children(vec![
            text_el("td", "Successful Sources").with_attr("style", "color: var(--text-dim);"),
            text_el("td", stats.successful.to_string()),
        ]),
    ]);

    let notes_by_type = if stats.by_type.is_empty() {
        vec![text_el("p", "No notes recorded yet.").with_attr("style", "color: var(--text-dim);")]
    } else {
        let mut rows = Vec::new();
        for (note_type, count) in &stats.by_type {
            rows.push(el("tr").with_children(vec![
                text_el("td", escape_html(&note_type.replace('_', " ")))
                    .with_attr("style", "color: var(--text-dim);"),
                text_el("td", count.to_string()),
            ]));
        }
        vec![el("table").with_children(rows)]
    };

    let mut nodes = vec![
        text_el("h1", "Agent Notes"),
        el("div").with_attr("class", "grid").with_children(vec![
            el("div")
                .with_attr("class", "card")
                .with_children(vec![text_el("h2", "Statistics"), stats_table]),
            el("div").with_attr("class", "card").with_children({
                let mut c = vec![text_el("h2", "Notes by Type")];
                c.extend(notes_by_type);
                c
            }),
        ]),
    ];

    if domains.is_empty() {
        nodes.push(el("div").with_attr("class", "card").with_children(vec![
            text_el("h2", "No Notes Yet"),
            text_el(
                "p",
                "Agent notes will appear here as the browser agent learns about different sites. Run a download to start building the knowledge base.",
            )
            .with_attr("style", "color: var(--text-dim);"),
        ]));
        return nodes;
    }

    let mut domain_sections = vec![text_el("h2", "Notes by Domain")];

    for domain in domains {
        let notes = domain_notes.get(domain).cloned().unwrap_or_default();

        let mut note_rows = Vec::new();
        for note in notes.iter() {
            let success_cell = match note.success {
                Some(true) => text_el("span", "Yes").with_attr("class", "tag success"),
                Some(false) => text_el("span", "No").with_attr("class", "tag error"),
                None => text_el("span", "-").with_attr("style", "color: var(--text-dim);"),
            };

            note_rows.push(el("tr").with_children(vec![
                el("td").with_children(vec![
                    text_el("span", escape_html(&note.note_type.replace('_', " ")))
                        .with_attr("class", "tag"),
                ]),
                text_el("td", escape_html(note.label.as_deref().unwrap_or("-"))),
                text_el("td", escape_html(&note.content)).with_attr(
                    "style",
                    "max-width: 400px; overflow: hidden; text-overflow: ellipsis;",
                ),
                el("td").with_children(vec![success_cell]),
                text_el("td", note.use_count.to_string()),
            ]));
        }

        let details = el("details")
            .with_attr("style", "margin-bottom: 1rem;")
            .with_children(vec![
                el("summary")
                    .with_attr(
                        "style",
                        "cursor: pointer; padding: 0.75rem; background: var(--bg); border-radius: 0.25rem; margin-bottom: 0.5rem;",
                    )
                    .with_children(vec![
                        text_el("strong", escape_html(domain))
                            .with_attr("style", "color: var(--accent);"),
                        text_el("span", format!("({} notes)", notes.len())).with_attr(
                            "style",
                            "color: var(--text-dim); margin-left: 0.5rem;",
                        ),
                    ]),
                el("table")
                    .with_attr("style", "margin-left: 1rem;")
                    .with_children(vec![
                        el("thead").with_children(vec![el("tr").with_children(vec![
                            text_el("th", "Type"),
                            text_el("th", "Label"),
                            text_el("th", "Content"),
                            text_el("th", "Success"),
                            text_el("th", "Uses"),
                        ])]),
                        el("tbody").with_children(note_rows),
                    ]),
            ]);

        domain_sections.push(details);
    }

    nodes.push(
        el("div")
            .with_attr("class", "card")
            .with_children(domain_sections),
    );
    nodes
}

fn cfg_string(config: &serde_json::Map<String, Value>, key: &str, default: &str) -> String {
    config
        .get(key)
        .map(value_to_string)
        .unwrap_or_else(|| default.to_string())
}

fn cfg_i64(config: &serde_json::Map<String, Value>, key: &str, default: i64) -> i64 {
    config
        .get(key)
        .and_then(|v| match v {
            Value::Number(number) => {
                if let Some(v) = number.as_i64() {
                    Some(v)
                } else {
                    number.as_f64().map(|v| v as i64)
                }
            }
            Value::String(text) => text.parse::<i64>().ok(),
            _ => None,
        })
        .unwrap_or(default)
}

fn cfg_f64(config: &serde_json::Map<String, Value>, key: &str, default: f64) -> f64 {
    config
        .get(key)
        .and_then(|v| match v {
            Value::Number(number) => number.as_f64(),
            Value::String(text) => text.parse::<f64>().ok(),
            _ => None,
        })
        .unwrap_or(default)
}

fn cfg_bool(config: &serde_json::Map<String, Value>, key: &str, default: bool) -> bool {
    config
        .get(key)
        .and_then(|v| match v {
            Value::Bool(flag) => Some(*flag),
            Value::String(text) => match text.as_str() {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            },
            _ => None,
        })
        .unwrap_or(default)
}

fn cfg_path_mappings(config: &serde_json::Map<String, Value>) -> String {
    let Some(value) = config.get("path_mappings") else {
        return String::new();
    };

    match value {
        Value::Array(values) => values
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join("\n"),
        _ => value_to_string(value),
    }
}

fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(v) => v.clone(),
        Value::Number(v) => v.to_string(),
        Value::Bool(v) => v.to_string(),
        Value::Array(v) => v.iter().map(value_to_string).collect::<Vec<_>>().join(","),
        Value::Null => String::new(),
        Value::Object(_) => value.to_string(),
    }
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn escape_html_attr(input: &str) -> String {
    escape_html(input)
}

fn escape_js_string(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::BuildStamp;

    fn request(path: &str) -> RequestContext {
        RequestContext {
            path: path.to_string(),
            scheme: "http".to_string(),
            netloc: "localhost:3000".to_string(),
            query_params: HashMap::new(),
        }
    }

    fn git() -> GitInfo {
        GitInfo {
            backend: BuildStamp {
                hash: "deadbeef".to_string(),
                timestamp: "2026-02-06 10:00:00".to_string(),
                tz: "UTC".to_string(),
                epoch: 1_770_000_000,
            },
            frontend: BuildStamp {
                hash: "feedface".to_string(),
                timestamp: "2026-02-06 10:01:00".to_string(),
                tz: "UTC".to_string(),
                epoch: 1_770_000_060,
            },
        }
    }

    #[test]
    fn renders_index_without_template_markers() {
        let html = render_index_page(&request("/"), &git(), false, "");
        assert!(!html.contains("{%"));
        assert!(!html.contains("{{"));
        assert!(html.contains("Dashboard"));
    }

    #[test]
    fn renders_config_without_template_markers() {
        let mut req = request("/config");
        req.query_params
            .insert("saved".to_string(), "1".to_string());

        let config = serde_json::Map::new();
        let html = render_config_page(&req, &git(), &config, "/tmp/config.toml");
        assert!(!html.contains("{%"));
        assert!(!html.contains("{{"));
        assert!(html.contains("Configuration saved successfully."));
    }

    #[test]
    fn renders_config_selected_and_checked_values() {
        let req = request("/config");
        let mut config = serde_json::Map::new();
        config.insert(
            "torrent_client".to_string(),
            Value::String("deluge".to_string()),
        );
        config.insert("headless".to_string(), Value::Bool(false));
        config.insert(
            "path_mappings".to_string(),
            Value::Array(vec![Value::String("/a:/b".to_string())]),
        );

        let html = render_config_page(&req, &git(), &config, "/tmp/config.toml");
        assert!(html.contains("<option value=\"deluge\" selected=\"selected\">"));
        assert!(html.contains("/a:/b"));
        assert!(!html.contains("id=\"headless\" style=\"width: auto;\" checked=\"checked\""));
    }

    #[test]
    fn renders_jobs_without_template_markers() {
        let html = render_jobs_page(&request("/jobs"), &git(), "abc123");
        assert!(!html.contains("{%"));
        assert!(!html.contains("{{"));
        assert!(html.contains("abc123"));
        assert!(html.contains("No jobs in queue"));
    }

    #[test]
    fn renders_login_error_conditionally() {
        let with_error = render_login_page(true);
        let without_error = render_login_page(false);
        assert!(with_error.contains("Invalid username or password"));
        assert!(!without_error.contains("Invalid username or password"));
    }
}
