use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::rc::Rc;

use gloo_net::http::Request;
use gloo_timers::callback::{Interval, Timeout};
use js_sys::Date;
use leptos::*;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen::closure::Closure;
use wasm_bindgen_futures::spawn_local;
use web_sys::{
    Document, HtmlButtonElement, HtmlElement, HtmlFormElement, HtmlImageElement, HtmlInputElement,
    HtmlSelectElement, HtmlTextAreaElement,
};

#[component]
fn App() -> impl IntoView {
    view! {
        <div
            id="leptos-runtime-marker"
            data-runtime="graboid-frontend"
            style="display:none;"
        ></div>
    }
}

#[derive(Debug, Deserialize, Clone)]
struct BuildStamp {
    hash: String,
    timestamp: String,
    tz: String,
    epoch: i64,
}

#[derive(Debug, Deserialize)]
struct ApiGitStatus {
    backend: BuildStamp,
    frontend: BuildStamp,
}

#[derive(Debug, Deserialize)]
struct ApiStatusResponse {
    is_running: bool,
    task: String,
    git: ApiGitStatus,
}

#[derive(Debug, Deserialize)]
struct JobView {
    id: String,
    created_at: String,
    updated_at: String,
    prompt: String,
    source_url: String,
    #[serde(default)]
    file_filter: Vec<String>,
    destination_path: String,
    file_operation: String,
    priority: i32,
    status: String,
    current_phase: String,
    progress_percent: f64,
    progress_message: String,
    #[serde(default)]
    found_urls: Vec<String>,
    #[serde(default)]
    downloaded_files: Vec<String>,
    #[serde(default)]
    final_paths: Vec<String>,
    error_message: String,
    metadata: Value,
}

#[derive(Debug, Deserialize, Clone)]
struct JobStepDetailView {
    step_number: i64,
    action: String,
    observation: String,
    url: String,
    timestamp: String,
    is_error: bool,
    screenshot_base64: Option<String>,
    #[serde(default)]
    notes: Vec<String>,
    #[serde(default)]
    claude_messages: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct JobStepsResponse {
    #[serde(default)]
    steps: Vec<JobStepDetailView>,
}

#[derive(Debug, Deserialize)]
struct ModelListResponse {
    #[serde(default)]
    models: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct TorrentTestResponse {
    success: bool,
    message: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FsDirectoryEntry {
    name: String,
    path: String,
}

#[derive(Debug, Deserialize)]
struct FsListResponse {
    path: String,
    parent: Option<String>,
    #[serde(default)]
    directories: Vec<FsDirectoryEntry>,
}

#[derive(Debug)]
struct StepCarouselState {
    selected: usize,
    follow_latest: bool,
}

impl StepCarouselState {
    fn new(selected: usize) -> Self {
        Self {
            selected,
            follow_latest: true,
        }
    }
}

thread_local! {
    static DIR_AUTOCOMPLETE_SEQ: Cell<u64> = const { Cell::new(0) };
    static DIR_AUTOCOMPLETE_GLOBAL_HANDLER: Cell<bool> = const { Cell::new(false) };
}

fn web_document() -> Option<Document> {
    web_sys::window().and_then(|window| window.document())
}

fn set_text(id: &str, value: impl AsRef<str>) {
    let Some(doc) = web_document() else {
        return;
    };
    let Some(node) = doc.get_element_by_id(id) else {
        return;
    };
    let next = value.as_ref();
    if node.text_content().as_deref() == Some(next) {
        return;
    }
    node.set_text_content(Some(next));
}

fn set_class(id: &str, class_name: &str) {
    let Some(doc) = web_document() else {
        return;
    };
    let Some(node) = doc.get_element_by_id(id) else {
        return;
    };
    node.set_class_name(class_name);
}

fn set_running_dot(id: &str, running: bool) {
    let Some(doc) = web_document() else {
        return;
    };
    let Some(node) = doc.get_element_by_id(id) else {
        return;
    };
    let classes = node.class_list();
    if running {
        let _ = classes.add_1("running");
    } else {
        let _ = classes.remove_1("running");
    }
}

fn signature_changed(node: &web_sys::Element, signature: &str) -> bool {
    let current = node.get_attribute("data-render-sig").unwrap_or_default();
    if current == signature {
        return false;
    }
    let _ = node.set_attribute("data-render-sig", signature);
    true
}

fn set_backend_connected(connected: bool) {
    let Some(doc) = web_document() else {
        return;
    };
    let Some(node) = doc.get_element_by_id("backend-status") else {
        return;
    };
    let classes = node.class_list();
    if connected {
        let _ = classes.add_1("connected");
    } else {
        let _ = classes.remove_1("connected");
    }
}

fn set_nav_enabled(id: &str, enabled: bool) {
    let Some(doc) = web_document() else {
        return;
    };
    let Some(element) = doc
        .get_element_by_id(id)
        .and_then(|node| node.dyn_into::<HtmlElement>().ok())
    else {
        return;
    };

    let _ = element
        .style()
        .set_property("opacity", if enabled { "1" } else { "0.5" });
    let _ = element
        .style()
        .set_property("pointer-events", if enabled { "auto" } else { "none" });
    if enabled {
        let _ = element.remove_attribute("disabled");
        let _ = element.set_attribute("aria-disabled", "false");
    } else {
        let _ = element.set_attribute("disabled", "disabled");
        let _ = element.set_attribute("aria-disabled", "true");
    }
}

fn runtime_status_text(is_running: bool, task: &str) -> String {
    let trimmed = task.trim();
    if is_running && !trimmed.is_empty() {
        format!("Running: {trimmed}")
    } else {
        "Idle".to_string()
    }
}

fn truncate_text(input: &str, max_chars: usize) -> String {
    let mut chars = input.chars();
    let truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{truncated}...")
    } else {
        truncated
    }
}

fn format_relative_age(epoch: i64) -> String {
    if epoch <= 0 {
        return "-".to_string();
    }

    let now = (Date::now() / 1000.0).round() as i64;
    let diff = now - epoch;
    let future = diff < 0;
    let delta = diff.abs();

    if delta < 60 {
        return if future {
            "in <1m".to_string()
        } else {
            "<1m ago".to_string()
        };
    }

    let (value, suffix) = if delta < 3_600 {
        (delta / 60, "m")
    } else if delta < 86_400 {
        (delta / 3_600, "h")
    } else {
        (delta / 86_400, "d")
    };

    if future {
        format!("in {value}{suffix}")
    } else {
        format!("{value}{suffix} ago")
    }
}

fn parse_iso_epoch(timestamp: &str) -> Option<i64> {
    let raw = timestamp.trim();
    if raw.is_empty() {
        return None;
    }

    let millis = Date::new(&JsValue::from_str(raw)).get_time();
    if millis.is_finite() {
        Some((millis / 1000.0).round() as i64)
    } else {
        None
    }
}

fn format_duration(seconds: i64) -> String {
    if seconds < 0 {
        return "-".to_string();
    }

    let mut remaining = seconds;
    let hours = remaining / 3_600;
    remaining %= 3_600;
    let minutes = remaining / 60;
    let secs = remaining % 60;

    if hours > 0 {
        format!("{hours}h {minutes}m {secs}s")
    } else if minutes > 0 {
        format!("{minutes}m {secs}s")
    } else {
        format!("{secs}s")
    }
}

fn is_active_job_status(status: &str) -> bool {
    matches!(
        status,
        "pending" | "running" | "browsing" | "downloading" | "extracting" | "copying"
    )
}

fn update_version_badge(backend: &BuildStamp, frontend: &BuildStamp) {
    let Some(doc) = web_document() else {
        return;
    };
    let Some(version) = doc.get_element_by_id("build-version") else {
        return;
    };

    let current_backend_hash = version
        .get_attribute("data-backend-hash")
        .unwrap_or_default();
    let current_backend_epoch = version
        .get_attribute("data-backend-epoch")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or_default();
    let current_frontend_hash = version
        .get_attribute("data-frontend-hash")
        .unwrap_or_default();
    let current_frontend_epoch = version
        .get_attribute("data-frontend-epoch")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or_default();

    let backend_changed = !current_backend_hash.trim().is_empty()
        && (current_backend_hash != backend.hash || current_backend_epoch != backend.epoch);
    let frontend_changed = !current_frontend_hash.trim().is_empty()
        && !frontend.hash.trim().is_empty()
        && (current_frontend_hash != frontend.hash || current_frontend_epoch != frontend.epoch);

    if backend_changed || frontend_changed {
        if let Some(window) = web_sys::window() {
            let _ = window.location().reload();
        }
        return;
    }

    let _ = version.set_attribute("data-backend-hash", &backend.hash);
    let _ = version.set_attribute("data-backend-epoch", &backend.epoch.to_string());
    let _ = version.set_attribute("data-frontend-hash", &frontend.hash);
    let _ = version.set_attribute("data-frontend-epoch", &frontend.epoch.to_string());

    let title = format!(
        "Backend build {} {} | Frontend assets {} {}",
        backend.timestamp, backend.tz, frontend.timestamp, frontend.tz
    );
    let _ = version.set_attribute("title", &title);

    let be_age = format_relative_age(backend.epoch);
    let fe_age = format_relative_age(frontend.epoch);

    set_text(
        "build-version-be",
        format!(
            "BE {} {} {} ({})",
            backend.hash, backend.timestamp, backend.tz, be_age
        ),
    );
    set_text(
        "build-version-fe",
        format!(
            "FE {} {} {} ({})",
            frontend.hash, frontend.timestamp, frontend.tz, fe_age
        ),
    );
}

fn apply_runtime_status(status: &ApiStatusResponse) {
    let status_text = runtime_status_text(status.is_running, &status.task);

    set_running_dot("status-dot", status.is_running);
    set_running_dot("dashboard-status-dot", status.is_running);
    set_text("status-text", &status_text);
    set_text("dashboard-status-text", &status_text);

    update_version_badge(&status.git.backend, &status.git.frontend);
}

fn poll_status_once() {
    spawn_local(async move {
        let status = fetch_json::<ApiStatusResponse>("/api/status").await;
        match status {
            Some(value) => {
                set_backend_connected(true);
                apply_runtime_status(&value);
            }
            None => {
                set_backend_connected(false);
            }
        }
    });
}

fn start_status_poller() {
    poll_status_once();
    let interval = Interval::new(2000, || {
        poll_status_once();
    });
    interval.forget();
}

fn job_status_class(status: &str) -> &'static str {
    match status {
        "complete" => "success",
        "failed" | "cancelled" => "error",
        "running" | "browsing" | "downloading" | "extracting" | "copying" => "warning",
        _ => "",
    }
}

fn concise_job_activity(
    status: &str,
    phase: &str,
    progress_percent: f64,
    progress_message: &str,
) -> String {
    let percent = format!("{:.0}%", progress_percent.round());
    if matches!(status, "complete" | "failed" | "cancelled") {
        let label = match status {
            "complete" => "Done",
            "failed" => "Failed",
            "cancelled" => "Cancelled",
            _ => status,
        };
        return format!("{percent} {label}");
    }

    let message = progress_message.trim();
    if message.is_empty() {
        let phase = phase.trim();
        if phase.is_empty() {
            format!("{percent} Working")
        } else {
            format!("{percent} {phase}...")
        }
    } else {
        format!("{percent} {message}")
    }
}

fn update_job_summary(job: &JobView) {
    let progress_text = concise_job_activity(
        &job.status,
        &job.current_phase,
        job.progress_percent,
        &job.progress_message,
    );

    set_class(
        "job-status-tag",
        format!("tag {}", job_status_class(&job.status)).trim(),
    );
    set_text("job-status-tag", &job.status);
    set_text("job-progress-text", &progress_text);
    let created_epoch = parse_iso_epoch(&job.created_at).unwrap_or(0);
    let updated_epoch = parse_iso_epoch(&job.updated_at).unwrap_or(0);
    set_text("job-created-text", format_relative_age(created_epoch));
    set_text("job-updated-text", format_relative_age(updated_epoch));
    let now_epoch = (Date::now() / 1000.0).round() as i64;
    let duration_end = if is_active_job_status(&job.status) {
        now_epoch
    } else if updated_epoch > 0 {
        updated_epoch
    } else {
        now_epoch
    };
    let job_duration = if created_epoch > 0 {
        format_duration((duration_end - created_epoch).max(0))
    } else {
        "-".to_string()
    };
    set_text("job-duration-text", job_duration);
    set_text(
        "job-source-url-text",
        if job.source_url.trim().is_empty() {
            "Auto-discover (no source URL provided)"
        } else {
            &job.source_url
        },
    );
    set_text("job-destination-text", &job.destination_path);
    set_text("job-operation-text", &job.file_operation);
    set_text(
        "job-priority-text",
        if job.priority == 0 {
            "Normal (0)".to_string()
        } else {
            job.priority.to_string()
        },
    );
    set_text("job-prompt-text", &job.prompt);

    if let Some(error_box) = web_document()
        .and_then(|doc| doc.get_element_by_id("job-error-box"))
        .and_then(|node| node.dyn_into::<HtmlElement>().ok())
    {
        if job.error_message.trim().is_empty() {
            let _ = error_box.style().set_property("display", "none");
        } else {
            let _ = error_box.style().set_property("display", "block");
        }
    }
    set_text("job-error-text", &job.error_message);

    let metadata = if job.metadata.is_null()
        || job
            .metadata
            .as_object()
            .map(|map| map.is_empty())
            .unwrap_or(false)
    {
        "(none)".to_string()
    } else {
        serde_json::to_string_pretty(&job.metadata).unwrap_or_else(|_| "{}".to_string())
    };
    set_text("job-metadata-text", metadata);

    let file_filter_text = if job.file_filter.is_empty() {
        "(none)".to_string()
    } else {
        job.file_filter.join("\n")
    };
    set_text("job-file-filter-text", file_filter_text);

    render_code_list(
        "job-found-urls",
        &job.found_urls,
        "No candidate URLs found yet.",
    );

    let (kind, values, hint) = if job.final_paths.is_empty() {
        (
            "downloaded",
            &job.downloaded_files,
            "Showing direct downloads (no finalized outputs yet).",
        )
    } else {
        (
            "final",
            &job.final_paths,
            "Showing final files after extract/filter/copy.",
        )
    };
    set_text("job-output-files-help", hint);
    render_artifact_list(
        "job-output-files",
        &job.id,
        kind,
        values,
        "No output files yet.",
    );
}

fn render_code_list(container_id: &str, values: &[String], empty_message: &str) {
    let Some(doc) = web_document() else {
        return;
    };
    let Some(container) = doc.get_element_by_id(container_id) else {
        return;
    };

    let signature = format!("{container_id}|{}", values.join("\u{1f}"));
    if !signature_changed(&container, &signature) {
        return;
    }

    container.set_inner_html("");

    if values.is_empty() {
        if let Ok(item) = doc.create_element("li") {
            let _ = item.set_attribute("style", "color: var(--text-dim);");
            item.set_text_content(Some(empty_message));
            let _ = container.append_child(&item);
        }
        return;
    }

    for value in values {
        let Ok(item) = doc.create_element("li") else {
            continue;
        };
        let Ok(code) = doc.create_element("code") else {
            continue;
        };

        let _ = code.set_attribute("style", "word-break: break-word;");
        code.set_text_content(Some(value));
        let _ = item.append_child(&code);
        let _ = container.append_child(&item);
    }
}

fn render_artifact_list(
    container_id: &str,
    job_id: &str,
    kind: &str,
    values: &[String],
    empty_message: &str,
) {
    let Some(doc) = web_document() else {
        return;
    };
    let Some(container) = doc.get_element_by_id(container_id) else {
        return;
    };

    let signature = format!("{job_id}|{kind}|{}", values.join("\u{1f}"));
    if !signature_changed(&container, &signature) {
        return;
    }

    container.set_inner_html("");

    if values.is_empty() {
        if let Ok(item) = doc.create_element("li") {
            let _ = item.set_attribute("style", "color: var(--text-dim);");
            item.set_text_content(Some(empty_message));
            let _ = container.append_child(&item);
        }
        return;
    }

    for (index, value) in values.iter().enumerate() {
        let Ok(item) = doc.create_element("li") else {
            continue;
        };

        let Ok(code) = doc.create_element("code") else {
            continue;
        };
        let _ = code.set_attribute("style", "word-break: break-word;");
        code.set_text_content(Some(value));

        if value.starts_with("torrent:") {
            let _ = item.append_child(&code);
            let _ = container.append_child(&item);
            continue;
        }

        let Ok(anchor) = doc.create_element("a") else {
            continue;
        };
        let _ = anchor.set_attribute("href", &format!("/jobs/{job_id}/artifacts/{kind}/{index}"));
        let _ = anchor.append_child(&code);
        let _ = item.append_child(&anchor);
        let _ = container.append_child(&item);
    }
}

fn render_note_list(container_id: &str, values: &[String], empty_message: &str) {
    let Some(doc) = web_document() else {
        return;
    };
    let Some(container) = doc.get_element_by_id(container_id) else {
        return;
    };
    if container_id == "job-step-notes" {
        if let Some(title) = doc
            .get_element_by_id("job-step-notes-title")
            .and_then(|node| node.dyn_into::<HtmlElement>().ok())
        {
            let _ = title
                .style()
                .set_property("display", if values.is_empty() { "none" } else { "block" });
        }
        if let Some(container_el) = container.dyn_ref::<HtmlElement>() {
            let _ = container_el
                .style()
                .set_property("display", if values.is_empty() { "none" } else { "grid" });
        }
    }

    let signature = format!("{container_id}|{}", values.join("\u{1f}"));
    if !signature_changed(&container, &signature) {
        return;
    }

    container.set_inner_html("");

    if values.is_empty() {
        if let Ok(item) = doc.create_element("li") {
            let _ = item.set_attribute("style", "color: var(--text-dim);");
            item.set_text_content(Some(empty_message));
            let _ = container.append_child(&item);
        }
        return;
    }

    for value in values {
        let Ok(item) = doc.create_element("li") else {
            continue;
        };
        item.set_text_content(Some(value));
        let _ = container.append_child(&item);
    }
}

fn render_agent_messages(messages: &[String]) {
    let Some(doc) = web_document() else {
        return;
    };
    let Some(container) = doc.get_element_by_id("job-step-agent") else {
        return;
    };

    let signature = format!("agent|{}", messages.join("\u{1f}"));
    if !signature_changed(&container, &signature) {
        return;
    }

    container.set_inner_html("");

    if messages.is_empty() {
        if let Ok(empty) = doc.create_element("p") {
            let _ = empty.set_attribute("style", "color: var(--text-dim);");
            empty.set_text_content(Some("No agent output for this step."));
            let _ = container.append_child(&empty);
        }
        return;
    }

    for message in messages.iter().rev() {
        let Ok(wrapper) = doc.create_element("div") else {
            continue;
        };
        wrapper.set_class_name("message");

        let Ok(role) = doc.create_element("div") else {
            continue;
        };
        role.set_class_name("role");
        role.set_text_content(Some("Agent"));

        let Ok(content) = doc.create_element("div") else {
            continue;
        };
        content.set_class_name("content");
        content.set_text_content(Some(message));

        let _ = wrapper.append_child(&role);
        let _ = wrapper.append_child(&content);
        let _ = container.append_child(&wrapper);
    }
}

fn render_selected_step(steps: &[JobStepDetailView], state: &Rc<RefCell<StepCarouselState>>) {
    let (selected_idx, total_steps, has_prev, has_next) = {
        let mut state_mut = state.borrow_mut();
        let total = steps.len();

        if total == 0 {
            state_mut.selected = 0;
        } else {
            if state_mut.follow_latest {
                state_mut.selected = total - 1;
            }
            if state_mut.selected >= total {
                state_mut.selected = total - 1;
            }
        }

        let selected_idx = state_mut.selected;
        let has_prev = total > 0 && selected_idx > 0;
        let has_next = total > 0 && selected_idx + 1 < total;

        (selected_idx, total, has_prev, has_next)
    };

    set_nav_enabled("job-step-prev", has_prev);
    set_nav_enabled("job-step-next", has_next);

    if let Some(root) = web_document().and_then(|doc| doc.get_element_by_id("job-detail-root")) {
        let _ = root.set_attribute("data-selected-step", &selected_idx.to_string());
    }

    if total_steps == 0 {
        set_text("job-step-title", "No navigation steps yet");
        set_text("job-step-counter", "No steps yet");
        set_text("job-step-meta", "Waiting for first navigation step");
        set_text("job-step-observation", "No step observation available yet.");
        render_agent_messages(&[]);
        render_note_list("job-step-notes", &[], "No notes attached to this step.");

        if let Some(error_tag) = web_document()
            .and_then(|doc| doc.get_element_by_id("job-step-error-tag"))
            .and_then(|node| node.dyn_into::<HtmlElement>().ok())
        {
            let _ = error_tag.style().set_property("display", "none");
        }

        if let Some(image) = web_document()
            .and_then(|doc| doc.get_element_by_id("job-step-image"))
            .and_then(|node| node.dyn_into::<HtmlImageElement>().ok())
        {
            image.set_src("");
        }
        if let Some(wrap) = web_document()
            .and_then(|doc| doc.get_element_by_id("job-step-image-wrap"))
            .and_then(|node| node.dyn_into::<HtmlElement>().ok())
        {
            let _ = wrap.style().set_property("display", "none");
        }

        return;
    }

    let step = &steps[selected_idx];

    set_text(
        "job-step-title",
        format!(
            "Step {}: {}",
            step.step_number,
            truncate_text(&step.action, 100)
        ),
    );
    set_text(
        "job-step-counter",
        format!("Step {}/{}", selected_idx + 1, total_steps),
    );
    set_text(
        "job-step-meta",
        format!(
            "{} | {}",
            parse_iso_epoch(&step.timestamp)
                .map(format_relative_age)
                .unwrap_or_else(|| step.timestamp.clone()),
            step.url
        ),
    );
    set_text("job-step-observation", &step.observation);

    if let Some(error_tag) = web_document()
        .and_then(|doc| doc.get_element_by_id("job-step-error-tag"))
        .and_then(|node| node.dyn_into::<HtmlElement>().ok())
    {
        let _ = error_tag.style().set_property(
            "display",
            if step.is_error {
                "inline-block"
            } else {
                "none"
            },
        );
    }

    if let Some(image) = web_document()
        .and_then(|doc| doc.get_element_by_id("job-step-image"))
        .and_then(|node| node.dyn_into::<HtmlImageElement>().ok())
    {
        if let Some(base64) = step.screenshot_base64.as_ref() {
            image.set_src(&format!("data:image/png;base64,{base64}"));
            if let Some(wrap) = web_document()
                .and_then(|doc| doc.get_element_by_id("job-step-image-wrap"))
                .and_then(|node| node.dyn_into::<HtmlElement>().ok())
            {
                let _ = wrap.style().set_property("display", "block");
            }
        } else {
            image.set_src("");
            if let Some(wrap) = web_document()
                .and_then(|doc| doc.get_element_by_id("job-step-image-wrap"))
                .and_then(|node| node.dyn_into::<HtmlElement>().ok())
            {
                let _ = wrap.style().set_property("display", "none");
            }
        }
    }

    render_agent_messages(&step.claude_messages);
    render_note_list(
        "job-step-notes",
        &step.notes,
        "No notes attached to this step.",
    );
}

fn install_step_nav_handlers(
    state: Rc<RefCell<StepCarouselState>>,
    steps_cache: Rc<RefCell<Vec<JobStepDetailView>>>,
) {
    let Some(doc) = web_document() else {
        return;
    };

    if let Some(prev_button) = doc
        .get_element_by_id("job-step-prev")
        .and_then(|node| node.dyn_into::<HtmlElement>().ok())
    {
        let prev_state = state.clone();
        let prev_steps = steps_cache.clone();
        let callback = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
            let total = prev_steps.borrow().len();
            if total == 0 {
                return;
            }
            event.prevent_default();

            {
                let mut state_mut = prev_state.borrow_mut();
                if state_mut.selected == 0 {
                    return;
                }
                state_mut.selected -= 1;
                state_mut.follow_latest = false;
            }

            let steps = prev_steps.borrow();
            render_selected_step(&steps, &prev_state);
        });

        let _ = prev_button
            .add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }

    if let Some(next_button) = doc
        .get_element_by_id("job-step-next")
        .and_then(|node| node.dyn_into::<HtmlElement>().ok())
    {
        let next_state = state.clone();
        let next_steps = steps_cache.clone();
        let callback = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
            let total = next_steps.borrow().len();
            if total == 0 {
                return;
            }
            event.prevent_default();

            {
                let mut state_mut = next_state.borrow_mut();
                if state_mut.selected + 1 >= total {
                    return;
                }
                state_mut.selected += 1;
                state_mut.follow_latest = state_mut.selected + 1 >= total;
            }

            let steps = next_steps.borrow();
            render_selected_step(&steps, &next_state);
        });

        let _ = next_button
            .add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
}

fn load_bootstrap_steps() -> Vec<JobStepDetailView> {
    let Some(doc) = web_document() else {
        return Vec::new();
    };
    let Some(node) = doc.get_element_by_id("job-steps-bootstrap") else {
        return Vec::new();
    };
    let raw = node.text_content().unwrap_or_default();
    serde_json::from_str::<Vec<JobStepDetailView>>(&raw).unwrap_or_default()
}

fn init_job_detail_live_updates() {
    let Some(doc) = web_document() else {
        return;
    };
    let Some(root) = doc.get_element_by_id("job-detail-root") else {
        return;
    };

    let job_id = root.get_attribute("data-job-id").unwrap_or_default();
    let api_key = root.get_attribute("data-api-key").unwrap_or_default();
    let selected_step = root
        .get_attribute("data-selected-step")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);

    if job_id.trim().is_empty() {
        return;
    }

    let state = Rc::new(RefCell::new(StepCarouselState::new(selected_step)));
    let steps_cache = Rc::new(RefCell::new(Vec::<JobStepDetailView>::new()));
    let poll_inflight = Rc::new(RefCell::new(false));

    install_step_nav_handlers(state.clone(), steps_cache.clone());
    {
        let mut cache = steps_cache.borrow_mut();
        *cache = load_bootstrap_steps();
    }
    {
        let steps = steps_cache.borrow();
        render_selected_step(&steps, &state);
    }

    if api_key.trim().is_empty() {
        return;
    }

    let run_poll = {
        let job_id = job_id.clone();
        let api_key = api_key.clone();
        let state = state.clone();
        let steps_cache = steps_cache.clone();
        let poll_inflight = poll_inflight.clone();

        move || {
            let job_id = job_id.clone();
            let api_key = api_key.clone();
            let state = state.clone();
            let steps_cache = steps_cache.clone();
            let poll_inflight = poll_inflight.clone();

            if *poll_inflight.borrow() {
                return;
            }
            *poll_inflight.borrow_mut() = true;

            spawn_local(async move {
                let job_url = format!("/api/v1/jobs/{job_id}?api_key={api_key}");
                let steps_url = format!("/api/v1/jobs/{job_id}/steps/detail?api_key={api_key}");

                let Some(job) = fetch_json::<JobView>(&job_url).await else {
                    *poll_inflight.borrow_mut() = false;
                    return;
                };
                let Some(steps_response) = fetch_json::<JobStepsResponse>(&steps_url).await else {
                    *poll_inflight.borrow_mut() = false;
                    return;
                };

                update_job_summary(&job);

                {
                    let mut cache = steps_cache.borrow_mut();
                    if steps_response.steps.len() >= cache.len() {
                        *cache = steps_response.steps;
                    }

                    let mut state_mut = state.borrow_mut();
                    if is_active_job_status(&job.status) {
                        state_mut.follow_latest = true;
                    } else if state_mut.selected + 1 < cache.len() {
                        state_mut.follow_latest = false;
                    }
                }

                let steps = steps_cache.borrow();
                render_selected_step(&steps, &state);
                *poll_inflight.borrow_mut() = false;
            });
        }
    };

    run_poll();
    let interval = Interval::new(1000, move || {
        run_poll();
    });
    interval.forget();
}

fn encode_component(input: &str) -> String {
    js_sys::encode_uri_component(input)
        .as_string()
        .unwrap_or_else(|| input.to_string())
}

fn serialize_form_urlencoded(form: &HtmlFormElement) -> String {
    let mut pairs = Vec::<(String, String)>::new();
    let elements = form.elements();

    for idx in 0..elements.length() {
        let Some(element) = elements.item(idx) else {
            continue;
        };

        let name = element.get_attribute("name").unwrap_or_default();
        if name.trim().is_empty() {
            continue;
        }

        if let Some(input) = element.dyn_ref::<HtmlInputElement>() {
            let kind = input.type_().to_ascii_lowercase();
            if matches!(
                kind.as_str(),
                "submit" | "button" | "reset" | "file" | "image"
            ) {
                continue;
            }
            if kind == "checkbox" && !input.checked() {
                continue;
            }
            pairs.push((name, input.value()));
            continue;
        }

        if let Some(select) = element.dyn_ref::<HtmlSelectElement>() {
            pairs.push((name, select.value()));
            continue;
        }

        if let Some(textarea) = element.dyn_ref::<HtmlTextAreaElement>() {
            pairs.push((name, textarea.value()));
            continue;
        }
    }

    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", encode_component(key), encode_component(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn set_config_save_status(text: &str, class_name: &str) {
    set_text("config-save-status", text);
    set_class("config-save-status", class_name);
}

fn sync_select_panel_visibility(select_id: &str, panel_class: &str, attr_name: &str) {
    let Some(doc) = web_document() else {
        return;
    };
    let Some(select) = doc
        .get_element_by_id(select_id)
        .and_then(|node| node.dyn_into::<HtmlSelectElement>().ok())
    else {
        return;
    };

    let selected = select.value();
    let panels = doc.get_elements_by_class_name(panel_class);
    for idx in 0..panels.length() {
        let Some(panel) = panels.item(idx) else {
            continue;
        };
        let show = panel
            .get_attribute(attr_name)
            .map(|value| value == selected)
            .unwrap_or(false);
        let _ = panel.set_attribute(
            "style",
            if show {
                "display: block;"
            } else {
                "display: none;"
            },
        );
    }
}

fn sync_torrent_client_panels() {
    sync_select_panel_visibility(
        "torrent_client",
        "torrent-client-panel",
        "data-torrent-client",
    );
}

fn sync_path_mappings_hidden() {
    let Some(doc) = web_document() else {
        return;
    };
    let Some(hidden) = doc
        .get_element_by_id("path_mappings")
        .and_then(|node| node.dyn_into::<HtmlTextAreaElement>().ok())
    else {
        return;
    };

    let sources = doc.get_elements_by_class_name("path-map-source");
    let dests = doc.get_elements_by_class_name("path-map-dest");
    let len = sources.length().min(dests.length());
    let mut lines = Vec::new();

    for idx in 0..len {
        let Some(source) = sources
            .item(idx)
            .and_then(|node| node.dyn_into::<HtmlInputElement>().ok())
        else {
            continue;
        };
        let Some(dest) = dests
            .item(idx)
            .and_then(|node| node.dyn_into::<HtmlInputElement>().ok())
        else {
            continue;
        };
        let source = source.value().trim().to_string();
        let dest = dest.value().trim().to_string();
        if source.is_empty() && dest.is_empty() {
            continue;
        }
        lines.push(format!("{source}:{dest}"));
    }

    hidden.set_value(&lines.join("\n"));
}

fn normalize_source_kind(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "ftp" => "ftp".to_string(),
        "samba" | "smb" => "samba".to_string(),
        _ => "sftp".to_string(),
    }
}

fn default_port_for_source_kind(kind: &str) -> u16 {
    match normalize_source_kind(kind).as_str() {
        "ftp" => 21,
        "samba" => 445,
        _ => 22,
    }
}

fn apply_default_port_for_source_select(select: &HtmlSelectElement) {
    let kind = normalize_source_kind(&select.value());
    select.set_value(&kind);

    let default_port = default_port_for_source_kind(&kind).to_string();
    let Some(parent) = select.parent_element() else {
        return;
    };
    let Ok(Some(port_node)) = parent.query_selector(".source-endpoint-port") else {
        return;
    };
    let Ok(port_input) = port_node.dyn_into::<HtmlInputElement>() else {
        return;
    };
    port_input.set_placeholder(&default_port);
}

fn sanitize_source_cell(value: &str) -> String {
    value.replace(['\n', '\r', '\t'], " ").trim().to_string()
}

fn sync_source_endpoints_hidden() {
    let Some(doc) = web_document() else {
        return;
    };
    let Some(hidden) = doc
        .get_element_by_id("source_endpoints")
        .and_then(|node| node.dyn_into::<HtmlTextAreaElement>().ok())
    else {
        return;
    };

    let names = doc.get_elements_by_class_name("source-endpoint-name");
    let kinds = doc.get_elements_by_class_name("source-endpoint-kind");
    let hosts = doc.get_elements_by_class_name("source-endpoint-host");
    let ports = doc.get_elements_by_class_name("source-endpoint-port");
    let locations = doc.get_elements_by_class_name("source-endpoint-location");
    let usernames = doc.get_elements_by_class_name("source-endpoint-username");
    let passwords = doc.get_elements_by_class_name("source-endpoint-password");

    let len = names
        .length()
        .min(kinds.length())
        .min(hosts.length())
        .min(ports.length())
        .min(locations.length())
        .min(usernames.length())
        .min(passwords.length());

    let mut lines = Vec::new();
    for idx in 0..len {
        let Some(name) = names
            .item(idx)
            .and_then(|node| node.dyn_into::<HtmlInputElement>().ok())
        else {
            continue;
        };
        let Some(kind) = kinds
            .item(idx)
            .and_then(|node| node.dyn_into::<HtmlSelectElement>().ok())
        else {
            continue;
        };
        let Some(host) = hosts
            .item(idx)
            .and_then(|node| node.dyn_into::<HtmlInputElement>().ok())
        else {
            continue;
        };
        let Some(port) = ports
            .item(idx)
            .and_then(|node| node.dyn_into::<HtmlInputElement>().ok())
        else {
            continue;
        };
        let Some(location) = locations
            .item(idx)
            .and_then(|node| node.dyn_into::<HtmlInputElement>().ok())
        else {
            continue;
        };
        let Some(username) = usernames
            .item(idx)
            .and_then(|node| node.dyn_into::<HtmlInputElement>().ok())
        else {
            continue;
        };
        let Some(password) = passwords
            .item(idx)
            .and_then(|node| node.dyn_into::<HtmlInputElement>().ok())
        else {
            continue;
        };

        let name = sanitize_source_cell(&name.value());
        let kind = normalize_source_kind(&kind.value());
        let host = sanitize_source_cell(&host.value());
        let port = sanitize_source_cell(&port.value());
        let location = sanitize_source_cell(&location.value());
        let username = sanitize_source_cell(&username.value());
        let password = sanitize_source_cell(&password.value());

        if name.is_empty()
            && host.is_empty()
            && location.is_empty()
            && username.is_empty()
            && password.is_empty()
        {
            continue;
        }

        lines.push(format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            name, kind, host, port, location, username, password
        ));
    }

    hidden.set_value(&lines.join("\n"));
}

fn create_source_endpoint_row(
    name: &str,
    kind: &str,
    host: &str,
    port: &str,
    location: &str,
    username: &str,
    password: &str,
) -> Option<HtmlElement> {
    let doc = web_document()?;
    let row = doc
        .create_element("div")
        .ok()?
        .dyn_into::<HtmlElement>()
        .ok()?;
    row.set_class_name("source-endpoint-row");
    let _ = row.set_attribute("data-source-endpoint-row", "1");

    let name_input = doc
        .create_element("input")
        .ok()?
        .dyn_into::<HtmlInputElement>()
        .ok()?;
    name_input.set_type("text");
    name_input.set_class_name("source-endpoint-name");
    name_input.set_placeholder("source name");
    name_input.set_value(name);

    let kind_select = doc
        .create_element("select")
        .ok()?
        .dyn_into::<HtmlSelectElement>()
        .ok()?;
    kind_select.set_class_name("source-endpoint-kind");
    for (value, label) in [("sftp", "SFTP"), ("ftp", "FTP"), ("samba", "Samba")] {
        let option = doc.create_element("option").ok()?;
        let _ = option.set_attribute("value", value);
        option.set_text_content(Some(label));
        let _ = kind_select.append_child(&option);
    }
    let selected_kind = normalize_source_kind(kind);
    kind_select.set_value(&selected_kind);

    let host_input = doc
        .create_element("input")
        .ok()?
        .dyn_into::<HtmlInputElement>()
        .ok()?;
    host_input.set_type("text");
    host_input.set_class_name("source-endpoint-host");
    host_input.set_placeholder("host");
    host_input.set_value(host);

    let port_input = doc
        .create_element("input")
        .ok()?
        .dyn_into::<HtmlInputElement>()
        .ok()?;
    port_input.set_type("number");
    port_input.set_class_name("source-endpoint-port");
    let default_port = default_port_for_source_kind(&selected_kind).to_string();
    port_input.set_placeholder(&default_port);
    port_input.set_value(port.trim());

    let location_input = doc
        .create_element("input")
        .ok()?
        .dyn_into::<HtmlInputElement>()
        .ok()?;
    location_input.set_type("text");
    location_input.set_class_name("source-endpoint-location");
    location_input.set_placeholder("path/share");
    location_input.set_value(location);

    let username_input = doc
        .create_element("input")
        .ok()?
        .dyn_into::<HtmlInputElement>()
        .ok()?;
    username_input.set_type("text");
    username_input.set_class_name("source-endpoint-username");
    username_input.set_placeholder("username");
    username_input.set_value(username);

    let password_input = doc
        .create_element("input")
        .ok()?
        .dyn_into::<HtmlInputElement>()
        .ok()?;
    password_input.set_type("password");
    password_input.set_class_name("source-endpoint-password");
    password_input.set_placeholder("password");
    password_input.set_value(password);

    let remove_button = doc
        .create_element("button")
        .ok()?
        .dyn_into::<HtmlButtonElement>()
        .ok()?;
    remove_button.set_type("button");
    remove_button.set_class_name("secondary source-endpoint-remove");
    remove_button.set_text_content(Some("Delete"));

    let _ = row.append_child(&name_input);
    let _ = row.append_child(&kind_select);
    let _ = row.append_child(&host_input);
    let _ = row.append_child(&port_input);
    let _ = row.append_child(&location_input);
    let _ = row.append_child(&username_input);
    let _ = row.append_child(&password_input);
    let _ = row.append_child(&remove_button);
    Some(row)
}

fn ensure_source_endpoint_row_exists() {
    let Some(doc) = web_document() else {
        return;
    };
    let Some(rows) = doc
        .get_element_by_id("source-endpoint-rows")
        .and_then(|node| node.dyn_into::<HtmlElement>().ok())
    else {
        return;
    };

    if doc
        .get_elements_by_class_name("source-endpoint-row")
        .length()
        > 0
    {
        return;
    }
    if let Some(row) = create_source_endpoint_row("", "sftp", "", "", "", "", "") {
        let _ = rows.append_child(&row);
    }
}

fn create_path_mapping_row(source: &str, dest: &str) -> Option<HtmlElement> {
    let doc = web_document()?;
    let row = doc
        .create_element("div")
        .ok()?
        .dyn_into::<HtmlElement>()
        .ok()?;
    row.set_class_name("path-map-row");
    let _ = row.set_attribute("data-path-map-row", "1");

    let source_input = doc
        .create_element("input")
        .ok()?
        .dyn_into::<HtmlInputElement>()
        .ok()?;
    source_input.set_class_name("path-map-source");
    source_input.set_type("text");
    source_input.set_placeholder("/host/path");
    source_input.set_value(source);
    let _ = source_input.set_attribute("data-map-source", "1");
    let _ = source_input.set_attribute("data-dir-autocomplete", "1");

    let arrow = doc
        .create_element("span")
        .ok()?
        .dyn_into::<HtmlElement>()
        .ok()?;
    arrow.set_class_name("path-map-arrow");
    arrow.set_text_content(Some("\u{2192}"));

    let dest_input = doc
        .create_element("input")
        .ok()?
        .dyn_into::<HtmlInputElement>()
        .ok()?;
    dest_input.set_class_name("path-map-dest");
    dest_input.set_type("text");
    dest_input.set_placeholder("/container/path");
    dest_input.set_value(dest);
    let _ = dest_input.set_attribute("data-map-dest", "1");
    let _ = dest_input.set_attribute("data-dir-autocomplete", "1");

    let remove_button = doc
        .create_element("button")
        .ok()?
        .dyn_into::<HtmlButtonElement>()
        .ok()?;
    remove_button.set_class_name("secondary path-map-remove");
    remove_button.set_type("button");
    remove_button.set_text_content(Some("Delete"));
    let _ = remove_button.set_attribute("data-path-map-remove", "1");

    let _ = row.append_child(&source_input);
    let _ = row.append_child(&arrow);
    let _ = row.append_child(&dest_input);
    let _ = row.append_child(&remove_button);
    Some(row)
}

fn ensure_path_mapping_row_exists() {
    let Some(doc) = web_document() else {
        return;
    };
    let Some(rows) = doc
        .get_element_by_id("path-mapping-rows")
        .and_then(|node| node.dyn_into::<HtmlElement>().ok())
    else {
        return;
    };

    if doc.get_elements_by_class_name("path-map-row").length() > 0 {
        return;
    }
    if let Some(row) = create_path_mapping_row("", "") {
        let _ = rows.append_child(&row);
    }
}

fn sync_local_whitelists_hidden() {
    let Some(doc) = web_document() else {
        return;
    };

    let sync = |class_name: &str, textarea_id: &str| {
        let Some(textarea) = doc
            .get_element_by_id(textarea_id)
            .and_then(|node| node.dyn_into::<HtmlTextAreaElement>().ok())
        else {
            return;
        };

        let inputs = doc.get_elements_by_class_name(class_name);
        let mut lines = Vec::new();
        for idx in 0..inputs.length() {
            let Some(input) = inputs
                .item(idx)
                .and_then(|node| node.dyn_into::<HtmlInputElement>().ok())
            else {
                continue;
            };
            let value = input.value().trim().to_string();
            if !value.is_empty() {
                lines.push(value);
            }
        }
        textarea.set_value(&lines.join("\n"));
    };

    sync("local-read-path", "local_read_whitelist");
    sync("local-write-path", "local_write_whitelist");
}

fn create_local_path_row(value: &str, input_class: &str, placeholder: &str) -> Option<HtmlElement> {
    let doc = web_document()?;
    let row = doc
        .create_element("div")
        .ok()?
        .dyn_into::<HtmlElement>()
        .ok()?;
    row.set_class_name("local-path-row");
    let _ = row.set_attribute("data-local-path-row", "1");

    let input = doc
        .create_element("input")
        .ok()?
        .dyn_into::<HtmlInputElement>()
        .ok()?;
    input.set_type("text");
    input.set_class_name(&format!("local-path-input {input_class}"));
    input.set_placeholder(placeholder);
    input.set_value(value);
    let _ = input.set_attribute("data-dir-autocomplete", "1");

    let remove_button = doc
        .create_element("button")
        .ok()?
        .dyn_into::<HtmlButtonElement>()
        .ok()?;
    remove_button.set_type("button");
    remove_button.set_class_name("secondary local-path-remove");
    remove_button.set_text_content(Some("Delete"));

    let _ = row.append_child(&input);
    let _ = row.append_child(&remove_button);
    Some(row)
}

fn ensure_local_path_row_exists(rows_id: &str, input_class: &str, placeholder: &str) {
    let Some(doc) = web_document() else {
        return;
    };
    let Some(rows) = doc
        .get_element_by_id(rows_id)
        .and_then(|node| node.dyn_into::<HtmlElement>().ok())
    else {
        return;
    };

    if rows.get_elements_by_class_name(input_class).length() > 0 {
        return;
    }
    if let Some(row) = create_local_path_row("", input_class, placeholder) {
        let _ = rows.append_child(&row);
    }
}

fn queue_config_autosave(form: HtmlFormElement, debounce: Rc<RefCell<Option<Timeout>>>) {
    if let Some(timeout) = debounce.borrow_mut().take() {
        timeout.cancel();
    }

    set_config_save_status("Saving...", "tag warning");
    let timeout = Timeout::new(450, move || {
        sync_path_mappings_hidden();
        sync_source_endpoints_hidden();
        sync_local_whitelists_hidden();
        let body = serialize_form_urlencoded(&form);
        spawn_local(async move {
            let request = Request::post("/api/config")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(body);

            let Ok(request) = request else {
                set_config_save_status("Save failed", "tag error");
                return;
            };
            match request.send().await {
                Ok(response) if response.ok() => {
                    set_config_save_status("Saved", "tag success");
                }
                _ => {
                    set_config_save_status("Save failed", "tag error");
                }
            }
        });
    });
    *debounce.borrow_mut() = Some(timeout);
}

fn static_model_suggestions(provider: &str) -> Vec<String> {
    match provider {
        "claude_code" | "anthropic" => vec![
            "sonnet".to_string(),
            "opus".to_string(),
            "haiku".to_string(),
            "claude-sonnet-4-20250514".to_string(),
            "claude-opus-4-5-20251101".to_string(),
        ],
        "openai" => vec![
            "gpt-4o".to_string(),
            "gpt-4.1".to_string(),
            "o3-mini".to_string(),
        ],
        "google" => vec!["gemini-2.0-flash".to_string(), "gemini-2.0-pro".to_string()],
        "openrouter" => vec![
            "anthropic/claude-sonnet-4".to_string(),
            "openai/gpt-4o".to_string(),
            "google/gemini-2.0-flash-001".to_string(),
        ],
        _ => Vec::new(),
    }
}

fn set_model_suggestions(models: Vec<String>) {
    let Some(doc) = web_document() else {
        return;
    };
    let Some(datalist) = doc.get_element_by_id("llm-model-suggestions") else {
        return;
    };

    let mut unique = BTreeSet::new();
    for model in models {
        let value = model.trim();
        if !value.is_empty() {
            unique.insert(value.to_string());
        }
    }

    datalist.set_inner_html("");
    for model in unique {
        let Ok(option) = doc.create_element("option") else {
            continue;
        };
        let _ = option.set_attribute("value", &model);
        let _ = datalist.append_child(&option);
    }
}

fn refresh_model_suggestions(provider: &str) {
    let provider = provider.trim().to_string();
    let fallback = static_model_suggestions(&provider);

    let endpoint = match provider.as_str() {
        "claude_code" => Some("/api/claude/models"),
        "ollama" => Some("/api/ollama/models"),
        _ => None,
    };

    let Some(endpoint) = endpoint else {
        set_model_suggestions(fallback);
        return;
    };

    spawn_local(async move {
        let mut models = fetch_json::<ModelListResponse>(endpoint)
            .await
            .map(|response| response.models)
            .unwrap_or_default();

        if models.is_empty() {
            models = fallback;
        } else {
            models.extend(fallback);
        }
        set_model_suggestions(models);
    });
}

fn refresh_model_suggestions_from_dom() {
    let Some(doc) = web_document() else {
        return;
    };
    let provider = doc
        .get_element_by_id("llm_provider")
        .and_then(|node| node.dyn_into::<HtmlSelectElement>().ok())
        .map(|select| select.value())
        .unwrap_or_else(|| "claude_code".to_string());
    refresh_model_suggestions(&provider);
}

fn next_dir_autocomplete_id() -> String {
    DIR_AUTOCOMPLETE_SEQ.with(|seq| {
        let next = seq.get().saturating_add(1);
        seq.set(next);
        format!("dir-autocomplete-{next}")
    })
}

#[derive(Clone)]
struct DirectoryQuery {
    request_path: Option<String>,
    fallback_prefix: String,
}

fn parse_directory_query(value: &str) -> DirectoryQuery {
    let trimmed = value.trim().replace('\\', "/");
    if trimmed.is_empty() {
        return DirectoryQuery {
            request_path: None,
            fallback_prefix: String::new(),
        };
    }

    if trimmed.contains('/') {
        let path = trimmed.trim_end_matches('/').to_string();
        let request_path = if path.is_empty() {
            Some("/".to_string())
        } else {
            Some(path)
        };
        return DirectoryQuery {
            request_path,
            fallback_prefix: String::new(),
        };
    }

    DirectoryQuery {
        request_path: Some(".".to_string()),
        fallback_prefix: trimmed,
    }
}

fn normalize_path_key(value: &str) -> String {
    let mut normalized = value.trim().replace('\\', "/");
    while normalized.len() > 1 && normalized.ends_with('/') {
        normalized.pop();
    }
    normalized
}

fn hide_all_directory_panels_except(except_panel_id: Option<&str>) {
    let Some(doc) = web_document() else {
        return;
    };
    let Ok(panels) = doc.query_selector_all(".dir-autocomplete-panel") else {
        return;
    };

    for idx in 0..panels.length() {
        let Some(panel) = panels
            .item(idx)
            .and_then(|node| node.dyn_into::<HtmlElement>().ok())
        else {
            continue;
        };

        if except_panel_id
            .map(|panel_id| panel.id() == panel_id)
            .unwrap_or(false)
        {
            continue;
        }

        let _ = panel.style().set_property("display", "none");
    }
}

fn hide_directory_panel(panel_id: &str) {
    let Some(doc) = web_document() else {
        return;
    };
    let Some(panel) = doc
        .get_element_by_id(panel_id)
        .and_then(|node| node.dyn_into::<HtmlElement>().ok())
    else {
        return;
    };
    let _ = panel.style().set_property("display", "none");
}

fn ensure_directory_panel(panel_id: &str) -> Option<HtmlElement> {
    let doc = web_document()?;

    if let Some(existing) = doc
        .get_element_by_id(panel_id)
        .and_then(|node| node.dyn_into::<HtmlElement>().ok())
    {
        return Some(existing);
    }

    let panel = doc
        .create_element("div")
        .ok()?
        .dyn_into::<HtmlElement>()
        .ok()?;
    panel.set_id(panel_id);
    panel.set_class_name("dir-autocomplete-panel");
    let _ = panel.set_attribute("role", "listbox");
    let _ = panel.style().set_property("display", "none");

    // Prevent click-to-select from blurring/closing the panel.
    {
        let callback = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
            event.prevent_default();
        });
        let _ =
            panel.add_event_listener_with_callback("mousedown", callback.as_ref().unchecked_ref());
        callback.forget();
    }

    if let Some(body) = doc.body() {
        let _ = body.append_child(&panel);
        Some(panel)
    } else {
        None
    }
}

fn position_directory_panel(input: &HtmlInputElement, panel: &HtmlElement) {
    let Ok(input_element) = input.clone().dyn_into::<HtmlElement>() else {
        return;
    };

    let mut left = 0_i32;
    let mut top = 0_i32;
    let mut current = Some(input_element.clone());
    while let Some(node) = current {
        left += node.offset_left();
        top += node.offset_top();
        current = node
            .offset_parent()
            .and_then(|parent| parent.dyn_into::<HtmlElement>().ok());
    }
    let top = top + input_element.offset_height() + 4;
    let width = input_element.offset_width().max(220);

    let style = panel.style();
    let _ = style.set_property("left", &format!("{left}px"));
    let _ = style.set_property("top", &format!("{top}px"));
    let _ = style.set_property("width", &format!("{width}px"));
}

fn show_directory_panel_for_input(input: &HtmlInputElement, panel_id: &str) {
    let Some(doc) = web_document() else {
        return;
    };
    let Some(panel) = doc
        .get_element_by_id(panel_id)
        .and_then(|node| node.dyn_into::<HtmlElement>().ok())
    else {
        return;
    };

    hide_all_directory_panels_except(Some(panel_id));
    position_directory_panel(input, &panel);
    let _ = panel.style().set_property("display", "block");
}

fn render_directory_suggestions(
    input: &HtmlInputElement,
    panel_id: &str,
    query: &DirectoryQuery,
    payload: FsListResponse,
) {
    let Some(doc) = web_document() else {
        return;
    };
    let Some(panel) = doc
        .get_element_by_id(panel_id)
        .and_then(|node| node.dyn_into::<HtmlElement>().ok())
    else {
        return;
    };

    panel.set_inner_html("");

    let effective_prefix = if query.fallback_prefix.trim().is_empty() {
        String::new()
    } else {
        query.fallback_prefix.trim().to_ascii_lowercase()
    };

    let mut option_count = 0usize;
    if let Some(parent) = payload.parent.as_deref() {
        let Ok(button_node) = doc.create_element("button") else {
            return;
        };
        let Ok(button) = button_node.dyn_into::<HtmlButtonElement>() else {
            return;
        };
        button.set_type("button");
        button.set_class_name("dir-autocomplete-item parent");
        button.set_text_content(Some(".."));
        let _ = button.set_attribute("title", parent);

        let parent_path = parent.to_string();
        let input_ref = input.clone();
        let callback = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
            event.prevent_default();
            input_ref.set_value(&parent_path);
            if let Ok(input_event) = web_sys::Event::new("input") {
                let _ = input_ref.dispatch_event(&input_event);
            }
        });
        let _ =
            button.add_event_listener_with_callback("mousedown", callback.as_ref().unchecked_ref());
        callback.forget();

        let _ = panel.append_child(&button);
        option_count += 1;
    }

    let payload_path = normalize_path_key(&payload.path);
    let current_value = normalize_path_key(&input.value());
    let mut directories = payload.directories;
    directories.sort_by(|left, right| {
        left.name
            .to_ascii_lowercase()
            .cmp(&right.name.to_ascii_lowercase())
    });

    for entry in directories {
        if !effective_prefix.is_empty()
            && !entry
                .name
                .to_ascii_lowercase()
                .starts_with(&effective_prefix)
        {
            continue;
        }

        // If the query resolved to this exact directory, skip rendering itself.
        if payload_path == current_value && normalize_path_key(&entry.path) == current_value {
            continue;
        }

        let Ok(button_node) = doc.create_element("button") else {
            continue;
        };
        let Ok(button) = button_node.dyn_into::<HtmlButtonElement>() else {
            continue;
        };
        button.set_type("button");
        button.set_class_name("dir-autocomplete-item");
        button.set_text_content(Some(&entry.name));
        let _ = button.set_attribute("title", &entry.path);

        let next_path = entry.path.clone();
        let input_ref = input.clone();
        let callback = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
            event.prevent_default();
            input_ref.set_value(&next_path);
            if let Ok(input_event) = web_sys::Event::new("input") {
                let _ = input_ref.dispatch_event(&input_event);
            }
        });
        let _ =
            button.add_event_listener_with_callback("mousedown", callback.as_ref().unchecked_ref());
        callback.forget();

        let _ = panel.append_child(&button);
        option_count += 1;
    }

    if option_count == 0 {
        if let Ok(empty) = doc.create_element("div") {
            empty.set_class_name("dir-autocomplete-empty");
            empty.set_text_content(Some("No subdirectories"));
            let _ = panel.append_child(&empty);
        }
    }

    show_directory_panel_for_input(input, panel_id);
}

fn refresh_directory_suggestions(input: HtmlInputElement) {
    let Some(panel_id) = input
        .get_attribute("data-dir-panel-id")
        .filter(|value| !value.trim().is_empty())
    else {
        return;
    };

    let current_value = input.value();
    let query = parse_directory_query(&current_value);
    let request_token = format!("{:.3}", Date::now());
    let _ = input.set_attribute("data-dir-request-token", &request_token);

    let mut url = "/api/fs/list".to_string();
    if let Some(path) = query.request_path.as_deref() {
        url = format!("/api/fs/list?path={}", encode_component(path));
    }

    spawn_local(async move {
        let payload = fetch_json::<FsListResponse>(&url).await;
        let still_latest = input
            .get_attribute("data-dir-request-token")
            .map(|token| token == request_token)
            .unwrap_or(false);
        if !still_latest {
            return;
        }

        if let Some(payload) = payload {
            render_directory_suggestions(&input, &panel_id, &query, payload);
        } else {
            hide_directory_panel(&panel_id);
        }
    });
}

fn ensure_directory_global_handlers() {
    let already = DIR_AUTOCOMPLETE_GLOBAL_HANDLER.with(|flag| {
        if flag.get() {
            true
        } else {
            flag.set(true);
            false
        }
    });
    if already {
        return;
    }

    let Some(doc) = web_document() else {
        return;
    };

    {
        let callback = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
            let Some(target) = event
                .target()
                .and_then(|node| node.dyn_into::<web_sys::Element>().ok())
            else {
                hide_all_directory_panels_except(None);
                return;
            };

            if target
                .closest("input[data-dir-autocomplete='1']")
                .ok()
                .flatten()
                .is_some()
            {
                return;
            }
            if target
                .closest(".dir-autocomplete-panel")
                .ok()
                .flatten()
                .is_some()
            {
                return;
            }

            hide_all_directory_panels_except(None);
        });
        let _ =
            doc.add_event_listener_with_callback("mousedown", callback.as_ref().unchecked_ref());
        callback.forget();
    }
}

fn ensure_directory_autocomplete_input(input: &HtmlInputElement) {
    if input.get_attribute("data-dir-autocomplete-init").as_deref() == Some("1") {
        return;
    }

    ensure_directory_global_handlers();

    let input_id = if input.id().trim().is_empty() {
        let generated = next_dir_autocomplete_id();
        input.set_id(&generated);
        generated
    } else {
        input.id()
    };
    let panel_id = format!("{input_id}-dir-panel");
    let _ = input.set_attribute("data-dir-panel-id", &panel_id);
    let _ = input.set_attribute("autocomplete", "off");
    let _ = ensure_directory_panel(&panel_id);

    let _ = input.set_attribute("data-dir-autocomplete-init", "1");

    {
        let input_ref = input.clone();
        let callback = Closure::<dyn FnMut(web_sys::Event)>::new(move |_event: web_sys::Event| {
            refresh_directory_suggestions(input_ref.clone());
        });
        let _ = input.add_event_listener_with_callback("focus", callback.as_ref().unchecked_ref());
        let _ = input.add_event_listener_with_callback("input", callback.as_ref().unchecked_ref());
        let _ = input.add_event_listener_with_callback("change", callback.as_ref().unchecked_ref());
        callback.forget();
    }

    {
        let panel_id_ref = panel_id.clone();
        let callback = Closure::<dyn FnMut(web_sys::Event)>::new(move |_event: web_sys::Event| {
            // Delay hide to allow mousedown handlers on panel options to run.
            let panel_id = panel_id_ref.clone();
            Timeout::new(140, move || {
                hide_directory_panel(&panel_id);
            })
            .forget();
        });
        let _ = input.add_event_listener_with_callback("blur", callback.as_ref().unchecked_ref());
        callback.forget();
    }
}

fn init_directory_autocomplete_inputs() {
    let Some(doc) = web_document() else {
        return;
    };
    let Ok(inputs) = doc.query_selector_all("input[data-dir-autocomplete='1']") else {
        return;
    };

    for idx in 0..inputs.length() {
        let Some(input) = inputs
            .item(idx)
            .and_then(|node| node.dyn_into::<HtmlInputElement>().ok())
        else {
            continue;
        };
        ensure_directory_autocomplete_input(&input);
    }
}

fn init_config_live_form() {
    let Some(doc) = web_document() else {
        return;
    };
    let Some(form) = doc
        .get_element_by_id("config-form")
        .and_then(|node| node.dyn_into::<HtmlFormElement>().ok())
    else {
        return;
    };

    sync_torrent_client_panels();
    sync_path_mappings_hidden();
    sync_source_endpoints_hidden();
    sync_local_whitelists_hidden();
    ensure_path_mapping_row_exists();
    ensure_source_endpoint_row_exists();
    ensure_local_path_row_exists("local-read-rows", "local-read-path", "/mnt/data");
    ensure_local_path_row_exists("local-write-rows", "local-write-path", "/mnt/downloads");
    init_directory_autocomplete_inputs();
    refresh_model_suggestions_from_dom();
    set_config_save_status("Auto-save enabled", "tag");

    let autosave_debounce = Rc::new(RefCell::new(None::<Timeout>));

    {
        let callback = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
            event.prevent_default();
        });
        let _ = form.add_event_listener_with_callback("submit", callback.as_ref().unchecked_ref());
        callback.forget();
    }

    {
        let form_ref = form.clone();
        let debounce = autosave_debounce.clone();
        let callback = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
            let target = event
                .target()
                .and_then(|node| node.dyn_into::<web_sys::Element>().ok());
            let target_id = target.as_ref().map(|node| node.id()).unwrap_or_default();

            if let Some(target) = target.as_ref() {
                if target.class_list().contains("source-endpoint-kind") {
                    if let Ok(select) = target.clone().dyn_into::<HtmlSelectElement>() {
                        apply_default_port_for_source_select(&select);
                    }
                }
            }

            if target_id == "torrent_client" {
                sync_torrent_client_panels();
            } else if target_id == "llm_provider" {
                refresh_model_suggestions_from_dom();
            }

            sync_path_mappings_hidden();
            sync_source_endpoints_hidden();
            sync_local_whitelists_hidden();
            queue_config_autosave(form_ref.clone(), debounce.clone());
        });
        let _ = form.add_event_listener_with_callback("input", callback.as_ref().unchecked_ref());
        let _ = form.add_event_listener_with_callback("change", callback.as_ref().unchecked_ref());
        callback.forget();
    }

    if let Some(add_button) = doc
        .get_element_by_id("path-mapping-add")
        .and_then(|node| node.dyn_into::<HtmlButtonElement>().ok())
    {
        let form_ref = form.clone();
        let debounce = autosave_debounce.clone();
        let callback = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
            event.prevent_default();
            let Some(doc) = web_document() else {
                return;
            };
            let Some(rows) = doc
                .get_element_by_id("path-mapping-rows")
                .and_then(|node| node.dyn_into::<HtmlElement>().ok())
            else {
                return;
            };
            if let Some(row) = create_path_mapping_row("", "") {
                let _ = rows.append_child(&row);
                init_directory_autocomplete_inputs();
                sync_path_mappings_hidden();
                sync_source_endpoints_hidden();
                sync_local_whitelists_hidden();
                queue_config_autosave(form_ref.clone(), debounce.clone());
            }
        });
        let _ =
            add_button.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }

    if let Some(rows) = doc
        .get_element_by_id("path-mapping-rows")
        .and_then(|node| node.dyn_into::<HtmlElement>().ok())
    {
        let form_ref = form.clone();
        let debounce = autosave_debounce.clone();
        let callback = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
            let Some(target) = event
                .target()
                .and_then(|node| node.dyn_into::<HtmlElement>().ok())
            else {
                return;
            };
            if !target.class_list().contains("path-map-remove") {
                return;
            }
            event.prevent_default();

            if let Some(parent) = target.parent_element() {
                parent.remove();
            }
            ensure_path_mapping_row_exists();
            init_directory_autocomplete_inputs();
            sync_path_mappings_hidden();
            sync_source_endpoints_hidden();
            sync_local_whitelists_hidden();
            queue_config_autosave(form_ref.clone(), debounce.clone());
        });
        let _ = rows.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }

    if let Some(add_button) = doc
        .get_element_by_id("source-endpoint-add")
        .and_then(|node| node.dyn_into::<HtmlButtonElement>().ok())
    {
        let form_ref = form.clone();
        let debounce = autosave_debounce.clone();
        let callback = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
            event.prevent_default();
            let Some(doc) = web_document() else {
                return;
            };
            let Some(rows) = doc
                .get_element_by_id("source-endpoint-rows")
                .and_then(|node| node.dyn_into::<HtmlElement>().ok())
            else {
                return;
            };
            if let Some(row) = create_source_endpoint_row("", "sftp", "", "", "", "", "") {
                let _ = rows.append_child(&row);
                sync_source_endpoints_hidden();
                queue_config_autosave(form_ref.clone(), debounce.clone());
            }
        });
        let _ =
            add_button.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }

    if let Some(rows) = doc
        .get_element_by_id("source-endpoint-rows")
        .and_then(|node| node.dyn_into::<HtmlElement>().ok())
    {
        let form_ref = form.clone();
        let debounce = autosave_debounce.clone();
        let callback = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
            let Some(target) = event
                .target()
                .and_then(|node| node.dyn_into::<HtmlElement>().ok())
            else {
                return;
            };
            if !target.class_list().contains("source-endpoint-remove") {
                return;
            }
            event.prevent_default();

            if let Some(parent) = target.parent_element() {
                parent.remove();
            }
            ensure_source_endpoint_row_exists();
            sync_source_endpoints_hidden();
            queue_config_autosave(form_ref.clone(), debounce.clone());
        });
        let _ = rows.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }

    if let Some(button) = doc
        .get_element_by_id("test-torrent-client")
        .and_then(|node| node.dyn_into::<HtmlButtonElement>().ok())
    {
        let form_ref = form.clone();
        let callback = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
            event.prevent_default();
            set_text("torrent-test-result", "Testing...");
            set_class("torrent-test-result", "config-inline-status");
            sync_path_mappings_hidden();
            sync_source_endpoints_hidden();
            sync_local_whitelists_hidden();
            let body = serialize_form_urlencoded(&form_ref);
            spawn_local(async move {
                let request = Request::post("/api/test/torrent")
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(body);
                let Ok(request) = request else {
                    set_text("torrent-test-result", "Request error");
                    set_class("torrent-test-result", "config-inline-status error");
                    return;
                };

                let Ok(response) = request.send().await else {
                    set_text("torrent-test-result", "Connection failed");
                    set_class("torrent-test-result", "config-inline-status error");
                    return;
                };
                let payload = response.json::<TorrentTestResponse>().await.ok();
                if let Some(payload) = payload {
                    if payload.success {
                        let message = payload
                            .message
                            .unwrap_or_else(|| "Connection successful".to_string());
                        set_text("torrent-test-result", message);
                        set_class("torrent-test-result", "config-inline-status success");
                    } else {
                        let message = payload
                            .error
                            .unwrap_or_else(|| "Connection failed".to_string());
                        set_text("torrent-test-result", message);
                        set_class("torrent-test-result", "config-inline-status error");
                    }
                } else {
                    set_text("torrent-test-result", "Unexpected response");
                    set_class("torrent-test-result", "config-inline-status error");
                }
            });
        });
        let _ = button.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }

    if let Some(add_button) = doc
        .get_element_by_id("local-read-add")
        .and_then(|node| node.dyn_into::<HtmlButtonElement>().ok())
    {
        let form_ref = form.clone();
        let debounce = autosave_debounce.clone();
        let callback = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
            event.prevent_default();
            let Some(doc) = web_document() else {
                return;
            };
            let Some(rows) = doc
                .get_element_by_id("local-read-rows")
                .and_then(|node| node.dyn_into::<HtmlElement>().ok())
            else {
                return;
            };
            if let Some(row) = create_local_path_row("", "local-read-path", "/mnt/data") {
                let _ = rows.append_child(&row);
                init_directory_autocomplete_inputs();
                sync_path_mappings_hidden();
                sync_source_endpoints_hidden();
                sync_local_whitelists_hidden();
                queue_config_autosave(form_ref.clone(), debounce.clone());
            }
        });
        let _ =
            add_button.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }

    if let Some(add_button) = doc
        .get_element_by_id("local-write-add")
        .and_then(|node| node.dyn_into::<HtmlButtonElement>().ok())
    {
        let form_ref = form.clone();
        let debounce = autosave_debounce.clone();
        let callback = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
            event.prevent_default();
            let Some(doc) = web_document() else {
                return;
            };
            let Some(rows) = doc
                .get_element_by_id("local-write-rows")
                .and_then(|node| node.dyn_into::<HtmlElement>().ok())
            else {
                return;
            };
            if let Some(row) = create_local_path_row("", "local-write-path", "/mnt/downloads") {
                let _ = rows.append_child(&row);
                init_directory_autocomplete_inputs();
                sync_path_mappings_hidden();
                sync_source_endpoints_hidden();
                sync_local_whitelists_hidden();
                queue_config_autosave(form_ref.clone(), debounce.clone());
            }
        });
        let _ =
            add_button.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }

    if let Some(rows) = doc
        .get_element_by_id("local-read-rows")
        .and_then(|node| node.dyn_into::<HtmlElement>().ok())
    {
        let form_ref = form.clone();
        let debounce = autosave_debounce.clone();
        let callback = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
            let Some(target) = event
                .target()
                .and_then(|node| node.dyn_into::<HtmlElement>().ok())
            else {
                return;
            };
            if !target.class_list().contains("local-path-remove") {
                return;
            }
            event.prevent_default();

            if let Some(parent) = target.parent_element() {
                parent.remove();
            }
            ensure_local_path_row_exists("local-read-rows", "local-read-path", "/mnt/data");
            init_directory_autocomplete_inputs();
            sync_path_mappings_hidden();
            sync_source_endpoints_hidden();
            sync_local_whitelists_hidden();
            queue_config_autosave(form_ref.clone(), debounce.clone());
        });
        let _ = rows.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }

    if let Some(rows) = doc
        .get_element_by_id("local-write-rows")
        .and_then(|node| node.dyn_into::<HtmlElement>().ok())
    {
        let form_ref = form.clone();
        let debounce = autosave_debounce.clone();
        let callback = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
            let Some(target) = event
                .target()
                .and_then(|node| node.dyn_into::<HtmlElement>().ok())
            else {
                return;
            };
            if !target.class_list().contains("local-path-remove") {
                return;
            }
            event.prevent_default();

            if let Some(parent) = target.parent_element() {
                parent.remove();
            }
            ensure_local_path_row_exists("local-write-rows", "local-write-path", "/mnt/downloads");
            init_directory_autocomplete_inputs();
            sync_path_mappings_hidden();
            sync_source_endpoints_hidden();
            sync_local_whitelists_hidden();
            queue_config_autosave(form_ref.clone(), debounce.clone());
        });
        let _ = rows.add_event_listener_with_callback("click", callback.as_ref().unchecked_ref());
        callback.forget();
    }
}

async fn fetch_json<T>(url: &str) -> Option<T>
where
    T: DeserializeOwned,
{
    let response = Request::get(url).send().await.ok()?;
    if !response.ok() {
        return None;
    }
    response.json::<T>().await.ok()
}

fn main() {
    console_error_panic_hook::set_once();

    if let Some(root) = web_document()
        .and_then(|doc| doc.get_element_by_id("leptos-runtime-root"))
        .and_then(|node| node.dyn_into::<HtmlElement>().ok())
    {
        mount_to(root, || view! { <App /> });
    } else {
        mount_to_body(|| view! { <App /> });
    }

    start_status_poller();
    init_job_detail_live_updates();
    init_config_live_form();
}
