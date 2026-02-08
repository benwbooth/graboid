use std::cell::RefCell;
use std::rc::Rc;

use gloo_net::http::Request;
use gloo_timers::callback::Interval;
use js_sys::Date;
use leptos::*;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen::closure::Closure;
use wasm_bindgen_futures::spawn_local;
use web_sys::{Document, HtmlElement, HtmlImageElement};

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

fn update_job_summary(job: &JobView) {
    let progress_text = if job.progress_message.trim().is_empty() {
        format!("{:.0}%", job.progress_percent)
    } else {
        format!("{:.0}% {}", job.progress_percent, job.progress_message)
    };

    set_class(
        "job-status-tag",
        format!("tag {}", job_status_class(&job.status)).trim(),
    );
    set_text("job-status-tag", &job.status);
    set_text("job-progress-text", &progress_text);
    set_text("job-phase-text", &job.current_phase);
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
            "-"
        } else {
            &job.source_url
        },
    );
    set_text("job-destination-text", &job.destination_path);
    set_text("job-operation-text", &job.file_operation);
    set_text("job-priority-text", job.priority.to_string());
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

    let metadata = serde_json::to_string_pretty(&job.metadata).unwrap_or_else(|_| "{}".to_string());
    set_text("job-metadata-text", metadata);

    let file_filter_text = if job.file_filter.is_empty() {
        "(none)".to_string()
    } else {
        job.file_filter.join("\n")
    };
    set_text("job-file-filter-text", file_filter_text);

    render_code_list("job-found-urls", &job.found_urls, "No URLs found yet.");
    render_artifact_list(
        "job-downloaded-files",
        &job.id,
        "downloaded",
        &job.downloaded_files,
        "No downloaded files yet.",
    );
    render_artifact_list(
        "job-final-paths",
        &job.id,
        "final",
        &job.final_paths,
        "No final paths yet.",
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

fn render_claude_messages(messages: &[String]) {
    let Some(doc) = web_document() else {
        return;
    };
    let Some(container) = doc.get_element_by_id("job-step-claude") else {
        return;
    };

    let signature = format!("claude|{}", messages.join("\u{1f}"));
    if !signature_changed(&container, &signature) {
        return;
    }

    container.set_inner_html("");

    if messages.is_empty() {
        if let Ok(empty) = doc.create_element("p") {
            let _ = empty.set_attribute("style", "color: var(--text-dim);");
            empty.set_text_content(Some("No Claude notes for this step."));
            let _ = container.append_child(&empty);
        }
        return;
    }

    for message in messages {
        let Ok(wrapper) = doc.create_element("div") else {
            continue;
        };
        wrapper.set_class_name("message");

        let Ok(role) = doc.create_element("div") else {
            continue;
        };
        role.set_class_name("role");
        role.set_text_content(Some("Claude"));

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
        render_claude_messages(&[]);
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

    render_claude_messages(&step.claude_messages);
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
}
