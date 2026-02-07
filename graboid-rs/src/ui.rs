use std::collections::{BTreeMap, HashMap};

use chrono::Utc;
use leptos::*;
use serde_json::Value;

use crate::models::{Job, JobLogEntry, JobStatus, JobStepDetail, NoteEntry, NoteStats};
use crate::state::{AgentMessage, GitInfo};

const BASE_CSS: &str = include_str!("ui_assets/base.css");
const LOGIN_CSS: &str = include_str!("ui_assets/login.css");

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub path: String,
    pub scheme: String,
    pub netloc: String,
    pub query_params: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct RuntimeBadge {
    pub is_running: bool,
    pub current_task: String,
}

impl RuntimeBadge {
    fn status_text(&self) -> String {
        let task = self.current_task.trim();
        if self.is_running && !task.is_empty() {
            format!("Running: {task}")
        } else {
            "Idle".to_string()
        }
    }
}

pub fn render_login_page(error: bool) -> String {
    let body = view! {
        <div class="login-container">
            <div class="logo">
                <h1>"Graboid"</h1>
                <p>"Browser automation agent"</p>
            </div>
            {error.then(|| {
                view! { <div class="error">"Invalid username or password"</div> }
            })}
            <form method="POST" action="/login">
                <div class="form-group">
                    <label for="username">"Username"</label>
                    <input type="text" name="username" id="username" required autofocus />
                </div>
                <div class="form-group">
                    <label for="password">"Password"</label>
                    <input type="password" name="password" id="password" required />
                </div>
                <button type="submit">"Sign In"</button>
            </form>
        </div>
    };

    render_document("Login - Graboid", LOGIN_CSS, None, body)
}

pub fn render_index_page(
    request: &RequestContext,
    git: &GitInfo,
    runtime: &RuntimeBadge,
) -> String {
    let status_text = runtime.status_text();

    let content = view! {
        <>
            <h1>"Dashboard"</h1>
            <div class="grid">
                <div class="card">
                    <h2>"Quick Actions"</h2>
                    <p style="color: var(--text-dim); margin-bottom: 1rem;">
                        "Browse websites and download content using AI-powered automation."
                    </p>
                    <a href="/browser" class="btn">"Open Browser View"</a>
                    <a href="/config" class="btn secondary" style="margin-left: 0.5rem;">"Configure"</a>
                </div>
                <div class="card">
                    <h2>"Status"</h2>
                    <div style="display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem;">
                        <div class="status-dot" class:running=runtime.is_running id="dashboard-status-dot"></div>
                        <span id="dashboard-status-text">{status_text}</span>
                    </div>
                    <div id="download-stats">
                        <p style="color: var(--text-dim);">"Status updates appear on page reload."</p>
                    </div>
                </div>
            </div>
            <div class="card">
                <h2>"Recent Activity"</h2>
                <div id="messages" class="messages">
                    <p style="color: var(--text-dim);">
                        "No recent activity. Start a download to see updates here."
                    </p>
                </div>
            </div>
            <div class="card">
                <h2>"Agent Notes"</h2>
                <p style="color: var(--text-dim);">"Open the Notes tab for current statistics."</p>
            </div>
        </>
    };

    render_app_page_with_refresh(
        request,
        git,
        runtime,
        "Dashboard - Graboid",
        Some(5),
        content,
    )
}

pub fn render_config_page(
    request: &RequestContext,
    git: &GitInfo,
    runtime: &RuntimeBadge,
    config: &serde_json::Map<String, Value>,
    config_path: &str,
) -> String {
    let saved = request
        .query_params
        .get("saved")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);

    let content = render_config_content(config, config_path, saved);
    render_app_page(request, git, runtime, "Configuration - Graboid", content)
}

pub fn render_notes_page(
    request: &RequestContext,
    git: &GitInfo,
    runtime: &RuntimeBadge,
    stats: &NoteStats,
    domains: &[String],
    domain_notes: &BTreeMap<String, Vec<NoteEntry>>,
) -> String {
    let content = render_notes_content(stats, domains, domain_notes);
    render_app_page_with_refresh(
        request,
        git,
        runtime,
        "Agent Notes - Graboid",
        Some(10),
        content,
    )
}

pub fn render_browser_page(
    request: &RequestContext,
    git: &GitInfo,
    runtime: &RuntimeBadge,
    screenshot: Option<(String, String)>,
    messages: &[AgentMessage],
) -> String {
    let (screenshot_src, current_url) = screenshot
        .map(|(img, url)| (format!("data:image/png;base64,{img}"), url))
        .unwrap_or_else(|| (String::new(), "-".to_string()));
    let image_style = if screenshot_src.is_empty() {
        "display: none;"
    } else {
        "display: block;"
    };
    let placeholder_style = if screenshot_src.is_empty() {
        "display: block;"
    } else {
        "display: none;"
    };
    let message_items: Vec<View> = if messages.is_empty() {
        vec![
            view! { <p style="color: var(--text-dim);">"Waiting for agent activity..."</p> }
                .into_view(),
        ]
    } else {
        messages
            .iter()
            .map(|entry| {
                view! {
                    <div class="message">
                        <div class="role">{entry.role.clone()}</div>
                        <div class="content">{entry.content.clone()}</div>
                    </div>
                }
                .into_view()
            })
            .collect()
    };

    let content = view! {
        <>
            <h1>"Browser View"</h1>
            <div class="grid-2">
                <div>
                    <div class="card" style="padding: 0; overflow: hidden;">
                        <div id="browser-view">
                            <img
                                id="browser-screenshot"
                                style=image_style
                                src=screenshot_src
                                alt="Browser Screenshot"
                            />
                            <div id="browser-placeholder" class="placeholder" style=placeholder_style>
                                <p>"No browser session active"</p>
                                <p style="font-size: 0.875rem; margin-top: 0.5rem;">
                                    "Start a browse task to see the browser here"
                                </p>
                            </div>
                        </div>
                    </div>
                    <div class="card">
                        <div style="display: flex; align-items: center; gap: 1rem;">
                            <span style="color: var(--text-dim);">"URL:"</span>
                            <code id="browser-url" style="flex: 1; color: var(--accent);">{current_url}</code>
                        </div>
                    </div>
                </div>
                <div>
                    <div class="card">
                        <h2>"Agent Messages"</h2>
                        <div id="messages" class="messages" style="max-height: 600px;">{message_items}</div>
                    </div>
                    <div class="card">
                        <h2>"Controls"</h2>
                        <p style="color: var(--text-dim); margin-bottom: 1rem;">
                            "Run tasks from the command line:"
                        </p>
                        <code
                            style="display: block; background: var(--bg); padding: 1rem; border-radius: 0.25rem; margin-bottom: 1rem;"
                        >
                            "graboid browse https://example.com \"find download links\""
                        </code>
                        <p style="color: var(--text-dim); font-size: 0.875rem;">
                            "The browser view will update automatically when a task starts."
                        </p>
                    </div>
                </div>
            </div>
        </>
    };

    render_app_page_with_refresh(
        request,
        git,
        runtime,
        "Browser View - Graboid",
        Some(3),
        content,
    )
}

pub fn render_jobs_page(
    request: &RequestContext,
    git: &GitInfo,
    runtime: &RuntimeBadge,
    api_key: &str,
    jobs: &[Job],
    total: i64,
    offset: i64,
    limit: i64,
    message: Option<&str>,
) -> String {
    let content = render_jobs_content(request, api_key, jobs, total, offset, limit, message);
    let refresh = if jobs.iter().any(|job| is_active_status(job.status)) {
        Some(5)
    } else {
        Some(15)
    };
    render_app_page_with_refresh(request, git, runtime, "Jobs - Graboid", refresh, content)
}

pub fn render_job_detail_page(
    request: &RequestContext,
    git: &GitInfo,
    runtime: &RuntimeBadge,
    api_key: &str,
    job: &Job,
    steps: &[JobStepDetail],
    logs: &[JobLogEntry],
) -> String {
    let short_id: String = job.id.chars().take(8).collect();
    let title = format!("Job {short_id} - Graboid");
    let content = render_job_detail_content(request, api_key, job, steps, logs);
    let refresh = if is_active_status(job.status) {
        Some(3)
    } else {
        Some(12)
    };
    render_app_page_with_refresh(request, git, runtime, &title, refresh, content)
}

fn render_job_detail_content(
    request: &RequestContext,
    api_key: &str,
    job: &Job,
    steps: &[JobStepDetail],
    logs: &[JobLogEntry],
) -> View {
    let status_class = job_status_class(job.status).to_string();
    let status_text = job.status.as_str().to_string();
    let phase_text = job.current_phase.as_str().to_string();
    let progress_text = if job.progress_message.trim().is_empty() {
        format!("{:.0}%", job.progress_percent)
    } else {
        format!("{:.0}% {}", job.progress_percent, job.progress_message)
    };
    let source_url = if job.source_url.trim().is_empty() {
        "-".to_string()
    } else {
        job.source_url.clone()
    };
    let metadata = serde_json::to_string_pretty(&job.metadata).unwrap_or_else(|_| "{}".to_string());
    let total_steps = steps.len();
    let selected_step = request
        .query_params
        .get("step")
        .and_then(|value| value.parse::<usize>().ok())
        .map(|value| value.saturating_sub(1))
        .filter(|index| *index < total_steps)
        .unwrap_or_else(|| total_steps.saturating_sub(1));

    let selected_step_detail = steps.get(selected_step);
    let step_counter = if total_steps == 0 {
        "No steps yet".to_string()
    } else {
        format!("Step {}/{}", selected_step + 1, total_steps)
    };
    let step_title = selected_step_detail
        .map(|step| format!("Step {}: {}", step.step_number, step.action))
        .unwrap_or_else(|| "No navigation steps yet".to_string());
    let step_meta = selected_step_detail
        .map(|step| format!("{} | {}", step.timestamp.to_rfc3339(), step.url))
        .unwrap_or_else(|| "Waiting for first navigation step".to_string());
    let step_observation = selected_step_detail
        .map(|step| step.observation.clone())
        .unwrap_or_else(|| "No step observation available yet.".to_string());
    let step_has_error = selected_step_detail
        .map(|step| step.is_error)
        .unwrap_or(false);
    let step_screenshot_src = selected_step_detail
        .and_then(|step| step.screenshot_base64.as_ref())
        .map(|base64| format!("data:image/png;base64,{base64}"))
        .unwrap_or_default();
    let screenshot_visible_style = if step_screenshot_src.is_empty() {
        "width: 100%; aspect-ratio: 5/4; object-fit: cover; border-radius: 0.4rem; background: #000; display: none;"
    } else {
        "width: 100%; aspect-ratio: 5/4; object-fit: cover; border-radius: 0.4rem; background: #000; display: block;"
    };
    let screenshot_placeholder_style = if step_screenshot_src.is_empty() {
        "min-height: 420px; display: flex; align-items: center; justify-content: center; background: #000; border-radius: 0.4rem;"
    } else {
        "min-height: 420px; display: none; align-items: center; justify-content: center; background: #000; border-radius: 0.4rem;"
    };
    let step_error_style = if step_has_error {
        String::new()
    } else {
        "display: none;".to_string()
    };
    let prev_href = if total_steps == 0 || selected_step == 0 {
        None
    } else {
        Some(format!("/jobs/{}?step={}", job.id, selected_step))
    };
    let next_href = if total_steps == 0 || selected_step + 1 >= total_steps {
        None
    } else {
        Some(format!("/jobs/{}?step={}", job.id, selected_step + 2))
    };

    let action_form = if is_active_status(job.status) {
        view! {
            <form method="post" action=format!("/jobs/{}/cancel", job.id) style="display: inline-block;">
                <button type="submit" class="secondary">"Cancel Job"</button>
            </form>
        }
        .into_view()
    } else {
        view! {
            <form method="post" action=format!("/jobs/{}/requeue", job.id) style="display: inline-block;">
                <button type="submit" class="secondary">"Re-queue Job"</button>
            </form>
        }
        .into_view()
    };

    let step_claude_items: Vec<View> = if let Some(step) = selected_step_detail {
        if step.claude_messages.is_empty() {
            vec![
                view! { <p style="color: var(--text-dim);">"No Claude notes for this step."</p> }
                    .into_view(),
            ]
        } else {
            step.claude_messages
                .iter()
                .map(|message| {
                    view! {
                        <div class="message">
                            <div class="role">"Claude"</div>
                            <div class="content">{message.clone()}</div>
                        </div>
                    }
                    .into_view()
                })
                .collect()
        }
    } else {
        vec![
            view! { <p style="color: var(--text-dim);">"No Claude notes for this step."</p> }
                .into_view(),
        ]
    };

    let step_note_items: Vec<View> = if let Some(step) = selected_step_detail {
        if step.notes.is_empty() {
            vec![view! { <li style="color: var(--text-dim);">"No notes attached to this step."</li> }.into_view()]
        } else {
            step.notes
                .iter()
                .map(|note| view! { <li>{note.clone()}</li> }.into_view())
                .collect()
        }
    } else {
        vec![
            view! { <li style="color: var(--text-dim);">"No notes attached to this step."</li> }
                .into_view(),
        ]
    };

    let logs_to_show = logs.iter().rev().take(80).collect::<Vec<_>>();
    let log_rows: Vec<View> = if logs_to_show.is_empty() {
        vec![view! {
            <tr>
                <td colspan="4" style="color: var(--text-dim); text-align: center; padding: 1rem;">
                    "No logs yet"
                </td>
            </tr>
        }
        .into_view()]
    } else {
        logs_to_show
            .into_iter()
            .map(|log| {
                view! {
                    <tr>
                        <td style="font-size: 0.8rem;">{log.timestamp.to_rfc3339()}</td>
                        <td><span class="tag">{log.level.clone()}</span></td>
                        <td style="font-size: 0.85rem;">{log.source.clone()}</td>
                        <td style="font-size: 0.85rem; white-space: pre-wrap;">{truncate_text(&log.message, 240)}</td>
                    </tr>
                }
                .into_view()
            })
            .collect()
    };

    let found_url_items = render_string_list(&job.found_urls, "No URLs found yet.");
    let downloaded_file_items =
        render_string_list(&job.downloaded_files, "No downloaded files yet.");
    let final_path_items = render_string_list(&job.final_paths, "No final paths yet.");

    view! {
        <>
            <section
                id="job-detail-root"
                class="job-detail-root"
                data-job-id=job.id.clone()
            >
                <h1>{format!("Job {}", job.id)}</h1>
                <div class="card job-toolbar">
                    <div class="job-toolbar-actions">
                        <a href="/jobs" class="btn secondary">"Back"</a>
                        {action_form}
                        <a href=format!("/api/v1/jobs/{}?api_key={}", job.id, api_key) class="btn secondary">"Raw JSON"</a>
                    </div>
                    <div class="job-toolbar-state">
                        <span
                            id="job-status-tag"
                            class=format!("tag {}", status_class).trim().to_string()
                        >
                            {status_text.clone()}
                        </span>
                        <span id="job-progress-text">{progress_text}</span>
                        <span id="job-phase-text">{phase_text}</span>
                    </div>
                </div>

                <div class="job-detail-layout">
                    <div class="card job-step-card">
                        <div class="job-step-header">
                            {prev_href
                                .map(|href| {
                                    view! { <a id="job-step-prev" href=href class="btn secondary job-step-nav">"<"</a> }
                                        .into_view()
                                })
                                .unwrap_or_else(|| {
                                    view! {
                                        <span id="job-step-prev" class="btn secondary job-step-nav" style="opacity: 0.5; pointer-events: none;">
                                            "<"
                                        </span>
                                    }
                                        .into_view()
                                })}
                            <div class="job-step-headtext">
                                <h2 id="job-step-title">{step_title}</h2>
                                <div id="job-step-counter" class="job-step-counter">{step_counter}</div>
                                <div id="job-step-meta" class="job-step-meta">{step_meta}</div>
                            </div>
                            {next_href
                                .map(|href| {
                                    view! { <a id="job-step-next" href=href class="btn secondary job-step-nav">">"</a> }
                                        .into_view()
                                })
                                .unwrap_or_else(|| {
                                    view! {
                                        <span id="job-step-next" class="btn secondary job-step-nav" style="opacity: 0.5; pointer-events: none;">
                                            ">"
                                        </span>
                                    }
                                        .into_view()
                                })}
                        </div>

                        <div id="job-step-observation" class="job-step-observation">{step_observation}</div>
                        <div style="margin-bottom: 0.5rem;">
                            <span id="job-step-error-tag" class="tag error" style=step_error_style>"Error"</span>
                        </div>

                        <div class="job-step-image-wrap">
                            <img
                                id="job-step-image"
                                src=step_screenshot_src
                                alt="Step screenshot"
                                style=screenshot_visible_style
                            />
                            <div id="job-step-image-placeholder" class="placeholder" style=screenshot_placeholder_style>
                                "No screenshot for this step"
                            </div>
                        </div>

                        <h3 class="job-subtitle">"Claude"</h3>
                        <div id="job-step-claude" class="messages job-step-messages">{step_claude_items}</div>
                        <h3 class="job-subtitle">"Step Notes"</h3>
                        <ul id="job-step-notes" class="job-step-notes">{step_note_items}</ul>
                    </div>

                    <div class="job-detail-side">
                        <div class="card job-summary-card">
                            <h2>"Summary"</h2>
                            <table class="job-compact-table">
                                <tr><td style="color: var(--text-dim);">"Created"</td><td id="job-created-text">{job.created_at.to_rfc3339()}</td></tr>
                                <tr><td style="color: var(--text-dim);">"Updated"</td><td id="job-updated-text">{job.updated_at.to_rfc3339()}</td></tr>
                                <tr><td style="color: var(--text-dim);">"Source"</td><td id="job-source-url-text">{source_url}</td></tr>
                                <tr><td style="color: var(--text-dim);">"Destination"</td><td id="job-destination-text">{job.destination_path.clone()}</td></tr>
                                <tr><td style="color: var(--text-dim);">"Operation"</td><td id="job-operation-text">{job.file_operation.clone()}</td></tr>
                                <tr><td style="color: var(--text-dim);">"Priority"</td><td id="job-priority-text">{job.priority.to_string()}</td></tr>
                            </table>
                            <h3 class="job-subtitle">"Prompt"</h3>
                            <pre id="job-prompt-text" class="job-prompt">{job.prompt.clone()}</pre>
                            <div
                                id="job-error-box"
                                class="alert error"
                                style=if job.error_message.trim().is_empty() {
                                    "display: none; margin-top: 0.75rem;"
                                } else {
                                    "margin-top: 0.75rem;"
                                }
                            >
                                <span id="job-error-text">{job.error_message.clone()}</span>
                            </div>
                        </div>

                        <details class="card" id="job-metadata-details">
                            <summary>"Metadata + Filter"</summary>
                            <pre id="job-metadata-text" style="max-height: 250px; overflow: auto; font-size: 0.8rem; margin-top: 0.75rem;">{metadata}</pre>
                            <h3 class="job-subtitle">"File Filter"</h3>
                            <pre id="job-file-filter-text" style="max-height: 120px; overflow: auto; font-size: 0.8rem;">{
                                if job.file_filter.is_empty() {
                                    "(none)".to_string()
                                } else {
                                    job.file_filter.join("\n")
                                }
                            }</pre>
                        </details>
                    </div>
                </div>

                <details class="card" id="job-artifacts-details">
                    <summary>"Artifacts"</summary>
                    <div class="grid-2" style="margin-top: 0.75rem;">
                        <div>
                            <h3 class="job-subtitle">"Found URLs"</h3>
                            <ul id="job-found-urls" class="job-list">{found_url_items}</ul>
                        </div>
                        <div>
                            <h3 class="job-subtitle">"Downloaded Files"</h3>
                            <ul id="job-downloaded-files" class="job-list">{downloaded_file_items}</ul>
                        </div>
                    </div>
                    <h3 class="job-subtitle">"Final Paths"</h3>
                    <ul id="job-final-paths" class="job-list">{final_path_items}</ul>
                </details>

                <details class="card" id="job-logs-details">
                    <summary>"Recent Logs"</summary>
                    <table style="margin-top: 0.75rem;">
                        <thead>
                            <tr>
                                <th>"Timestamp"</th>
                                <th>"Level"</th>
                                <th>"Source"</th>
                                <th>"Message"</th>
                            </tr>
                        </thead>
                        <tbody id="job-logs-body">{log_rows}</tbody>
                    </table>
                </details>
            </section>
        </>
    }
    .into_view()
}

fn render_string_list(values: &[String], empty_message: &str) -> Vec<View> {
    if values.is_empty() {
        return vec![
            view! { <li style="color: var(--text-dim);">{empty_message.to_string()}</li> }
                .into_view(),
        ];
    }

    values
        .iter()
        .map(|value| {
            view! { <li><code style="word-break: break-word;">{value.clone()}</code></li> }
                .into_view()
        })
        .collect()
}

fn truncate_text(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }

    format!("{}...", text.chars().take(max_chars).collect::<String>())
}

fn render_app_page(
    request: &RequestContext,
    git: &GitInfo,
    runtime: &RuntimeBadge,
    title: &str,
    content: impl IntoView,
) -> String {
    render_app_page_with_refresh(request, git, runtime, title, None, content)
}

fn render_app_page_with_refresh(
    request: &RequestContext,
    git: &GitInfo,
    runtime: &RuntimeBadge,
    title: &str,
    refresh_seconds: Option<u32>,
    content: impl IntoView,
) -> String {
    let body = view! {
        <>
            {render_nav(request, git, runtime)}
            <main>{content}</main>
        </>
    };

    render_document(title, BASE_CSS, refresh_seconds, body)
}

fn render_document(
    title: &str,
    css: &str,
    refresh_seconds: Option<u32>,
    body: impl IntoView,
) -> String {
    let runtime = create_runtime();
    let refresh_meta = refresh_seconds
        .filter(|seconds| *seconds > 0)
        .map(|seconds| {
            view! {
                <meta http-equiv="refresh" content=seconds.to_string() />
            }
            .into_view()
        });

    let rendered = view! {
        <html lang="en">
            <head>
                <meta charset="UTF-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1.0" />
                {refresh_meta}
                <title>{title.to_string()}</title>
                <style inner_html=css.to_string()></style>
            </head>
            <body>
                {body}
                <script type="module" src="/assets/graboid_frontend.js"></script>
            </body>
        </html>
    }
    .into_view()
    .render_to_string();

    runtime.dispose();
    format!("<!DOCTYPE html>\n{rendered}")
}

fn render_nav(request: &RequestContext, git: &GitInfo, runtime: &RuntimeBadge) -> View {
    let version = render_version(git);
    let status_text = runtime.status_text();

    view! {
        <nav>
            <span class="logo">"Graboid"</span>
            <span class="backend-status connected" id="backend-status" title="Backend connected"></span>
            {version}
            {nav_link("/", "Dashboard", &request.path)}
            {nav_link("/jobs", "Jobs", &request.path)}
            {nav_link("/browser", "Browser", &request.path)}
            {nav_link("/notes", "Notes", &request.path)}
            {nav_link("/config", "Config", &request.path)}
            <div class="status-indicator">
                <div class="status-dot" class:running=runtime.is_running id="status-dot"></div>
                <span id="status-text">{status_text}</span>
            </div>
            <a href="/logout" class="logout">"Logout"</a>
        </nav>
    }
    .into_view()
}

fn nav_link(path: &str, label: &str, active_path: &str) -> View {
    let href = path.to_string();
    let text = label.to_string();
    let is_active = active_path == path;
    view! { <a href=href class:active=is_active>{text}</a> }.into_view()
}

fn render_version(git: &GitInfo) -> Option<View> {
    if git.backend.hash.trim().is_empty() && git.frontend.hash.trim().is_empty() {
        return None;
    }

    let title = format!(
        "Backend build {} {} | Frontend assets {} {}",
        git.backend.timestamp, git.backend.tz, git.frontend.timestamp, git.frontend.tz
    );
    let backend_age = format_relative_age(git.backend.epoch);
    let frontend_age = format_relative_age(git.frontend.epoch);

    Some(
        view! {
            <span
                class="version"
                id="build-version"
                data-backend-hash=git.backend.hash.clone()
                data-backend-epoch=git.backend.epoch.to_string()
                data-frontend-hash=git.frontend.hash.clone()
                data-frontend-epoch=git.frontend.epoch.to_string()
                title=title
            >
                <span class="version-line">
                    <span id="build-version-be">
                        {format!(
                            "BE {} {} {} ({})",
                            git.backend.hash, git.backend.timestamp, git.backend.tz, backend_age
                        )}
                    </span>
                </span>
                <br />
                <span class="version-line">
                    <span id="build-version-fe">
                        {format!(
                            "FE {} {} {} ({})",
                            git.frontend.hash, git.frontend.timestamp, git.frontend.tz, frontend_age
                        )}
                    </span>
                </span>
            </span>
        }
        .into_view(),
    )
}

fn format_relative_age(epoch: i64) -> String {
    if epoch <= 0 {
        return "-".to_string();
    }

    let now = Utc::now().timestamp();
    let diff = now - epoch;
    let future = diff < 0;
    let delta = diff.abs();

    if delta < 5 {
        return "just now".to_string();
    }

    let units = [
        (86_400_i64, "d"),
        (3_600_i64, "h"),
        (60_i64, "m"),
        (1_i64, "s"),
    ];

    for (seconds, suffix) in units {
        if delta >= seconds {
            let value = delta / seconds;
            return if future {
                format!("in {value}{suffix}")
            } else {
                format!("{value}{suffix} ago")
            };
        }
    }

    "-".to_string()
}

fn job_status_class(status: JobStatus) -> &'static str {
    match status {
        JobStatus::Complete => "success",
        JobStatus::Failed | JobStatus::Cancelled => "error",
        JobStatus::Running
        | JobStatus::Browsing
        | JobStatus::Downloading
        | JobStatus::Extracting
        | JobStatus::Copying => "warning",
        JobStatus::Pending => "",
    }
}

fn is_active_status(status: JobStatus) -> bool {
    matches!(
        status,
        JobStatus::Pending
            | JobStatus::Running
            | JobStatus::Browsing
            | JobStatus::Downloading
            | JobStatus::Extracting
            | JobStatus::Copying
    )
}

fn format_jobs_message(raw: &str) -> (&'static str, String) {
    match raw {
        "submitted" => ("success", "Job submitted.".to_string()),
        "requeued" => ("success", "Job re-queued.".to_string()),
        "cancelled" => ("success", "Job cancelled.".to_string()),
        "error:prompt-required" => ("error", "Prompt is required.".to_string()),
        "error:not-found" => ("error", "Job not found.".to_string()),
        value if value.starts_with("error:") => (
            "error",
            value
                .trim_start_matches("error:")
                .replace('-', " ")
                .trim()
                .to_string(),
        ),
        other => ("success", other.replace('-', " ")),
    }
}

fn render_jobs_content(
    request: &RequestContext,
    api_key: &str,
    jobs: &[Job],
    total: i64,
    offset: i64,
    limit: i64,
    message: Option<&str>,
) -> View {
    let endpoint_url = format!("{}://{}", request.scheme, request.netloc);
    let example_request = format!(
        "curl -X POST {endpoint_url}/api/v1/jobs \\\n  -H \"X-API-Key: YOUR_KEY\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{{\n    \"prompt\": \"Download latest release\",\n    \"source_url\": \"https://example.com\"\n  }}'"
    );

    let safe_limit = limit.max(1);
    let current_page = (offset / safe_limit) + 1;
    let total_pages = if total <= 0 {
        1
    } else {
        ((total + safe_limit - 1) / safe_limit).max(1)
    };
    let prev_offset = if offset >= safe_limit {
        Some(offset - safe_limit)
    } else {
        None
    };
    let next_offset = if offset + safe_limit < total {
        Some(offset + safe_limit)
    } else {
        None
    };

    let job_rows: Vec<View> = if jobs.is_empty() {
        vec![view! {
            <tr>
                <td colspan="6" style="text-align: center; color: var(--text-dim); padding: 2rem;">
                    "No jobs in queue"
                </td>
            </tr>
        }
        .into_view()]
    } else {
        jobs.iter().map(render_job_row).collect()
    };

    let message_view = message.and_then(|raw| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            let (kind, text) = format_jobs_message(trimmed);
            Some(view! { <div class=format!("alert {kind}")>{text}</div> }.into_view())
        }
    });

    view! {
        <>
            <h1>"Job Queue"</h1>
            {message_view}
            <div class="grid-2">
                <div class="card">
                    <h2>"Submit New Job"</h2>
                    <form method="post" action="/jobs/submit">
                        <label for="prompt">"Task Description"</label>
                        <textarea
                            id="prompt"
                            name="prompt"
                            rows="3"
                            placeholder="Find and download the latest release of..."
                            required
                        ></textarea>

                        <label for="source_url">"Starting URL (optional)"</label>
                        <input type="url" id="source_url" name="source_url" placeholder="https://example.com" />

                        <label for="destination_path">"Destination Path"</label>
                        <input
                            type="text"
                            id="destination_path"
                            name="destination_path"
                            value="./downloads"
                            placeholder="./downloads"
                        />

                        <div class="grid-2">
                            <div>
                                <label for="file_operation">"File Operation"</label>
                                <select id="file_operation" name="file_operation">
                                    <option value="copy" selected>"Copy"</option>
                                    <option value="hardlink">"Hard Link"</option>
                                    <option value="symlink">"Symbolic Link"</option>
                                    <option value="reflink">"Reflink (CoW)"</option>
                                    <option value="path_only">"Path Only"</option>
                                </select>
                            </div>
                            <div>
                                <label for="priority">"Priority"</label>
                                <input type="number" id="priority" name="priority" value="0" min="-10" max="10" />
                            </div>
                        </div>

                        <label for="file_filter">"File Filter (glob patterns, one per line)"</label>
                        <textarea id="file_filter" name="file_filter" rows="2" placeholder="*.mkv&#10;*.mp4"></textarea>

                        <button type="submit">"Submit Job"</button>
                    </form>
                </div>

                <div class="card">
                    <h2>"API Access"</h2>
                    <p style="color: var(--text-dim); margin-bottom: 1rem;">"Use the API to submit jobs programmatically."</p>
                    <label>"API Key"</label>
                    <code style="display: block; margin-bottom: 1rem; word-break: break-all;">{api_key.to_string()}</code>
                    <label>"Example Request"</label>
                    <pre
                        style="background: var(--bg); padding: 1rem; border-radius: 0.25rem; overflow-x: auto; font-size: 0.8rem;"
                    >
                        {example_request}
                    </pre>
                </div>
            </div>

            <div class="card">
                <h2>"Job Queue"</h2>
                <div
                    style="margin-bottom: 1rem; display: flex; justify-content: flex-end; align-items: center; gap: 0.5rem; flex-wrap: wrap;"
                >
                    {prev_offset
                        .map(|prev| {
                            view! {
                                <a href=format!("/jobs?offset={prev}&limit={safe_limit}") class="btn secondary" style="padding: 0.35rem 0.65rem;">
                                    "Prev"
                                </a>
                            }
                                .into_view()
                        })
                        .unwrap_or_else(|| {
                            view! {
                                <span class="btn secondary" style="padding: 0.35rem 0.65rem; opacity: 0.5; pointer-events: none;">
                                    "Prev"
                                </span>
                            }
                                .into_view()
                        })}
                    <span
                        style="color: var(--text-dim); font-size: 0.85rem; min-width: 9rem; text-align: center;"
                    >
                        {format!("Page {current_page}/{total_pages} ({total} jobs)")}
                    </span>
                    {next_offset
                        .map(|next| {
                            view! {
                                <a href=format!("/jobs?offset={next}&limit={safe_limit}") class="btn secondary" style="padding: 0.35rem 0.65rem;">
                                    "Next"
                                </a>
                            }
                                .into_view()
                        })
                        .unwrap_or_else(|| {
                            view! {
                                <span class="btn secondary" style="padding: 0.35rem 0.65rem; opacity: 0.5; pointer-events: none;">
                                    "Next"
                                </span>
                            }
                                .into_view()
                        })}
                </div>

                <table>
                    <thead>
                        <tr>
                            <th>"ID"</th>
                            <th>"Status"</th>
                            <th>"Progress"</th>
                            <th>"Task"</th>
                            <th>"Created"</th>
                            <th>"Actions"</th>
                        </tr>
                    </thead>
                    <tbody>{job_rows}</tbody>
                </table>
            </div>
        </>
    }
    .into_view()
}

fn render_job_row(job: &Job) -> View {
    let job_id = job.id.clone();
    let short_id: String = job_id.chars().take(8).collect();
    let status_text = job.status.as_str().to_string();
    let status_class = job_status_class(job.status).to_string();
    let progress_message = if job.progress_message.trim().is_empty() {
        format!("{}%", job.progress_percent.round())
    } else {
        format!("{}% {}", job.progress_percent.round(), job.progress_message)
    };
    let task_preview = if job.prompt.chars().count() > 80 {
        format!("{}...", job.prompt.chars().take(80).collect::<String>())
    } else {
        job.prompt.clone()
    };
    let created = job.created_at.to_rfc3339();

    let action_form = if is_active_status(job.status) {
        view! {
            <form method="post" action=format!("/jobs/{job_id}/cancel") style="display: inline-block; margin-right: 0.5rem;">
                <button type="submit" class="secondary" style="padding: 0.3rem 0.6rem; font-size: 0.75rem;">
                    "Cancel"
                </button>
            </form>
        }
        .into_view()
    } else {
        view! {
            <form method="post" action=format!("/jobs/{job_id}/requeue") style="display: inline-block; margin-right: 0.5rem;">
                <button type="submit" class="secondary" style="padding: 0.3rem 0.6rem; font-size: 0.75rem;">
                    "Re-queue"
                </button>
            </form>
        }
        .into_view()
    };

    view! {
        <tr>
            <td><code title=job.id.clone()>{short_id}</code></td>
            <td>
                <span class=format!("tag {}", status_class).trim().to_string()>{status_text}</span>
            </td>
            <td>{progress_message}</td>
            <td style="max-width: 420px; overflow: hidden; text-overflow: ellipsis;">{task_preview}</td>
            <td style="font-size: 0.8rem; color: var(--text-dim);">{created}</td>
            <td>
                {action_form}
                <a href=format!("/jobs/{}", job.id) class="btn secondary" style="padding: 0.3rem 0.6rem; font-size: 0.75rem;">
                    "Details"
                </a>
            </td>
        </tr>
    }
    .into_view()
}

fn render_config_content(
    config: &serde_json::Map<String, Value>,
    config_path: &str,
    saved: bool,
) -> View {
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

    view! {
        <>
            <h1>"Configuration"</h1>
            {saved.then(|| view! { <div class="alert success">"Configuration saved successfully."</div> })}

            <form method="post" action="/config">
                <div class="grid-2">
                    <div class="card">
                        <h2>"Torrent Client"</h2>
                        <label for="torrent_client">"Client"</label>
                        <select name="torrent_client" id="torrent_client">
                            <option value="auto" selected=torrent_client=="auto">"Auto (fallback chain)"</option>
                            <option value="embedded" selected=torrent_client=="embedded">"Embedded (librqbit feature)"</option>
                            <option value="qbittorrent" selected=torrent_client=="qbittorrent">"qBittorrent"</option>
                            <option value="transmission" selected=torrent_client=="transmission">"Transmission"</option>
                            <option value="deluge" selected=torrent_client=="deluge">"Deluge"</option>
                            <option value="rtorrent" selected=torrent_client=="rtorrent">"rTorrent"</option>
                            <option value="aria2" selected=torrent_client=="aria2">"aria2"</option>
                        </select>

                        <h3 style="margin: 1.5rem 0 1rem; font-size: 1rem;">"qBittorrent Settings"</h3>
                        <label for="qbittorrent_host">"Host"</label>
                        <input type="text" name="qbittorrent_host" id="qbittorrent_host" value=qb_host />
                        <label for="qbittorrent_port">"Port"</label>
                        <input type="number" name="qbittorrent_port" id="qbittorrent_port" value=qb_port.to_string() />
                        <label for="qbittorrent_username">"Username"</label>
                        <input type="text" name="qbittorrent_username" id="qbittorrent_username" value=qb_username />
                        <label for="qbittorrent_password">"Password"</label>
                        <input type="password" name="qbittorrent_password" id="qbittorrent_password" value=qb_password />

                        <h3 style="margin: 1.5rem 0 1rem; font-size: 1rem;">"Transmission Settings"</h3>
                        <label for="transmission_host">"Host"</label>
                        <input type="text" name="transmission_host" id="transmission_host" value=transmission_host />
                        <label for="transmission_port">"Port"</label>
                        <input type="number" name="transmission_port" id="transmission_port" value=transmission_port.to_string() />
                        <label for="transmission_username">"Username"</label>
                        <input type="text" name="transmission_username" id="transmission_username" value=transmission_username />
                        <label for="transmission_password">"Password"</label>
                        <input type="password" name="transmission_password" id="transmission_password" value=transmission_password />

                        <h3 style="margin: 1.5rem 0 1rem; font-size: 1rem;">"Deluge Settings"</h3>
                        <label for="deluge_host">"Host"</label>
                        <input type="text" name="deluge_host" id="deluge_host" value=deluge_host />
                        <label for="deluge_port">"Port"</label>
                        <input type="number" name="deluge_port" id="deluge_port" value=deluge_port.to_string() />
                        <label for="deluge_username">"Username"</label>
                        <input type="text" name="deluge_username" id="deluge_username" value=deluge_username />
                        <label for="deluge_password">"Password"</label>
                        <input type="password" name="deluge_password" id="deluge_password" value=deluge_password />

                        <h3 style="margin: 1.5rem 0 1rem; font-size: 1rem;">"rTorrent Settings"</h3>
                        <label for="rtorrent_url">"XML-RPC URL"</label>
                        <input
                            type="text"
                            name="rtorrent_url"
                            id="rtorrent_url"
                            value=rtorrent_url
                            placeholder="http://localhost:8000/RPC2"
                        />

                        <h3 style="margin: 1.5rem 0 1rem; font-size: 1rem;">"aria2 Settings"</h3>
                        <label for="aria2_host">"Host"</label>
                        <input type="text" name="aria2_host" id="aria2_host" value=aria2_host />
                        <label for="aria2_port">"Port"</label>
                        <input type="number" name="aria2_port" id="aria2_port" value=aria2_port.to_string() />
                        <label for="aria2_secret">"Secret Token"</label>
                        <input type="password" name="aria2_secret" id="aria2_secret" value=aria2_secret />
                    </div>

                    <div class="card">
                        <h2>"LLM Provider"</h2>
                        <label for="llm_provider">"Provider"</label>
                        <select name="llm_provider" id="llm_provider">
                            <option value="claude_code" selected=llm_provider=="claude_code">"Claude Code (Max subscription)"</option>
                            <option value="anthropic" selected=llm_provider=="anthropic">"Anthropic API"</option>
                            <option value="openai" selected=llm_provider=="openai">"OpenAI"</option>
                            <option value="ollama" selected=llm_provider=="ollama">"Ollama (local)"</option>
                            <option value="google" selected=llm_provider=="google">"Google Gemini"</option>
                            <option value="openrouter" selected=llm_provider=="openrouter">"OpenRouter"</option>
                        </select>

                        <label for="llm_model">"Model"</label>
                        <input
                            type="text"
                            name="llm_model"
                            id="llm_model"
                            value=llm_model
                            placeholder="sonnet, opus, gpt-4o, llama3.2, etc."
                        />

                        <h2 style="margin-top: 1.5rem;">"Browser"</h2>
                        <label for="browser_mode">"Browser Mode"</label>
                        <select name="browser_mode" id="browser_mode">
                            <option value="chrome" selected=browser_mode=="chrome">"Claude Chrome Integration"</option>
                            <option value="browser_use" selected=browser_mode=="browser_use">"browser-use (Playwright)"</option>
                        </select>

                        <label for="browser_use_mcp_command">"browser-use MCP Command"</label>
                        <input
                            type="text"
                            name="browser_use_mcp_command"
                            id="browser_use_mcp_command"
                            value=browser_use_mcp_command
                            placeholder="uvx"
                        />

                        <label for="browser_use_mcp_args">"browser-use MCP Args"</label>
                        <input
                            type="text"
                            name="browser_use_mcp_args"
                            id="browser_use_mcp_args"
                            value=browser_use_mcp_args
                            placeholder="browser-use[mcp]"
                        />

                        <div style="font-size: 0.75rem; color: var(--text-dim); margin-top: 0.25rem;">
                            "Used only when Browser Mode is set to browser-use."
                        </div>

                        <label
                            style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer; margin-top: 0.5rem;"
                        >
                            <input
                                type="checkbox"
                                name="headless"
                                id="headless"
                                style="width: auto;"
                                checked=headless
                            />
                            <span>"Headless mode (use Xvfb for Chrome)"</span>
                        </label>

                        <h2 style="margin-top: 1.5rem;">"Paths"</h2>
                        <label for="download_dir">"Download Directory"</label>
                        <input type="text" name="download_dir" id="download_dir" value=download_dir />

                        <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer;">
                            <input
                                type="checkbox"
                                name="download_allow_insecure"
                                id="download_allow_insecure"
                                style="width: auto;"
                                checked=download_allow_insecure
                            />
                            <span>"Allow insecure downloads (skip TLS verification)"</span>
                        </label>

                        <div class="grid-2">
                            <div>
                                <label for="download_retry_attempts">"Download Retry Attempts"</label>
                                <input
                                    type="number"
                                    name="download_retry_attempts"
                                    id="download_retry_attempts"
                                    value=download_retry_attempts.to_string()
                                    min="1"
                                    max="10"
                                />
                            </div>
                            <div>
                                <label for="download_retry_backoff_sec">"Retry Backoff (seconds)"</label>
                                <input
                                    type="number"
                                    name="download_retry_backoff_sec"
                                    id="download_retry_backoff_sec"
                                    value=download_retry_backoff_sec.to_string()
                                    step="0.5"
                                    min="0"
                                />
                            </div>
                        </div>

                        <label for="download_max_parallel">"Max Parallel Downloads"</label>
                        <input
                            type="number"
                            name="download_max_parallel"
                            id="download_max_parallel"
                            value=download_max_parallel.to_string()
                            min="1"
                            max="32"
                        />

                        <label for="path_mappings">"Path Mappings (one per line, host:container)"</label>
                        <textarea
                            name="path_mappings"
                            id="path_mappings"
                            rows="4"
                            placeholder="/mnt/downloads:/downloads"
                        >
                            {path_mappings}
                        </textarea>

                        <h2 style="margin-top: 1.5rem;">"Logging"</h2>
                        <label for="log_level">"Log Level"</label>
                        <select name="log_level" id="log_level">
                            <option value="DEBUG" selected=log_level=="DEBUG">"Debug"</option>
                            <option value="INFO" selected=log_level=="INFO">"Info"</option>
                            <option value="WARNING" selected=log_level=="WARNING">"Warning"</option>
                            <option value="ERROR" selected=log_level=="ERROR">"Error"</option>
                        </select>
                    </div>
                </div>

                <div class="card">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <span style="color: var(--text-dim);">"Config file: "</span>
                            <code>{config_path.to_string()}</code>
                        </div>
                        <button type="submit">"Save Configuration"</button>
                    </div>
                </div>
            </form>
        </>
    }
    .into_view()
}

fn render_notes_content(
    stats: &NoteStats,
    domains: &[String],
    domain_notes: &BTreeMap<String, Vec<NoteEntry>>,
) -> View {
    let by_type_rows: Vec<View> = if stats.by_type.is_empty() {
        vec![view! { <p style="color: var(--text-dim);">"No notes recorded yet."</p> }.into_view()]
    } else {
        let mut rows: Vec<View> = Vec::new();
        for (note_type, count) in &stats.by_type {
            rows.push(
                view! {
                    <tr>
                        <td style="color: var(--text-dim);">{note_type.replace('_', " ")}</td>
                        <td>{count.to_string()}</td>
                    </tr>
                }
                .into_view(),
            );
        }
        vec![view! { <table>{rows}</table> }.into_view()]
    };

    let domains_view: View = if domains.is_empty() {
        view! {
            <div class="card">
                <h2>"No Notes Yet"</h2>
                <p style="color: var(--text-dim);">
                    "Agent notes will appear here as the browser agent learns about different sites. Run a download to start building the knowledge base."
                </p>
            </div>
        }
        .into_view()
    } else {
        let mut sections: Vec<View> = Vec::new();
        for domain in domains {
            let notes = domain_notes.get(domain).cloned().unwrap_or_default();
            let rows: Vec<View> = notes
                .iter()
                .map(|note| {
                    let success_tag = match note.success {
                        Some(true) => view! { <span class="tag success">"Yes"</span> }.into_view(),
                        Some(false) => view! { <span class="tag error">"No"</span> }.into_view(),
                        None => {
                            view! { <span style="color: var(--text-dim);">"-"</span> }.into_view()
                        }
                    };

                    view! {
                        <tr>
                            <td><span class="tag">{note.note_type.replace('_', " ")}</span></td>
                            <td>{note.label.clone().unwrap_or_else(|| "-".to_string())}</td>
                            <td style="max-width: 400px; overflow: hidden; text-overflow: ellipsis;">{note.content.clone()}</td>
                            <td>{success_tag}</td>
                            <td>{note.use_count.to_string()}</td>
                        </tr>
                    }
                    .into_view()
                })
                .collect();

            sections.push(
                view! {
                    <details style="margin-bottom: 1rem;">
                        <summary style="cursor: pointer; padding: 0.75rem; background: var(--bg); border-radius: 0.25rem; margin-bottom: 0.5rem;">
                            <strong style="color: var(--accent);">{domain.clone()}</strong>
                            <span style="color: var(--text-dim); margin-left: 0.5rem;">
                                {format!("({} notes)", notes.len())}
                            </span>
                        </summary>
                        <table style="margin-left: 1rem;">
                            <thead>
                                <tr>
                                    <th>"Type"</th>
                                    <th>"Label"</th>
                                    <th>"Content"</th>
                                    <th>"Success"</th>
                                    <th>"Uses"</th>
                                </tr>
                            </thead>
                            <tbody>{rows}</tbody>
                        </table>
                    </details>
                }
                .into_view(),
            );
        }

        view! {
            <div class="card">
                <h2>"Notes by Domain"</h2>
                {sections}
            </div>
        }
        .into_view()
    };

    view! {
        <>
            <h1>"Agent Notes"</h1>
            <div class="grid">
                <div class="card">
                    <h2>"Statistics"</h2>
                    <table>
                        <tr>
                            <td style="color: var(--text-dim);">"Total Notes"</td>
                            <td>{stats.total_notes.to_string()}</td>
                        </tr>
                        <tr>
                            <td style="color: var(--text-dim);">"Domains"</td>
                            <td>{stats.domains.to_string()}</td>
                        </tr>
                        <tr>
                            <td style="color: var(--text-dim);">"Successful Sources"</td>
                            <td>{stats.successful.to_string()}</td>
                        </tr>
                    </table>
                </div>
                <div class="card">
                    <h2>"Notes by Type"</h2>
                    {by_type_rows}
                </div>
            </div>
            {domains_view}
        </>
    }
    .into_view()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::CreateJobRequest;
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

    fn runtime() -> RuntimeBadge {
        RuntimeBadge {
            is_running: false,
            current_task: String::new(),
        }
    }

    #[test]
    fn renders_index_without_template_markers() {
        let html = render_index_page(&request("/"), &git(), &runtime());
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
        let html = render_config_page(&req, &git(), &runtime(), &config, "/tmp/config.toml");
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

        let html = render_config_page(&req, &git(), &runtime(), &config, "/tmp/config.toml");
        assert!(html.contains("value=\"deluge\""));
        assert!(html.contains("&#x2F;a:&#x2F;b") || html.contains("/a:/b"));
        assert!(!html.contains("id=\"headless\" checked"));
    }

    #[test]
    fn renders_jobs_without_template_markers() {
        let html = render_jobs_page(
            &request("/jobs"),
            &git(),
            &runtime(),
            "abc123",
            &[],
            0,
            0,
            50,
            None,
        );
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

    #[test]
    fn jobs_table_details_link_points_to_html_page() {
        let req = CreateJobRequest {
            prompt: "Download item".to_string(),
            source_url: String::new(),
            credential_name: None,
            file_filter: Vec::new(),
            destination_path: "./downloads".to_string(),
            file_operation: "copy".to_string(),
            priority: 0,
            metadata: Value::Object(Default::default()),
        };
        let job = Job::new(req, "./downloads");
        let html = render_jobs_page(
            &request("/jobs"),
            &git(),
            &runtime(),
            "abc123",
            &[job.clone()],
            1,
            0,
            50,
            None,
        );
        assert!(html.contains(&format!("/jobs/{}", job.id)));
    }

    #[test]
    fn renders_job_detail_page() {
        let req = CreateJobRequest {
            prompt: "Download item".to_string(),
            source_url: String::new(),
            credential_name: None,
            file_filter: Vec::new(),
            destination_path: "./downloads".to_string(),
            file_operation: "copy".to_string(),
            priority: 0,
            metadata: Value::Object(Default::default()),
        };
        let job = Job::new(req, "./downloads");
        let html = render_job_detail_page(
            &request("/jobs"),
            &git(),
            &runtime(),
            "abc123",
            &job,
            &[],
            &[],
        );
        assert!(!html.contains("{%"));
        assert!(!html.contains("{{"));
        assert!(html.contains("No navigation steps yet"));
        assert!(html.contains("Raw JSON"));
        assert!(html.contains("job-detail-root"));
    }
}
