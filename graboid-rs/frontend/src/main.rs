use leptos::*;
use wasm_bindgen::JsCast;
use web_sys::HtmlElement;

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

fn main() {
    console_error_panic_hook::set_once();

    if let Some(root) = document()
        .get_element_by_id("leptos-runtime-root")
        .and_then(|node| node.dyn_into::<HtmlElement>().ok())
    {
        mount_to(root, || view! { <App /> });
    } else {
        mount_to_body(|| view! { <App /> });
    }
}
