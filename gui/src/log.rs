use ansi_to_html::convert;
use async_process::ChildStdout;
use dioxus::prelude::*;
use futures_lite::AsyncReadExt;

pub async fn update_log(mut stdout: ChildStdout, mut log: Signal<String>) {
    let mut buf = [0u8; 1024];
    loop {
        match stdout.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                let raw = String::from_utf8_lossy(&buf[..n]);
                let html = convert(&raw);
                let update = html.as_deref().unwrap_or(&raw);

                log.write().push_str(update);
            }
            Err(e) => {
                log.write()
                    .push_str(&format!("\nError While Reading Proxy Logs {e:?}"));
            }
        }
    }
}

#[component]
pub fn LogsTab(log: Signal<String>) -> Element {
    rsx! {
        div { class: "flex flex-1",
            pre {
                class: "flex-1 overflow-y-auto max-h-[80vh] bg-white/3 rounded-xl p-4 m-4",
                dangerous_inner_html: log,
            }
        }
    }
}
