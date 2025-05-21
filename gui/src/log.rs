use ansi_to_html::convert;
use async_process::ChildStdout;
use dioxus::prelude::*;
use futures_lite::AsyncReadExt;

/// update_log reads from the stdout of a child process and updates the log
/// signal with the new log data.
/// It uses a buffer to read the data in chunks and converts it to HTML
/// using the `ansi_to_html` crate.
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

/// LogsTab is a component that displays the logs of the application.
/// It takes a `log` signal as a prop, which contains the log data.
/// The logs are displayed in a `pre` element with a scrollable area.
///
/// # Arguments
///
/// * `log`: A signal containing the log data as a string.
///
/// # Returns
/// An `Element` representing the logs tab.
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
