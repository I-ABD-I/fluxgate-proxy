use std::{net::ToSocketAddrs, path::PathBuf};

use dioxus::prelude::*;
use fluxgate::config::Upstream;
use rfd::FileDialog;

/// The SettingsTab component is responsible for rendering the settings tab
/// of the application. It displays a list of server settings and allows
/// users to add new servers or modify existing ones.
///
/// # Arguments
/// * `settings` - A signal containing a vector of server settings.
///
/// # Returns
/// An `Element` representing the settings tab.
#[component]
pub fn SettingsTab(settings: Signal<Vec<fluxgate::config::helper::Server>>) -> Element {
    rsx! {
        div { class: "flex flex-1 items-center p-4 flex-col",
            div { class: "overflow-y-auto flex flex-col w-3/4 items-center max-h-[70vh]",
                for i in 0..settings.len() {
                    ServerSettings { settings, index: i }
                }
            }
            button {
                class: "mt-auto bg-accent py-2 px-4 m-0 rounded-3xl",
                onclick: move |_| {
                    settings.push(fluxgate::config::helper::Server::default());
                },
                "Add Server"
            }
        }
    }
}

/// The ServerSettings component is responsible for rendering the settings
/// of a single server. It allows users to modify the server name, SSL
/// certificate path, SSL key path, load balancer type, and upstreams.
///
/// # Arguments
/// * `settings` - A signal containing a vector of server settings.
/// * `index` - The index of the server settings in the vector.
///
/// # Returns
/// An `Element` representing the server settings.
#[component]
fn ServerSettings(
    settings: Signal<Vec<fluxgate::config::helper::Server>>,
    index: usize,
) -> Element {
    let mut ssl_cert = use_signal(|| {
        if let Some(ssl) = &settings.read()[index].ssl {
            ssl.ssl_certificate.display().to_string()
        } else {
            "Choose File".to_string()
        }
    });
    let mut ssl_key = use_signal(|| {
        if let Some(ssl) = &settings.read()[index].ssl {
            ssl.ssl_certificate_key.display().to_string()
        } else {
            "Choose File".to_string()
        }
    });
    let mut load_balancer = use_signal(|| settings.read()[index].load_balancer.to_string());

    let mut current_upstream = use_signal(String::default);

    rsx! {
        div { class: "bg-white/3 rounded-xl p-4 m-2 w-7/8",
            div {
                label { "Server Name:  " }
                input {
                    class: "border-2 rounded-3xl px-2",
                    r#type: "text",
                    value: "{settings.read()[index].server_name}",
                    oninput: move |event| settings.write()[index].server_name = event.value(),
                }
            }
            div {
                label { "SSL Certificate Path: " }
                button {
                    class: "border-2 rounded-3xl px-2 truncate max-w-77",
                    style: "direction: rtl;",
                    onclick: move |_| {
                        let file = FileDialog::new().pick_file();
                        if let Some(file) = file {
                            ssl_cert.set(file.display().to_string());
                            try_update_ssl(&ssl_cert, &ssl_key, &mut settings.write()[index]);
                        }
                    },
                    {ssl_cert}
                }
            }
            div { class: "max-w-fit",
                label { "SSL Key Path: " }
                button {
                    class: "border-2 rounded-3xl px-2 truncate max-w-89",
                    style: "direction: rtl;",
                    onclick: move |_| {
                        let file = FileDialog::new().pick_file();
                        if let Some(file) = file {
                            ssl_key.set(file.display().to_string());
                            try_update_ssl(&ssl_cert, &ssl_key, &mut settings.write()[index]);
                        }
                    },
                    {ssl_key}
                }
            }
            div {
                label { "Load Balancer: " }
                select {
                    class: "appearance-none px-2 bg-accent rounded-md focus:outline-none focus:ring-2 focus:ring-blue-300",
                    value: "{load_balancer}",
                    onchange: move |event| {
                        load_balancer.set(event.value());
                        settings.write()[index].load_balancer = ron::from_str(&event.value()).unwrap();
                    },
                    option { value: "RoundRobin", "RoundRobin" }
                    option { value: "LeastConnections", "LeastConnections" }
                    option { value: "ResourceBased", "ResourceBased" }
                }
            }
            div {
                label { "Upstreams: " }
                ul { class: "list-disc px-8",
                    for (idx , upstream) in settings.read()[index].upstreams.iter().enumerate() {
                        li { key: {idx},
                            button {
                                onclick: move |_| {
                                    settings.write()[index].upstreams.remove(idx);
                                },
                                {upstream.addr.to_string()}
                            }
                        }
                    }
                    li {
                        form {
                            onsubmit: move |_| {
                                match ToSocketAddrs::to_socket_addrs(&*current_upstream.read()) {
                                    Ok(addrs) => {
                                        for addr in addrs {
                                            settings.write()[index].upstreams.push(Upstream { addr });
                                        }
                                    }
                                    Err(_) => {
                                        return;
                                    }
                                }
                                current_upstream.set(String::default());
                            },
                            input {
                                r#type: "text",
                                value: "{current_upstream}",
                                oninput: move |event| {
                                    current_upstream.set(event.value());
                                },
                            }
                        }
                    }
                }
            }
        }
    }
}

/// The try_update_ssl function attempts to update the SSL certificate and
/// key paths in the server settings. If both paths are valid, it updates
/// the SSL configuration in the settings.
///
/// # Arguments
/// * `ssl_cert` - A signal containing the SSL certificate path.
/// * `ssl_key` - A signal containing the SSL key path.
/// * `settings` - A mutable reference to the server settings.
fn try_update_ssl(
    ssl_cert: &Signal<String>,
    ssl_key: &Signal<String>,
    settings: &mut fluxgate::config::helper::Server,
) {
    let cert = ssl_cert.read();
    let key = ssl_key.read();

    if *cert != "Choose File" && *key != "Choose File" {
        settings.ssl = Some(fluxgate::config::SSLConfig {
            ssl_certificate: PathBuf::from(cert.as_str()),
            ssl_certificate_key: PathBuf::from(key.as_str()),
        });
    }
}
