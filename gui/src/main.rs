use std::{
    fs,
    io::Write,
    net::ToSocketAddrs,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

#[cfg(feature = "desktop")]
use dioxus::desktop::Config;
use dioxus::{dioxus_core::SpawnIfAsync, prelude::*};
use dioxus_free_icons::{icons::bs_icons::BsPlayFill, Icon};
use fluxgate::config::Upstream;
use rfd::FileDialog;

const FAVICON: Asset = asset!("/assets/favicon.ico");
const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");

fn main() {
    #[cfg(feature = "desktop")]
    dioxus::LaunchBuilder::new()
        .with_cfg(Config::default().with_menu(None))
        .launch(App);

    #[cfg(not(feature = "desktop"))]
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    let mut selected_tab = use_signal(|| Tab::Settings);

    let settings = use_signal(|| match fs::read_to_string("config.ron") {
        Ok(str) => ron::from_str(&str).unwrap(),
        Err(_) => Vec::new(),
    });

    let mut proxy: Signal<Option<Child>> = use_signal(|| None);

    rsx! {
        document::Link { rel: "icon", href: FAVICON }
        document::Link { rel: "stylesheet", href: TAILWIND_CSS }
        div { class: "flex flex-col min-h-screen bg-background text-text",
            Header { state: selected_tab }
            match *selected_tab.read() {
                Tab::Settings => rsx! {
                    SettingsTab { settings }
                },
                Tab::Logs => rsx! {
                    LogsTab {}
                },
            }
            Footer {
                play_cb: move |_| {
                    let mut file = fs::File::create("config.ron").unwrap();
                    file.write(ron::to_string(&*settings.read()).unwrap().as_bytes()).unwrap();
                    if let Some(_) = *proxy.read() {
                        return;
                    }
                    proxy
                        .set(
                            Some(
                                Command::new("./fluxgate")
                                    .args(&["-c", "config.ron"])
                                    .env("PYTHON", "../.venv/bin/python")
                                    .stdout(Stdio::inherit())
                                    .spawn()
                                    .expect("Cannot launch fluxgate"),
                            ),
                        );
                    selected_tab.set(Tab::Logs);
                },
            }
        }
    }
}

#[derive(PartialEq, Eq)]
enum Tab {
    Settings,
    Logs,
}

#[component]
fn Header(state: Signal<Tab>) -> Element {
    const SELECTED_COLOR: &str = "bg-secondary-700/20";
    const UNSELECTED_COLOR: &str = "bg-white/3";

    let selected = state.read();

    let (settings_color, log_color) = match *selected {
        Tab::Settings => (SELECTED_COLOR, UNSELECTED_COLOR),
        Tab::Logs => (UNSELECTED_COLOR, SELECTED_COLOR),
    };

    rsx! {
        div { class: "flex min-h-10",
            button {
                class: "{settings_color} rounded-tl min-w-32 px-8 py-2",
                onclick: move |_| state.set(Tab::Settings),
                "Fluxgate Settings"
            }
            button {
                class: "{log_color} rounded-tr-lg min-w-32 px-8 py-2",
                onclick: move |_| state.set(Tab::Logs),
                "Fluxgate Log"
            }
        }
    }
}

#[component]
fn Footer(play_cb: EventHandler<Event<MouseData>>) -> Element {
    rsx! {
        div { class: "flex min-h-10",
            button {
                class: "items-center rounded-full p-2 m-4 bg-accent",
                onclick: play_cb,
                Icon {
                    class: "fill-primary-700",
                    width: 40,
                    height: 40,
                    icon: BsPlayFill,
                }
            }
        }
    }
}

#[component]
fn SettingsTab(settings: Signal<Vec<fluxgate::config::helper::Server>>) -> Element {
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

#[component]
fn LogsTab() -> Element {
    rsx! {
        div { class: "felx-1", "Logs Tab" }
    }
}
