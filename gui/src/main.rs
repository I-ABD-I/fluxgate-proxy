use std::{fs, io::Write};

use async_process::{Child, Command, Stdio};

use db::DatabaseTab;
#[cfg(feature = "desktop")]
use dioxus::desktop::Config;
use dioxus::prelude::*;
use log::{update_log, LogsTab};
use settings::SettingsTab;

mod db;
mod log;
mod settings;

/// The path to the favicon asset.
const FAVICON: Asset = asset!("/assets/favicon.ico");
/// The path to the Tailwind CSS asset.
const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");

/// The path to the configuration file.
const CONFIG_FILE: &str = "~/.config/fluxgate/config.ron";


fn main() {
    #[cfg(feature = "desktop")]
    dioxus::LaunchBuilder::new()
        .with_cfg(Config::default().with_menu(None))
        .launch(App);

    #[cfg(not(feature = "desktop"))]
    dioxus::launch(App);
}

/// The main application component.
/// It initializes the application state, including the selected tab,
/// the settings, and the proxy process.
#[component]
fn App() -> Element {
    let mut selected_tab = use_signal(|| Tab::Settings);

    let settings = use_signal(|| match fs::read_to_string(CONFIG_FILE) {
        Ok(str) => ron::from_str(&str).unwrap(),
        Err(_) => Vec::new(),
    });

    let mut proxy: Signal<Option<Child>> = use_signal(|| None);
    let mut current_log = use_signal(String::default);

    use_drop({
        let mut proxy = proxy.clone();
        move || {
            if let Some(child) = &mut *proxy.write() {
                child.kill().unwrap();
            }
        }
    });

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
                    LogsTab { log: current_log }
                },
                Tab::Database => rsx! {
                    DatabaseTab {}
                },
            }
            Footer {
                play_cb: move |_| {
                    let mut file = match fs::File::create(CONFIG_FILE) {
                        Ok(file) => file,
                        Err(e) => {
                            println!("unable to write config file {e:?}");
                            return;
                        }
                    };
                    file.write(ron::to_string(&*settings.read()).unwrap().as_bytes()).unwrap();
                    if let Some(child) = &mut *proxy.write() {
                        child.kill().unwrap();
                        current_log.set(String::default());
                    }
                    let mut child = match Command::new("./fluxgate")
                        .args(&["-c", CONFIG_FILE])
                        .env("RUST_LOG_STYLE", "always")
                        .env("CLICOLOR_FORCE", "1")
                        .stdout(Stdio::piped())
                        .spawn()
                    {
                        Ok(child) => child,
                        Err(e) => {
                            println!("Failed to launch fluxgate {e:?}");
                            return;
                        }
                    };
                    let stdout = child.stdout.take();
                    let stdout = match stdout {
                        Some(s) => s,
                        _ => return,
                    };
                    spawn(update_log(stdout, current_log));
                    proxy.set(Some(child));
                    selected_tab.set(Tab::Logs);
                },
            }
        }
    }
}

#[derive(PartialEq, Eq)]
/// Represents the different tabs in the application.
enum Tab {
    /// The settings tab.
    Settings,
    /// The logs tab.
    Logs,
    /// The database tab.
    Database,
}

/// Represents the header of the application.
/// It contains buttons to switch between different tabs.
///
/// # Arguments
///
/// * `state`: A signal representing the currently selected tab.
///   - `Tab::Settings`: The settings tab.
///   - `Tab::Logs`: The logs tab.
///   - `Tab::Database`: The database tab.
///
/// # Returns
/// An `Element` representing the header of the application.

#[component]
fn Header(state: Signal<Tab>) -> Element {
    const SELECTED_COLOR: &str = "bg-secondary-700/20";
    const UNSELECTED_COLOR: &str = "bg-white/3";

    let selected = state.read();

    let (settings_color, log_color, database_color) = match *selected {
        Tab::Settings => (SELECTED_COLOR, UNSELECTED_COLOR, UNSELECTED_COLOR),
        Tab::Logs => (UNSELECTED_COLOR, SELECTED_COLOR, UNSELECTED_COLOR),
        Tab::Database => (UNSELECTED_COLOR, UNSELECTED_COLOR, SELECTED_COLOR),
    };

    rsx! {
        div { class: "flex max-h-[10vh]",
            button {
                class: "{settings_color} rounded-tl min-w-32 px-8 py-2",
                onclick: move |_| state.set(Tab::Settings),
                "Fluxgate Settings"
            }
            button {
                class: "{log_color} min-w-32 px-8 py-2",
                onclick: move |_| state.set(Tab::Logs),
                "Fluxgate Log"
            }
            button {
                class: "{database_color} rounded-tr-lg min-w-32 px-8 py-2",
                onclick: move |_| state.set(Tab::Database),
                "Database analyitics"
            }
        }
    }
}

/// Represents the footer of the application.
/// It contains a play button to start the proxy process.
///
/// # Arguments
/// * `play_cb`: A callback function to be called when the play button is clicked.
///
/// # Returns
/// An `Element` representing the footer of the application.

#[component]
fn Footer(play_cb: EventHandler<Event<MouseData>>) -> Element {
    rsx! {
        div { class: "flex max-h-[10vh] min-h-[10vh] items-center",
            button {
                class: "justify-center rounded-full p-2 m-4 bg-accent w-12 h-12",
                onclick: play_cb,
                svg {
                    xmlns: "http://www.w3.org/2000/svg",
                    width: "32",
                    height: "32",
                    fill: "currentColor",
                    class: "fill-primary-800/80",
                    view_box: "0 0 16 16",
                    path { d: "m11.596 8.697-6.363 3.692c-.54.313-1.233-.066-1.233-.697V4.308c0-.63.692-1.01 1.233-.696l6.363 3.692a.802.802 0 0 1 0 1.393" }
                }
            }
        }
    }
}
