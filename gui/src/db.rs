use std::env;

use dioxus::prelude::*;
use firestore::{FirestoreDb, FirestoreDbOptions, FirestoreTimestamp};
use serde::{Deserialize, Serialize};

#[component]
pub fn DatabaseTab() -> Element {
    let mut servers: Signal<Option<Vec<Server>>> = use_signal(|| None);

    use_future(move || async move {
        servers.set(get_db().await);
    });

    rsx! {
        div { class: "flex flex-1 items-center p-4 flex-col",
            div { class: "overflow-y-auto flex flex-col w-3/4 items-center max-h-[70vh]",
                if let Some(ref vec) = *servers.read() {
                    for index in 0..vec.len() {
                        ServerWidget { servers, index }
                    }
                }
            }
            button {
                class: "mt-auto bg-accent py-2 px-4 m-0 rounded-3xl",
                onclick: move |_| {
                    spawn(async move {
                        servers.set(get_db().await);
                    });
                },
                "Refresh"
            }
        }
    }
}

async fn get_db() -> Option<Vec<Server>> {
    let pid = match env::var("FIREBASE_ID") {
        Ok(s) => s,
        Err(_) => {
            println!("Unable to find Firebase Project Id");
            return None;
        }
    };

    let db = FirestoreDb::with_options_service_account_key_file(
        FirestoreDbOptions::new(pid),
        "./cred.json".into(),
    )
    .await
    .unwrap();

    Some(
        db.fluent()
            .select()
            .from("servers")
            .obj::<Server>()
            .query()
            .await
            .unwrap(),
    )
}

#[component]
fn ServerWidget(servers: Signal<Option<Vec<Server>>>, index: usize) -> Element {
    let servers = servers.read();

    let server = match *servers {
        Some(ref vec) => &vec[index],
        None => unreachable!(),
    };

    let fmt = "%Y-%m-%d %H:%M:%S";

    rsx! {
        div { class: "flex flex-col bg-white/3 rounded-xl p-4 m-2 w-7/8",
            h1 { "{server.id}" }
            p {
                "New Connections: "
                "{server.new_connections}"
            }
            div { class: "max-h-[50vh] overflow-y-auto",
                table { class: "table-auto w-[calc(100%-10rem)]",
                    thead {
                        tr {
                            th { "Timestamp" }
                            th { "Length" }
                        }
                    }
                    tbody { class: "text-center",
                        for stamp in &server.log {
                            tr {
                                td { "{stamp.timestamp.0.format(fmt)}" }
                                td { "{stamp.length}" }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Server {
    #[serde(alias = "_firestore_id")]
    pub id: String,
    new_connections: u64,
    log: Vec<Stamp>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Stamp {
    timestamp: FirestoreTimestamp,
    length: usize,
}
