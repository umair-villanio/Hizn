//! Dev harness: inject a trivial Frida script into an app on a device, to
//! verify the Rust Frida control-protocol client end to end.
//! Usage: cargo run -p hizn-devices --example frida_inject -- <serial> <app.id>
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use hizn_devices::FridaSessions;
use hizn_devices::adb::Adb;
use hizn_devices::frida::{self, InjectOptions};

#[tokio::main]
async fn main() {
    let serial = std::env::args().nth(1).expect("serial");
    let target = std::env::args().nth(2).expect("app id");
    let adb = Adb::new();
    let sessions = FridaSessions::new();
    let opts = InjectOptions {
        serial: serial.clone(),
        payload: "send('hizn-rust-inject-ok');".into(),
        target,
        spawn: true,
        frida_port: frida::FRIDA_DEFAULT_PORT,
    };
    match frida::inject(&adb, &sessions, opts).await {
        Ok(pid) => {
            println!("INJECT OK — spawned + script loaded + resumed, pid {pid}");
            // Let it run briefly, then detach (kills the held connection).
            tokio::time::sleep(std::time::Duration::from_millis(600)).await;
            sessions.detach(&serial, pid);
            println!("detached");
        }
        Err(e) => {
            eprintln!("INJECT FAILED: {e}");
            std::process::exit(1);
        }
    }
}
