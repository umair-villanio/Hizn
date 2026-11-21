//! Dev harness: scan an APK and print the report JSON.
//! Usage: cargo run -p hizn-analyzer --example scan -- <file.apk> [displayName]
//!
//! SPDX-License-Identifier: AGPL-3.0-only

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: scan <file.apk> [name]");
    let name = std::env::args().nth(2);
    let bytes = std::fs::read(&path).expect("read apk");
    let report = hizn_analyzer::analyze_to_json(&bytes, name.as_deref());
    println!("{}", serde_json::to_string(&report).expect("serialize"));
}
