//! Hizn device automation: a thin ADB client, device description and setup,
//! and the one-click orchestrator. Replaces the Node `AdbService`,
//! `Orchestrator`, and the ADB parts of the backend.
//!
//! SPDX-License-Identifier: AGPL-3.0-only

pub mod adb;
pub mod devices;
pub mod orchestrator;

pub use adb::{Adb, AdbError};
pub use devices::{CaInstall, DeviceInfo, Devices};
pub use orchestrator::{
    FridaOutcome, FridaRequest, FridaRunner, Orchestrator, ProxyControl, SetupOptions, SetupResult,
    SetupStep, StepSink, step_event,
};

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
