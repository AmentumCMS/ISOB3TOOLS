//! `isob3_tools` — shared library for the ISOB3 media-integrity toolchain.
//!
//! This crate is the common foundation used by:
//!
//! - **`isob3_tools`** (main binary) — the egui desktop GUI ([`app`])
//! - **`blake3iso`** — CLI for implanting / verifying / removing ISOB3 metadata
//! - **`direnc`** — CLI for encrypting a directory tree in-place before mastering an ISO
//! - **`discdecrypt`** — CLI for decrypting an encrypted disc image after optical read-back
//!
//! ## Module map
//!
//! | Module              | Responsibility                                              |
//! |---------------------|-------------------------------------------------------------|
//! | [`app`]             | egui GUI application state and rendering                    |
//! | [`blake3iso_core`]  | ISOB3 implant/check/remove/info logic                       |
//! | [`dbenc`]           | DBENC001–005 file encryption and decryption                 |
//! | [`encfile`]         | Ciphertext sidecar file helpers                             |
//! | [`isomd5`]          | Legacy ISOMD5 verification support                          |
//! | [`media`]           | Drive/media discovery                                       |
//! | [`sha256sum`]       | SHA-256 manifest parsing and verification                   |
//! | [`worker`]          | Background worker threads and event types                   |

pub mod app;
pub mod blake3iso_core;
pub mod dbenc;
pub mod encfile;
pub mod isomd5;
pub mod media;
pub mod sha256sum;
pub mod worker;
