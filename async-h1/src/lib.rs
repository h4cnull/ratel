//! Streaming async HTTP 1.1 parser.

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations, nonstandard_style, rust_2018_idioms)]
#![warn(missing_docs, missing_doc_code_examples, unreachable_pub)]
#![cfg_attr(test, deny(warnings))]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::len_zero)]
#![allow(clippy::match_bool)]
#![allow(clippy::unreadable_literal)]

/// The maximum amount of headers parsed on the server.
const MAX_HEADERS: usize = 128;

/// The maximum length of the head section we'll try to parse.
/// See: https://nodejs.org/en/blog/vulnerability/november-2018-security-releases/#denial-of-service-with-large-http-headers-cve-2018-12121
const MAX_HEAD_LENGTH: usize = 6 * 1024;

mod chunked;

/// simple http client
pub mod client;
pub use client::connect;