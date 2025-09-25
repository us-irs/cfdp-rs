#[cfg(not(any(
    feature = "packet-buf-256",
    feature = "packet-buf-512",
    feature = "packet-buf-1k",
    feature = "packet-buf-2k",
    feature = "packet-buf-4k"
)))]
compile_error!(
    "One of the features `packet-buf-256`, `packet-buf-512`, `packet-buf-1k`, `packet-buf-2k`, or `packet-buf-4k` must be enabled."
);

#[cfg(feature = "packet-buf-256")]
pub const PACKET_BUF_LEN: usize = 256;
#[cfg(feature = "packet-buf-512")]
pub const PACKET_BUF_LEN: usize = 512;
#[cfg(feature = "packet-buf-1k")]
pub const PACKET_BUF_LEN: usize = 1024;
#[cfg(feature = "packet-buf-2k")]
pub const PACKET_BUF_LEN: usize = 2048;
#[cfg(feature = "packet-buf-4k")]
pub const PACKET_BUF_LEN: usize = 4096;
