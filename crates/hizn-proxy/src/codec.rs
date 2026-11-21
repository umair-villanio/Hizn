//! Content-Encoding decode/encode, so bodies can be shown and rewritten as
//! text and then re-encoded the way they arrived (as mockttp does).
//!
//! SPDX-License-Identifier: AGPL-3.0-only

use std::io::{Read, Write};

use http::HeaderMap;

/// The encodings listed in `Content-Encoding`, in the order applied.
pub fn encodings(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(http::header::CONTENT_ENCODING)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|e| e.trim().to_ascii_lowercase())
        .filter(|e| !e.is_empty() && e != "identity")
        .collect()
}

/// Undo the encodings (last applied first). `None` if any is unknown or the
/// data is corrupt.
pub fn decode(body: &[u8], encodings: &[String]) -> Option<Vec<u8>> {
    let mut data = body.to_vec();
    for enc in encodings.iter().rev() {
        data = decode_one(&data, enc)?;
    }
    Some(data)
}

/// Apply the encodings in order.
pub fn encode(body: &[u8], encodings: &[String]) -> Option<Vec<u8>> {
    let mut data = body.to_vec();
    for enc in encodings {
        data = encode_one(&data, enc)?;
    }
    Some(data)
}

fn decode_one(data: &[u8], enc: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    match enc {
        "gzip" | "x-gzip" => {
            flate2::read::MultiGzDecoder::new(data)
                .read_to_end(&mut out)
                .ok()?;
        }
        "deflate" | "x-deflate" => {
            // zlib-wrapped per the spec; some servers send raw deflate.
            if flate2::read::ZlibDecoder::new(data)
                .read_to_end(&mut out)
                .is_err()
            {
                out.clear();
                flate2::read::DeflateDecoder::new(data)
                    .read_to_end(&mut out)
                    .ok()?;
            }
        }
        "br" => {
            brotli::Decompressor::new(data, 4096)
                .read_to_end(&mut out)
                .ok()?;
        }
        "zstd" => {
            ruzstd::decoding::StreamingDecoder::new(data)
                .ok()?
                .read_to_end(&mut out)
                .ok()?;
        }
        _ => return None,
    }
    Some(out)
}

/// zlib's gzip header OS byte for the platform Node would be running on.
const GZIP_OS: u8 = if cfg!(windows) {
    10
} else if cfg!(target_os = "macos") {
    19
} else {
    3
};

/// mockttp re-encodes rewritten bodies at level 1 for every codec
/// (`encodeBuffer(..., { level: 1 })`).
fn encode_one(data: &[u8], enc: &str) -> Option<Vec<u8>> {
    let level = flate2::Compression::new(1);
    match enc {
        "gzip" | "x-gzip" => {
            let mut e = flate2::GzBuilder::new()
                .operating_system(GZIP_OS)
                .write(Vec::new(), level);
            e.write_all(data).ok()?;
            e.finish().ok()
        }
        "deflate" | "x-deflate" => {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), level);
            e.write_all(data).ok()?;
            e.finish().ok()
        }
        "br" => {
            let mut out = Vec::new();
            {
                // Quality 1, Node's default 22-bit window.
                let mut w = brotli::CompressorWriter::new(&mut out, 4096, 1, 22);
                w.write_all(data).ok()?;
            }
            Some(out)
        }
        "zstd" => Some(ruzstd::encoding::compress_to_vec(
            data,
            ruzstd::encoding::CompressionLevel::Fastest,
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_codec_and_stacks() {
        let text = b"hello hello hello codec world".repeat(50);
        for list in [
            vec!["gzip"],
            vec!["deflate"],
            vec!["br"],
            vec!["zstd"],
            vec!["gzip", "br"],
        ] {
            let list: Vec<String> = list.into_iter().map(String::from).collect();
            let packed = encode(&text, &list).unwrap();
            assert_ne!(packed, text);
            assert_eq!(decode(&packed, &list).unwrap(), text, "{list:?}");
        }
        assert!(decode(b"not gzip", &["gzip".into()]).is_none());
        assert!(decode(b"x", &["compress".into()]).is_none());
    }

    #[test]
    fn reads_the_header_like_mockttp() {
        let mut h = HeaderMap::new();
        h.insert(
            http::header::CONTENT_ENCODING,
            "GZIP, identity, br".parse().unwrap(),
        );
        assert_eq!(encodings(&h), ["gzip", "br"]);
    }
}
