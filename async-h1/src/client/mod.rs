use async_std::io::{BufReader,Read, Write, WriteExt};
use async_std::prelude::*;
use http_types::{ensure, format_err};
use http_types::{
    Body,
    trailers::{Trailers,Sender}
};

use crate::chunked::ChunkedDecoder;
use crate::{MAX_HEADERS, MAX_HEAD_LENGTH};

const CR: u8 = b'\r';
const LF: u8 = b'\n';

/// Opens an HTTP/1.1 connection to a remote host, return code,raw_header,location,body
pub async fn connect<RW>(mut stream: RW, raw_request: &[u8]) -> http_types::Result<(u16,Option<String>,Vec<u8>,Vec<u8>)>
where
    RW: Read + Write + Send + Sync + Unpin + 'static,
{
    let _ = stream.write_all(raw_request).await;
    let mut reader = BufReader::new(stream);
    let mut raw_header = Vec::new();
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut httparse_res = httparse::Response::new(&mut headers);

    // Keep reading bytes from the stream until we hit the end of the stream.
    loop {
        let bytes_read = reader.read_until(LF, &mut raw_header).await?;
        // No more bytes are yielded from the stream.

        match (bytes_read, raw_header.len()) {
            (0, 0) => return Err(format_err!("connection closed")),
            (0, _) => return Err(format_err!("empty response")),
            _ => {}
        }

        // Prevent CWE-400 DDOS with large HTTP Headers.
        ensure!(
            raw_header.len() < MAX_HEAD_LENGTH,
            "Head byte length should be less than 8kb"
        );

        // We've hit the end delimiter of the stream.
        let idx = raw_header.len() - 1;
        if idx >= 3 && raw_header[idx - 3..=idx] == [CR, LF, CR, LF] {
            break;
        }
        if idx >= 1 && raw_header[idx - 1..=idx] == [LF, LF] {
            break;
        }
    }

    // Convert our header buf into an httparse instance, and validate.
    let status = httparse_res.parse(&raw_header)?;
    ensure!(!status.is_partial(), "Malformed HTTP head");

    let code = httparse_res.code;
    let code = code.ok_or_else(|| format_err!("No status code found"))?;

    let mut location = None;
    let mut content_length = None;
    let mut chunked_encoding = false;

    let mut headers_map = Vec::new();
    for header in httparse_res.headers.iter() {
        let name = header.name.to_lowercase();
        let v = std::str::from_utf8(header.value)?;
        if name == "content-length" {
            content_length = Some(v);
        }
        headers_map.push((name,v));
    }

    for header in headers_map.iter() {
        if header.0 == "location" {
            location = Some(header.1.to_string());
            break;
        }
    }

    if content_length.is_none() {
        for header in headers_map.iter() {
            if header.0 == "transfer-encoding" {
                if header.1 == "chunked" {
                    chunked_encoding = true;
                    break;
                }
            }
        }
    }

    //let content_length = httparse_res.headers. .header(CONTENT_LENGTH);
    // Check for Content-Length.
    let body = if let Some(len) = content_length {
        let len = len.parse::<usize>()?;
        Body::from_reader(reader.take(len as u64), Some(len))
    } else {
        if chunked_encoding {
            let (trailers_sender, _) = async_channel::bounded::<Trailers>(1);
            let trailers_sender = Sender::new(trailers_sender);
            let reader = BufReader::new(ChunkedDecoder::new(reader, trailers_sender));
            Body::from_reader(reader, None)
        } else {
            Body::empty()
        }
    };
    let body = if let Ok(b) = body.into_bytes ().await {
        b
    } else {
        Vec::new()
    };
    // Return the response.
    Ok((code,location,raw_header,body))
}