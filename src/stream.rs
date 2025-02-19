// Copyright 2021 by Accenture ESR
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! # dlt streaming support
use crate::{
    dlt::{HEADER_MIN_LENGTH, STORAGE_HEADER_LENGTH},
    filtering::ProcessedDltFilterConfig,
    parse::{dlt_message, parse_length, DltParseError, ParsedMessage},
};
use futures::{AsyncRead, AsyncReadExt};

const DEFAULT_MESSAGE_MAX_LEN: usize = 10 * 1024;

/// Async read and parse the next DLT message from the given reader, if any.
pub async fn read_message<S: AsyncRead + Unpin>(
    reader: &mut DltStreamReader<S>,
    filter_config_opt: Option<&ProcessedDltFilterConfig>,
) -> Result<Option<ParsedMessage>, DltParseError> {
    let with_storage_header = reader.with_storage_header();
    let slice = reader.next_message_slice().await?;

    if !slice.is_empty() {
        Ok(Some(
            dlt_message(slice, filter_config_opt, with_storage_header)?.1,
        ))
    } else {
        Ok(None)
    }
}

/// Async reader for DLT message slices from a source.
pub struct DltStreamReader<S: AsyncRead + Unpin> {
    source: S,
    with_storage_header: bool,
    buffer: Vec<u8>,
}

impl<S: AsyncRead + Unpin> DltStreamReader<S> {
    /// Create a new reader for the given source.
    pub fn new(source: S, with_storage_header: bool) -> Self {
        DltStreamReader::with_capacity(DEFAULT_MESSAGE_MAX_LEN, source, with_storage_header)
    }

    /// Create a new reader for the given source and specified capacity.
    pub fn with_capacity(message_max_len: usize, source: S, with_storage_header: bool) -> Self {
        DltStreamReader {
            source,
            with_storage_header,
            buffer: vec![0u8; message_max_len],
        }
    }

    /// Async read the next message slice from the source,
    /// or return an empty slice if no more message could be read.
    pub async fn next_message_slice(&mut self) -> Result<&[u8], DltParseError> {
        let storage_len = if self.with_storage_header {
            STORAGE_HEADER_LENGTH as usize
        } else {
            0
        };
        let header_len = storage_len + HEADER_MIN_LENGTH as usize;

        if self
            .source
            .read_exact(&mut self.buffer[..header_len])
            .await
            .is_err()
        {
            return Ok(&[]);
        }

        let (_, message_len) = parse_length(&self.buffer[storage_len..header_len])?;
        let total_len = storage_len + message_len;

        self.source
            .read_exact(&mut self.buffer[header_len..total_len])
            .await?;

        Ok(&self.buffer[..total_len])
    }

    /// Answer if message slices contain a `StorageHeader´.
    pub fn with_storage_header(&self) -> bool {
        self.with_storage_header
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::DLT_ROUNDTRIP_MESSAGE;
    use futures::{stream, TryStreamExt};

    #[tokio::test]
    async fn test_next_message() {
        let stream = stream::iter([Ok(DLT_ROUNDTRIP_MESSAGE)]);
        let mut input = stream.into_async_read();
        let mut reader = DltStreamReader::new(&mut input, true);
        assert!(reader.with_storage_header());

        let message = reader.next_message_slice().await.expect("message");
        assert_eq!(DLT_ROUNDTRIP_MESSAGE, message);

        assert!(reader
            .next_message_slice()
            .await
            .expect("message")
            .is_empty());
    }

    #[tokio::test]
    async fn test_read_message() {
        let stream = stream::iter([Ok(DLT_ROUNDTRIP_MESSAGE)]);
        let mut input = stream.into_async_read();
        let mut reader = DltStreamReader::new(&mut input, true);
        assert!(reader.with_storage_header());

        if let Some(ParsedMessage::Item(message)) =
            read_message(&mut reader, None).await.expect("message")
        {
            assert_eq!(DLT_ROUNDTRIP_MESSAGE, message.as_bytes());
        }

        assert_eq!(
            None,
            read_message(&mut reader, None).await.expect("message")
        )
    }
}
