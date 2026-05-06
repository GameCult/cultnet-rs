use anyhow::Result;
use anyhow::anyhow;

pub const FRAME_HEADER_BYTES: usize = 4;

pub fn encode_frame(payload: &[u8]) -> Result<Vec<u8>> {
    let len: u32 = payload
        .len()
        .try_into()
        .map_err(|_| anyhow!("CultNet frame payload is too large"))?;
    let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

#[derive(Clone, Debug, Default)]
pub struct LengthPrefixedMessageFramer {
    buffer: Vec<u8>,
}

impl LengthPrefixedMessageFramer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, chunk: impl AsRef<[u8]>) -> Vec<Vec<u8>> {
        self.buffer.extend_from_slice(chunk.as_ref());
        let mut frames = Vec::new();
        loop {
            if self.buffer.len() < FRAME_HEADER_BYTES {
                break;
            }
            let payload_len = u32::from_be_bytes([
                self.buffer[0],
                self.buffer[1],
                self.buffer[2],
                self.buffer[3],
            ]) as usize;
            let total_len = FRAME_HEADER_BYTES + payload_len;
            if self.buffer.len() < total_len {
                break;
            }
            frames.push(self.buffer[FRAME_HEADER_BYTES..total_len].to_vec());
            self.buffer.drain(0..total_len);
        }
        frames
    }
}
