pub const MAGIC: &[u8; 4] = b"PBA1";
pub const ACK_LEN: usize = 14; // 4 magic + 1 status + 1 reason + 8 seq

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckStatus {
    Accepted,
    Duplicate,
    Retry,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckReason {
    None,
    SeqGap,
    HashMismatch,
    Oversize,
    Malformed,
    BadRecordNewline,
    SpoolWriteFailed,
    Busy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ack {
    pub status: AckStatus,
    pub reason: AckReason,
    pub next_expected_seq: u64,
}

impl AckStatus {
    fn to_u8(self) -> u8 {
        self as u8
    }
    fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0 => Self::Accepted,
            1 => Self::Duplicate,
            2 => Self::Retry,
            3 => Self::Reject,
            _ => return None,
        })
    }
}
impl AckReason {
    fn to_u8(self) -> u8 {
        self as u8
    }
    fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0 => Self::None,
            1 => Self::SeqGap,
            2 => Self::HashMismatch,
            3 => Self::Oversize,
            4 => Self::Malformed,
            5 => Self::BadRecordNewline,
            6 => Self::SpoolWriteFailed,
            7 => Self::Busy,
            _ => return None,
        })
    }
}

pub fn encode_ack(a: &Ack) -> [u8; ACK_LEN] {
    let mut out = [0u8; ACK_LEN];
    out[0..4].copy_from_slice(MAGIC);
    out[4] = a.status.to_u8();
    out[5] = a.reason.to_u8();
    out[6..14].copy_from_slice(&a.next_expected_seq.to_be_bytes());
    out
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AckError {
    #[error("bad ack")]
    Bad,
}

pub fn decode_ack(bytes: &[u8]) -> Result<Ack, AckError> {
    if bytes.len() != ACK_LEN || &bytes[0..4] != MAGIC {
        return Err(AckError::Bad);
    }
    let status = AckStatus::from_u8(bytes[4]).ok_or(AckError::Bad)?;
    let reason = AckReason::from_u8(bytes[5]).ok_or(AckError::Bad)?;
    let next_expected_seq = u64::from_be_bytes(bytes[6..14].try_into().unwrap());
    Ok(Ack {
        status,
        reason,
        next_expected_seq,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip_each_status() {
        for (st, rn) in [
            (AckStatus::Accepted, AckReason::None),
            (AckStatus::Duplicate, AckReason::None),
            (AckStatus::Retry, AckReason::Busy),
            (AckStatus::Reject, AckReason::SeqGap),
        ] {
            let a = Ack {
                status: st,
                reason: rn,
                next_expected_seq: 42,
            };
            let bytes = encode_ack(&a);
            assert_eq!(bytes.len(), ACK_LEN);
            assert_eq!(decode_ack(&bytes).unwrap(), a);
        }
    }
    #[test]
    fn unknown_status_byte_is_rejected() {
        let mut bytes = encode_ack(&Ack {
            status: AckStatus::Accepted,
            reason: AckReason::None,
            next_expected_seq: 1,
        });
        bytes[4] = 9;
        assert!(decode_ack(&bytes).is_err());
    }
}
