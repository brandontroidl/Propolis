pub mod guard;
pub mod http;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FetchStatus {
    Pending,
    Success,
    Dead,
    Rejected,
    TooBig,
    Timeout,
    Empty,
}

impl FetchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Success => "success",
            Self::Dead => "dead",
            Self::Rejected => "rejected",
            Self::TooBig => "too_big",
            Self::Timeout => "timeout",
            Self::Empty => "empty",
        }
    }
}
