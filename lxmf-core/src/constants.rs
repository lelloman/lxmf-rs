// LXMF Protocol Constants
// Ported from Python LXMF v0.9.4

// ============================================================
// Application
// ============================================================

pub const APP_NAME: &str = "lxmf";

// Destination aspects
pub const ASPECT_DELIVERY: &str = "lxmf.delivery";
pub const ASPECT_PROPAGATION: &str = "lxmf.propagation";
pub const ASPECT_PROPAGATION_CONTROL: &str = "lxmf.propagation.control";

// ============================================================
// Message Field IDs (LXMF.py)
// ============================================================

pub const FIELD_EMBEDDED_LXMS: u8 = 0x01;
pub const FIELD_TELEMETRY: u8 = 0x02;
pub const FIELD_TELEMETRY_STREAM: u8 = 0x03;
pub const FIELD_ICON_APPEARANCE: u8 = 0x04;
pub const FIELD_FILE_ATTACHMENTS: u8 = 0x05;
pub const FIELD_IMAGE: u8 = 0x06;
pub const FIELD_AUDIO: u8 = 0x07;
pub const FIELD_THREAD: u8 = 0x08;
pub const FIELD_COMMANDS: u8 = 0x09;
pub const FIELD_RESULTS: u8 = 0x0A;
pub const FIELD_GROUP: u8 = 0x0B;
pub const FIELD_TICKET: u8 = 0x0C;
pub const FIELD_EVENT: u8 = 0x0D;
pub const FIELD_RNR_REFS: u8 = 0x0E;
pub const FIELD_RENDERER: u8 = 0x0F;

pub const FIELD_CUSTOM_TYPE: u8 = 0xFB;
pub const FIELD_CUSTOM_DATA: u8 = 0xFC;
pub const FIELD_CUSTOM_META: u8 = 0xFD;
pub const FIELD_NON_SPECIFIC: u8 = 0xFE;
pub const FIELD_DEBUG: u8 = 0xFF;

// ============================================================
// Audio Modes (LXMF.py)
// ============================================================

// Codec2
pub const AM_CODEC2_450PWB: u8 = 0x01;
pub const AM_CODEC2_450: u8 = 0x02;
pub const AM_CODEC2_700C: u8 = 0x03;
pub const AM_CODEC2_1200: u8 = 0x04;
pub const AM_CODEC2_1300: u8 = 0x05;
pub const AM_CODEC2_1400: u8 = 0x06;
pub const AM_CODEC2_1600: u8 = 0x07;
pub const AM_CODEC2_2400: u8 = 0x08;
pub const AM_CODEC2_3200: u8 = 0x09;

// Opus
pub const AM_OPUS_OGG: u8 = 0x10;
pub const AM_OPUS_LBW: u8 = 0x11;
pub const AM_OPUS_MBW: u8 = 0x12;
pub const AM_OPUS_PTT: u8 = 0x13;
pub const AM_OPUS_RT_HDX: u8 = 0x14;
pub const AM_OPUS_RT_FDX: u8 = 0x15;
pub const AM_OPUS_STANDARD: u8 = 0x16;
pub const AM_OPUS_HQ: u8 = 0x17;
pub const AM_OPUS_BROADCAST: u8 = 0x18;
pub const AM_OPUS_LOSSLESS: u8 = 0x19;

pub const AM_CUSTOM: u8 = 0xFF;

// ============================================================
// Renderer Hints (LXMF.py)
// ============================================================

pub const RENDERER_PLAIN: u8 = 0x00;
pub const RENDERER_MICRON: u8 = 0x01;
pub const RENDERER_MARKDOWN: u8 = 0x02;
pub const RENDERER_BBCODE: u8 = 0x03;

// ============================================================
// Propagation Node Metadata Fields (LXMF.py)
// ============================================================

pub const PN_META_VERSION: u8 = 0x00;
pub const PN_META_NAME: u8 = 0x01;
pub const PN_META_SYNC_STRATUM: u8 = 0x02;
pub const PN_META_SYNC_THROTTLE: u8 = 0x03;
pub const PN_META_AUTH_BAND: u8 = 0x04;
pub const PN_META_UTIL_PRESSURE: u8 = 0x05;
pub const PN_META_CUSTOM: u8 = 0xFF;

// ============================================================
// Message States (LXMessage.py)
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageState {
    Generating = 0x00,
    Outbound = 0x01,
    Sending = 0x02,
    Sent = 0x04,
    Delivered = 0x08,
    Rejected = 0xFD,
    Cancelled = 0xFE,
    Failed = 0xFF,
}

impl MessageState {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Generating),
            0x01 => Some(Self::Outbound),
            0x02 => Some(Self::Sending),
            0x04 => Some(Self::Sent),
            0x08 => Some(Self::Delivered),
            0xFD => Some(Self::Rejected),
            0xFE => Some(Self::Cancelled),
            0xFF => Some(Self::Failed),
            _ => None,
        }
    }
}

// ============================================================
// Delivery Methods (LXMessage.py)
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeliveryMethod {
    Opportunistic = 0x01,
    Direct = 0x02,
    Propagated = 0x03,
    Paper = 0x05,
}

impl DeliveryMethod {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Opportunistic),
            0x02 => Some(Self::Direct),
            0x03 => Some(Self::Propagated),
            0x05 => Some(Self::Paper),
            _ => None,
        }
    }
}

// ============================================================
// Representation Types (LXMessage.py)
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Representation {
    Unknown = 0x00,
    Packet = 0x01,
    Resource = 0x02,
}

impl Representation {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Unknown),
            0x01 => Some(Self::Packet),
            0x02 => Some(Self::Resource),
            _ => None,
        }
    }
}

// ============================================================
// Unverified Reasons (LXMessage.py)
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UnverifiedReason {
    SourceUnknown = 0x01,
    SignatureInvalid = 0x02,
}

impl UnverifiedReason {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::SourceUnknown),
            0x02 => Some(Self::SignatureInvalid),
            _ => None,
        }
    }
}

// ============================================================
// Peer States (LXMPeer.py)
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PeerState {
    Idle = 0x00,
    LinkEstablishing = 0x01,
    LinkReady = 0x02,
    RequestSent = 0x03,
    ResponseReceived = 0x04,
    ResourceTransferring = 0x05,
}

impl PeerState {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Idle),
            0x01 => Some(Self::LinkEstablishing),
            0x02 => Some(Self::LinkReady),
            0x03 => Some(Self::RequestSent),
            0x04 => Some(Self::ResponseReceived),
            0x05 => Some(Self::ResourceTransferring),
            _ => None,
        }
    }
}

// ============================================================
// Peer Errors (LXMPeer.py)
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PeerError {
    NoIdentity = 0xF0,
    NoAccess = 0xF1,
    InvalidKey = 0xF3,
    InvalidData = 0xF4,
    InvalidStamp = 0xF5,
    Throttled = 0xF6,
    NotFound = 0xFD,
    Timeout = 0xFE,
}

impl PeerError {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0xF0 => Some(Self::NoIdentity),
            0xF1 => Some(Self::NoAccess),
            0xF3 => Some(Self::InvalidKey),
            0xF4 => Some(Self::InvalidData),
            0xF5 => Some(Self::InvalidStamp),
            0xF6 => Some(Self::Throttled),
            0xFD => Some(Self::NotFound),
            0xFE => Some(Self::Timeout),
            _ => None,
        }
    }
}

// ============================================================
// Sync Strategies (LXMPeer.py)
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SyncStrategy {
    Lazy = 0x01,
    Persistent = 0x02,
}

impl SyncStrategy {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Lazy),
            0x02 => Some(Self::Persistent),
            _ => None,
        }
    }
}

pub const DEFAULT_SYNC_STRATEGY: SyncStrategy = SyncStrategy::Persistent;

// ============================================================
// Propagation Transfer States (LXMRouter.py)
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PropagationTransferState {
    Idle = 0x00,
    PathRequested = 0x01,
    LinkEstablishing = 0x02,
    LinkEstablished = 0x03,
    RequestSent = 0x04,
    Receiving = 0x05,
    ResponseReceived = 0x06,
    Complete = 0x07,
    NoPath = 0xF0,
    LinkFailed = 0xF1,
    TransferFailed = 0xF2,
    NoIdentityReceived = 0xF3,
    NoAccess = 0xF4,
    Failed = 0xFE,
}

impl PropagationTransferState {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Idle),
            0x01 => Some(Self::PathRequested),
            0x02 => Some(Self::LinkEstablishing),
            0x03 => Some(Self::LinkEstablished),
            0x04 => Some(Self::RequestSent),
            0x05 => Some(Self::Receiving),
            0x06 => Some(Self::ResponseReceived),
            0x07 => Some(Self::Complete),
            0xF0 => Some(Self::NoPath),
            0xF1 => Some(Self::LinkFailed),
            0xF2 => Some(Self::TransferFailed),
            0xF3 => Some(Self::NoIdentityReceived),
            0xF4 => Some(Self::NoAccess),
            0xFE => Some(Self::Failed),
            _ => None,
        }
    }
}

pub const PR_ALL_MESSAGES: u8 = 0x00;

// ============================================================
// Size Constants (LXMessage.py)
// ============================================================

pub const DESTINATION_LENGTH: usize = 16;
pub const SIGNATURE_LENGTH: usize = 64;
pub const TICKET_LENGTH: usize = 16;
pub const TIMESTAMP_SIZE: usize = 8;
pub const STRUCT_OVERHEAD: usize = 8;
pub const LXMF_OVERHEAD: usize =
    2 * DESTINATION_LENGTH + SIGNATURE_LENGTH + TIMESTAMP_SIZE + STRUCT_OVERHEAD;

pub const STAMP_SIZE: usize = 32;

// Packet MDU values (from RNS)
pub const ENCRYPTED_PACKET_MDU: usize = 399; // Packet.ENCRYPTED_MDU + TIMESTAMP_SIZE
pub const LINK_PACKET_MDU: usize = 431; // Link.MDU
pub const PLAIN_PACKET_MDU: usize = 464; // Packet.PLAIN_MDU

pub const ENCRYPTED_PACKET_MAX_CONTENT: usize =
    ENCRYPTED_PACKET_MDU - LXMF_OVERHEAD + DESTINATION_LENGTH;
pub const LINK_PACKET_MAX_CONTENT: usize = LINK_PACKET_MDU - LXMF_OVERHEAD;
pub const PLAIN_PACKET_MAX_CONTENT: usize =
    PLAIN_PACKET_MDU - LXMF_OVERHEAD + DESTINATION_LENGTH;

// Paper / QR
pub const URI_SCHEMA: &str = "lxm";
pub const QR_MAX_STORAGE: usize = 2953;
pub const PAPER_MDU: usize = (QR_MAX_STORAGE - URI_SCHEMA.len() - 3) * 6 / 8; // 3 = "://"

// Encryption descriptions
pub const ENCRYPTION_DESCRIPTION_AES: &str = "AES-128";
pub const ENCRYPTION_DESCRIPTION_EC: &str = "Curve25519";
pub const ENCRYPTION_DESCRIPTION_UNENCRYPTED: &str = "Unencrypted";

// ============================================================
// Ticket Constants (LXMessage.py)
// ============================================================

pub const TICKET_EXPIRY: u64 = 21 * 24 * 60 * 60; // 21 days
pub const TICKET_GRACE: u64 = 5 * 24 * 60 * 60; // 5 days
pub const TICKET_RENEW: u64 = 14 * 24 * 60 * 60; // 14 days
pub const TICKET_INTERVAL: u64 = 1 * 24 * 60 * 60; // 1 day
pub const COST_TICKET: u32 = 0x100; // 256

// ============================================================
// Stamp / Workblock Constants (LXStamper.py)
// ============================================================

pub const WORKBLOCK_EXPAND_ROUNDS: u32 = 3000;
pub const WORKBLOCK_EXPAND_ROUNDS_PN: u32 = 1000;
pub const WORKBLOCK_EXPAND_ROUNDS_PEERING: u32 = 25;
pub const PN_VALIDATION_POOL_MIN_SIZE: usize = 256;

// ============================================================
// Router Constants (LXMRouter.py)
// ============================================================

// Delivery and processing
pub const MAX_DELIVERY_ATTEMPTS: u32 = 5;
pub const PROCESSING_INTERVAL: u64 = 4; // seconds
pub const DELIVERY_RETRY_WAIT: u64 = 10; // seconds
pub const PATH_REQUEST_WAIT: u64 = 7; // seconds
pub const MAX_PATHLESS_TRIES: u32 = 1;
pub const LINK_MAX_INACTIVITY: u64 = 10 * 60; // 10 minutes
pub const P_LINK_MAX_INACTIVITY: u64 = 3 * 60; // 3 minutes

// Message and stamp expiry
pub const MESSAGE_EXPIRY: u64 = 30 * 24 * 60 * 60; // 30 days
pub const STAMP_COST_EXPIRY: u64 = 45 * 24 * 60 * 60; // 45 days

// Node configuration
pub const NODE_ANNOUNCE_DELAY: u64 = 20; // seconds

// Peer management
pub const MAX_PEERS: usize = 20;
pub const AUTOPEER: bool = true;
pub const AUTOPEER_MAXDEPTH: u8 = 4;
pub const FASTEST_N_RANDOM_POOL: usize = 2;
pub const ROTATION_HEADROOM_PCT: usize = 10;
pub const ROTATION_AR_MAX: f64 = 0.5;

// Stamp and propagation costs
pub const PEERING_COST: u8 = 18;
pub const MAX_PEERING_COST: u8 = 26;
pub const PROPAGATION_COST_MIN: u8 = 13;
pub const PROPAGATION_COST_FLEX: u8 = 3;
pub const PROPAGATION_COST: u8 = 16;
pub const PROPAGATION_LIMIT: u32 = 256; // KB
pub const SYNC_LIMIT: u32 = PROPAGATION_LIMIT * 40; // KB
pub const DELIVERY_LIMIT: u32 = 1000; // KB

// Propagation request timing
pub const PR_PATH_TIMEOUT: u64 = 10; // seconds
pub const PN_STAMP_THROTTLE: u64 = 180; // seconds

// Job intervals (in processing cycles)
pub const JOB_OUTBOUND_INTERVAL: u32 = 1;
pub const JOB_STAMPS_INTERVAL: u32 = 1;
pub const JOB_LINKS_INTERVAL: u32 = 1;
pub const JOB_TRANSIENT_INTERVAL: u32 = 60;
pub const JOB_STORE_INTERVAL: u32 = 120;
pub const JOB_PEERSYNC_INTERVAL: u32 = 6;
pub const JOB_PEERINGEST_INTERVAL: u32 = 6;
pub const JOB_ROTATE_INTERVAL: u32 = 56 * JOB_PEERINGEST_INTERVAL;

// Signals and paths
pub const DUPLICATE_SIGNAL: &str = "lxmf_duplicate";
pub const STATS_GET_PATH: &str = "/pn/get/stats";
pub const SYNC_REQUEST_PATH: &str = "/pn/peer/sync";
pub const UNPEER_REQUEST_PATH: &str = "/pn/peer/unpeer";
pub const OFFER_REQUEST_PATH: &str = "/offer";
pub const MESSAGE_GET_PATH: &str = "/get";

// ============================================================
// Peer Constants (LXMPeer.py)
// ============================================================

pub const MAX_UNREACHABLE: u64 = 14 * 24 * 60 * 60; // 14 days
pub const SYNC_BACKOFF_STEP: u64 = 12 * 60; // 12 minutes
pub const PATH_REQUEST_GRACE: f64 = 7.5; // seconds
