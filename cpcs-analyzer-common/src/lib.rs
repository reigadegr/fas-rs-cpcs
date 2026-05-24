#![no_std]

#[repr(u8)]
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum EventKind {
    FramePoint = 1,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Event {
    pub ktime_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub cpu: u32,
    pub kind: u8,
    pub flags: u8,
    pub _pad: [u8; 2],
    pub arg0: u64,
    pub arg1: u64,
}

impl Event {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        ktime_ns: u64,
        pid: u32,
        tid: u32,
        cpu: u32,
        kind: EventKind,
        flags: u8,
        arg0: u64,
        arg1: u64,
    ) -> Self {
        Self {
            ktime_ns,
            pid,
            tid,
            cpu,
            kind: kind as u8,
            flags,
            _pad: [0; 2],
            arg0,
            arg1,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct DagThreadMetrics {
    pub exec_ns: u64,
    pub rq_delay_ns: u64,
    pub futex_wait_ns: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DagThreadMetrics {}
