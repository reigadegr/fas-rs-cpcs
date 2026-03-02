#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_smp_processor_id, bpf_ktime_get_ns},
    macros::{map, tracepoint, uprobe},
    maps::{Array, HashMap, RingBuf},
    programs::{ProbeContext, TracePointContext},
};
use cpcs_analyzer_common::{DagThreadMetrics, Event, EventKind};

const MAX_CPUS: u32 = 32;
const DAG_BANKS: u32 = 8;
const FRAME_SAMPLE_EVERY: u64 = 4;
const DAG_EDGE_MAX: u32 = 65536;
const DAG_THREAD_MAX: u32 = 32768;
const INVALID_POLICY: u32 = u32::MAX;
const EXEC_MIN_NS: u64 = 30_000;
const RQ_MIN_NS: u64 = 20_000;
const FUTEX_MIN_NS: u64 = 100_000;

#[map]
static FRAME_RING: RingBuf = RingBuf::with_byte_size(0x4000, 0);

#[map]
static TARGET_TGID: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static TARGET_TIDS: HashMap<u32, u8> = HashMap::with_max_entries(32768, 0);

#[map]
static DAG_ACTIVE_BANK: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static BANK_FRAME_ID: Array<u64> = Array::with_max_entries(DAG_BANKS, 0);

#[map]
static CPU_TO_POLICY: Array<u32> = Array::with_max_entries(MAX_CPUS, 0);

#[map]
static FRAME_ID: Array<u64> = Array::with_max_entries(1, 0);

#[map]
static SAMPLE_ACTIVE: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static RUNNING_TID: Array<u32> = Array::with_max_entries(MAX_CPUS, 0);

#[map]
static RUNNING_START_NS: Array<u64> = Array::with_max_entries(MAX_CPUS, 0);

#[repr(C)]
#[derive(Copy, Clone)]
struct DagWakeInfo {
    ktime_ns: u64,
    waker_tid: u32,
    sampled: u32,
}

#[map]
static DAG_LAST_WAKEUP: HashMap<u32, DagWakeInfo> = HashMap::with_max_entries(DAG_THREAD_MAX, 0);

#[map]
static DAG_THREAD_POLICY_STATS_0: HashMap<u64, DagThreadMetrics> =
    HashMap::with_max_entries(DAG_THREAD_MAX, 0);
#[map]
static DAG_THREAD_POLICY_STATS_1: HashMap<u64, DagThreadMetrics> =
    HashMap::with_max_entries(DAG_THREAD_MAX, 0);
#[map]
static DAG_THREAD_POLICY_STATS_2: HashMap<u64, DagThreadMetrics> =
    HashMap::with_max_entries(DAG_THREAD_MAX, 0);
#[map]
static DAG_THREAD_POLICY_STATS_3: HashMap<u64, DagThreadMetrics> =
    HashMap::with_max_entries(DAG_THREAD_MAX, 0);
#[map]
static DAG_THREAD_POLICY_STATS_4: HashMap<u64, DagThreadMetrics> =
    HashMap::with_max_entries(DAG_THREAD_MAX, 0);
#[map]
static DAG_THREAD_POLICY_STATS_5: HashMap<u64, DagThreadMetrics> =
    HashMap::with_max_entries(DAG_THREAD_MAX, 0);
#[map]
static DAG_THREAD_POLICY_STATS_6: HashMap<u64, DagThreadMetrics> =
    HashMap::with_max_entries(DAG_THREAD_MAX, 0);
#[map]
static DAG_THREAD_POLICY_STATS_7: HashMap<u64, DagThreadMetrics> =
    HashMap::with_max_entries(DAG_THREAD_MAX, 0);
#[map]
static DAG_EDGE_0: HashMap<u64, u64> = HashMap::with_max_entries(DAG_EDGE_MAX, 0);
#[map]
static DAG_EDGE_1: HashMap<u64, u64> = HashMap::with_max_entries(DAG_EDGE_MAX, 0);
#[map]
static DAG_EDGE_2: HashMap<u64, u64> = HashMap::with_max_entries(DAG_EDGE_MAX, 0);
#[map]
static DAG_EDGE_3: HashMap<u64, u64> = HashMap::with_max_entries(DAG_EDGE_MAX, 0);
#[map]
static DAG_EDGE_4: HashMap<u64, u64> = HashMap::with_max_entries(DAG_EDGE_MAX, 0);
#[map]
static DAG_EDGE_5: HashMap<u64, u64> = HashMap::with_max_entries(DAG_EDGE_MAX, 0);
#[map]
static DAG_EDGE_6: HashMap<u64, u64> = HashMap::with_max_entries(DAG_EDGE_MAX, 0);
#[map]
static DAG_EDGE_7: HashMap<u64, u64> = HashMap::with_max_entries(DAG_EDGE_MAX, 0);

#[repr(C)]
#[derive(Copy, Clone)]
struct PendingWait {
    start_ns: u64,
    uaddr: u64,
    cpu: u32,
    sampled: u32,
}

#[map]
static PENDING_WAIT: HashMap<u32, PendingWait> = HashMap::with_max_entries(32768, 0);

#[repr(C)]
#[derive(Copy, Clone)]
struct WakeByAddr {
    ktime_ns: u64,
    cpu: u32,
    waker_tid: u32,
    sampled: u32,
}

#[map]
static WAKE_BY_ADDR: HashMap<u64, WakeByAddr> = HashMap::with_max_entries(32768, 0);

#[uprobe]
pub fn frame_point(ctx: ProbeContext) -> u32 {
    match emit_event(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn emit_event(_ctx: ProbeContext) -> Result<u32, u32> {
    if !allow_current_task() {
        return Ok(0);
    }

    let now = unsafe { bpf_ktime_get_ns() };
    let prev_frame = current_frame_id();
    let next_frame = prev_frame.wrapping_add(1);
    set_frame_id(next_frame);

    let closed_bank = dag_active_bank();
    if prev_frame > 0 {
        let sample_prev = should_sample_frame(prev_frame);
        split_running_exec_dag(now, closed_bank, sample_prev);
        if sample_prev {
            set_bank_frame_id(closed_bank, prev_frame);
            set_dag_active_bank((closed_bank + 1) % DAG_BANKS);
            emit_simple_event(EventKind::FramePoint, next_frame, closed_bank as u64, 0);
        }
    }
    set_sample_active(should_sample_frame(next_frame));

    Ok(0)
}

fn should_sample_frame(frame_id: u64) -> bool {
    if frame_id == 0 {
        return false;
    }
    if FRAME_SAMPLE_EVERY <= 1 {
        return true;
    }
    frame_id.wrapping_add(1) % FRAME_SAMPLE_EVERY == 0
}

fn sampling_enabled() -> bool {
    SAMPLE_ACTIVE.get(0).copied().unwrap_or(0) != 0
}

fn set_sample_active(enabled: bool) {
    if let Some(ptr) = SAMPLE_ACTIVE.get_ptr_mut(0) {
        unsafe {
            *ptr = if enabled { 1 } else { 0 };
        }
    }
}

#[repr(C)]
struct TraceEntry {
    _type: u16,
    _flags: u8,
    _preempt_count: u8,
    _pid: i32,
}

#[repr(C)]
struct SchedSwitchArgs {
    _common: TraceEntry,
    _prev_comm: [u8; 16],
    prev_pid: i32,
    _prev_prio: i32,
    _prev_state: i64,
    _next_comm: [u8; 16],
    next_pid: i32,
    _next_prio: i32,
}

#[repr(C)]
struct SchedWakeupArgs {
    _common: TraceEntry,
    _comm: [u8; 16],
    pid: i32,
    _prio: i32,
    _success: i32,
    _target_cpu: i32,
}

#[tracepoint]
pub fn sched_switch(ctx: TracePointContext) -> u32 {
    match try_sched_switch(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sched_switch(ctx: TracePointContext) -> Result<u32, u32> {
    let args = unsafe { ctx.read_at::<SchedSwitchArgs>(0).map_err(|_| 1u32)? };
    let prev_tid = args.prev_pid as u32;
    let next_tid = args.next_pid as u32;
    if !allow_sched_pair(prev_tid, next_tid) {
        return Ok(0);
    }

    let now = unsafe { bpf_ktime_get_ns() };
    let cpu = unsafe { bpf_get_smp_processor_id() } as u32;
    let bank = dag_active_bank();
    let sample = sampling_enabled();

    if is_target_tid(prev_tid) && valid_cpu(cpu) {
        let running_tid = RUNNING_TID.get(cpu).copied().unwrap_or(0);
        if running_tid == prev_tid {
            let start_ns = RUNNING_START_NS.get(cpu).copied().unwrap_or(0);
            if start_ns > 0 && now > start_ns {
                if sample {
                    dag_add_thread_exec(bank, prev_tid, cpu, now - start_ns);
                }
            }
        }
        set_array_u32(&RUNNING_TID, cpu, 0);
        set_array_u64(&RUNNING_START_NS, cpu, 0);
    }

    if is_target_tid(next_tid) && valid_cpu(cpu) {
        if let Some(wake_ptr) = DAG_LAST_WAKEUP.get_ptr(&next_tid) {
            let wake = unsafe { *wake_ptr };
            if now > wake.ktime_ns {
                let delay = now - wake.ktime_ns;
                if sample && wake.sampled != 0 {
                    dag_add_thread_rq(bank, next_tid, cpu, delay);
                    dag_add_edge(bank, wake.waker_tid, next_tid, delay);
                }
            }
            let _ = DAG_LAST_WAKEUP.remove(&next_tid);
        }
        set_array_u32(&RUNNING_TID, cpu, next_tid);
        set_array_u64(&RUNNING_START_NS, cpu, now);
    }

    Ok(0)
}

#[tracepoint]
pub fn sched_wakeup(ctx: TracePointContext) -> u32 {
    match try_sched_wakeup(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sched_wakeup(ctx: TracePointContext) -> Result<u32, u32> {
    let args = unsafe { ctx.read_at::<SchedWakeupArgs>(0).map_err(|_| 1u32)? };
    let waker_tid = current_tid();
    let wakee_tid = args.pid as u32;
    if !allow_sched_pair(waker_tid, wakee_tid) {
        return Ok(0);
    }

    if is_target_tid(wakee_tid) {
        let wake = DagWakeInfo {
            ktime_ns: unsafe { bpf_ktime_get_ns() },
            waker_tid,
            sampled: if sampling_enabled() { 1 } else { 0 },
        };
        let _ = DAG_LAST_WAKEUP.insert(&wakee_tid, &wake, 0);
    }

    Ok(0)
}

#[repr(C)]
struct RawSysEnterArgs {
    _common: TraceEntry,
    id: i64,
    args: [u64; 6],
}

#[repr(C)]
struct RawSysExitArgs {
    _common: TraceEntry,
    id: i64,
    ret: i64,
}

#[repr(C)]
struct SysEnterFutexArgs {
    _common: TraceEntry,
    _syscall_nr: i64,
    uaddr: u64,
    op: u64,
    val: u64,
    _utime: u64,
    _uaddr2: u64,
    _val3: u64,
}

#[repr(C)]
struct SysExitFutexArgs {
    _common: TraceEntry,
    _syscall_nr: i64,
    ret: i64,
}

const FUTEX_NR_AARCH64: i64 = 98;
const FUTEX_CMD_MASK: u32 = 0x7f;
const FUTEX_WAIT: u32 = 0;
const FUTEX_WAKE: u32 = 1;
const FUTEX_WAIT_BITSET: u32 = 9;
const FUTEX_WAKE_BITSET: u32 = 10;

#[tracepoint]
pub fn raw_sys_enter(ctx: TracePointContext) -> u32 {
    match try_raw_sys_enter(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_raw_sys_enter(ctx: TracePointContext) -> Result<u32, u32> {
    if !allow_current_task() {
        return Ok(0);
    }
    let args = unsafe { ctx.read_at::<RawSysEnterArgs>(0).map_err(|_| 1u32)? };
    if args.id != FUTEX_NR_AARCH64 {
        return Ok(0);
    }

    handle_futex_enter_dag(args.args[0], args.args[1] as u32, args.args[2]);
    Ok(0)
}

#[tracepoint]
pub fn raw_sys_exit(ctx: TracePointContext) -> u32 {
    match try_raw_sys_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_raw_sys_exit(ctx: TracePointContext) -> Result<u32, u32> {
    if !allow_current_task() {
        return Ok(0);
    }
    let args = unsafe { ctx.read_at::<RawSysExitArgs>(0).map_err(|_| 1u32)? };
    if args.id != FUTEX_NR_AARCH64 {
        return Ok(0);
    }
    handle_futex_exit_dag(args.ret as u64);
    Ok(0)
}

#[tracepoint]
pub fn sys_enter_futex(ctx: TracePointContext) -> u32 {
    match try_sys_enter_futex(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_enter_futex(ctx: TracePointContext) -> Result<u32, u32> {
    if !allow_current_task() {
        return Ok(0);
    }
    let args = unsafe { ctx.read_at::<SysEnterFutexArgs>(0).map_err(|_| 1u32)? };
    handle_futex_enter_dag(args.uaddr, args.op as u32, args.val);
    Ok(0)
}

#[tracepoint]
pub fn sys_exit_futex(ctx: TracePointContext) -> u32 {
    match try_sys_exit_futex(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sys_exit_futex(ctx: TracePointContext) -> Result<u32, u32> {
    if !allow_current_task() {
        return Ok(0);
    }
    let args = unsafe { ctx.read_at::<SysExitFutexArgs>(0).map_err(|_| 1u32)? };
    handle_futex_exit_dag(args.ret as u64);
    Ok(0)
}

fn handle_futex_enter_dag(uaddr: u64, op: u32, _val: u64) {
    let cmd = op & FUTEX_CMD_MASK;
    if cmd == FUTEX_WAIT || cmd == FUTEX_WAIT_BITSET {
        let pending = PendingWait {
            start_ns: unsafe { bpf_ktime_get_ns() },
            uaddr,
            cpu: unsafe { bpf_get_smp_processor_id() } as u32,
            sampled: if sampling_enabled() { 1 } else { 0 },
        };
        let tid = current_tid();
        let _ = PENDING_WAIT.insert(&tid, &pending, 0);
    } else if cmd == FUTEX_WAKE || cmd == FUTEX_WAKE_BITSET {
        let wake = WakeByAddr {
            ktime_ns: unsafe { bpf_ktime_get_ns() },
            cpu: unsafe { bpf_get_smp_processor_id() } as u32,
            waker_tid: current_tid(),
            sampled: if sampling_enabled() { 1 } else { 0 },
        };
        let _ = WAKE_BY_ADDR.insert(&uaddr, &wake, 0);
    }
}

fn handle_futex_exit_dag(_ret: u64) {
    let tid = current_tid();
    let Some(ptr) = PENDING_WAIT.get_ptr(&tid) else {
        return;
    };
    let pending = unsafe { *ptr };
    let _ = PENDING_WAIT.remove(&tid);

    let now = unsafe { bpf_ktime_get_ns() };
    if now <= pending.start_ns {
        return;
    }

    let wait_ns = now - pending.start_ns;
    let bank = dag_active_bank();
    let sample = sampling_enabled() && pending.sampled != 0;

    let wake = WAKE_BY_ADDR
        .get_ptr(&pending.uaddr)
        .map(|wake_ptr| unsafe { *wake_ptr });

    let mut attr_cpu = pending.cpu;
    if let Some(wake) = wake {
        if wake.ktime_ns >= pending.start_ns && wake.ktime_ns <= now {
            attr_cpu = wake.cpu;
            if sample && wake.sampled != 0 {
                dag_add_edge(bank, wake.waker_tid, tid, wait_ns);
            }
        }
    }
    if sample {
        dag_add_thread_futex(bank, tid, attr_cpu, wait_ns);
    }
}

fn split_running_exec_dag(now: u64, bank: u32, sample: bool) {
    let mut cpu = 0u32;
    while cpu < MAX_CPUS {
        let tid = RUNNING_TID.get(cpu).copied().unwrap_or(0);
        if tid != 0 {
            let start_ns = RUNNING_START_NS.get(cpu).copied().unwrap_or(0);
            if start_ns > 0 && now > start_ns {
                if sample {
                    dag_add_thread_exec(bank, tid, cpu, now - start_ns);
                }
            }
            set_array_u64(&RUNNING_START_NS, cpu, now);
        }
        cpu += 1;
    }
}

fn current_frame_id() -> u64 {
    FRAME_ID.get(0).copied().unwrap_or(0)
}

fn dag_active_bank() -> u32 {
    DAG_ACTIVE_BANK.get(0).copied().unwrap_or(0) % DAG_BANKS
}

fn set_frame_id(frame_id: u64) {
    if let Some(ptr) = FRAME_ID.get_ptr_mut(0) {
        unsafe {
            *ptr = frame_id;
        }
    }
}

fn set_dag_active_bank(bank: u32) {
    if let Some(ptr) = DAG_ACTIVE_BANK.get_ptr_mut(0) {
        unsafe {
            *ptr = bank % DAG_BANKS;
        }
    }
}

fn set_bank_frame_id(bank: u32, frame_id: u64) {
    if bank >= DAG_BANKS {
        return;
    }
    if let Some(ptr) = BANK_FRAME_ID.get_ptr_mut(bank) {
        unsafe {
            *ptr = frame_id;
        }
    }
}

#[inline]
fn valid_cpu(cpu: u32) -> bool {
    cpu < MAX_CPUS
}

fn set_array_u64(map: &Array<u64>, idx: u32, val: u64) {
    if !valid_cpu(idx) {
        return;
    }
    if let Some(ptr) = map.get_ptr_mut(idx) {
        unsafe {
            *ptr = val;
        }
    }
}

fn set_array_u32(map: &Array<u32>, idx: u32, val: u32) {
    if !valid_cpu(idx) {
        return;
    }
    if let Some(ptr) = map.get_ptr_mut(idx) {
        unsafe {
            *ptr = val;
        }
    }
}

fn dag_add_thread_exec(bank: u32, tid: u32, cpu: u32, delta: u64) {
    let Some(policy) = cpu_to_policy(cpu) else {
        return;
    };
    let key = pack_tid_policy(tid, policy);
    match bank {
        0 => add_hash_thread_exec(&DAG_THREAD_POLICY_STATS_0, key, delta),
        1 => add_hash_thread_exec(&DAG_THREAD_POLICY_STATS_1, key, delta),
        2 => add_hash_thread_exec(&DAG_THREAD_POLICY_STATS_2, key, delta),
        3 => add_hash_thread_exec(&DAG_THREAD_POLICY_STATS_3, key, delta),
        4 => add_hash_thread_exec(&DAG_THREAD_POLICY_STATS_4, key, delta),
        5 => add_hash_thread_exec(&DAG_THREAD_POLICY_STATS_5, key, delta),
        6 => add_hash_thread_exec(&DAG_THREAD_POLICY_STATS_6, key, delta),
        7 => add_hash_thread_exec(&DAG_THREAD_POLICY_STATS_7, key, delta),
        _ => {}
    }
}

fn dag_add_thread_rq(bank: u32, tid: u32, cpu: u32, delta: u64) {
    let Some(policy) = cpu_to_policy(cpu) else {
        return;
    };
    let key = pack_tid_policy(tid, policy);
    match bank {
        0 => add_hash_thread_rq(&DAG_THREAD_POLICY_STATS_0, key, delta),
        1 => add_hash_thread_rq(&DAG_THREAD_POLICY_STATS_1, key, delta),
        2 => add_hash_thread_rq(&DAG_THREAD_POLICY_STATS_2, key, delta),
        3 => add_hash_thread_rq(&DAG_THREAD_POLICY_STATS_3, key, delta),
        4 => add_hash_thread_rq(&DAG_THREAD_POLICY_STATS_4, key, delta),
        5 => add_hash_thread_rq(&DAG_THREAD_POLICY_STATS_5, key, delta),
        6 => add_hash_thread_rq(&DAG_THREAD_POLICY_STATS_6, key, delta),
        7 => add_hash_thread_rq(&DAG_THREAD_POLICY_STATS_7, key, delta),
        _ => {}
    }
}

fn dag_add_thread_futex(bank: u32, tid: u32, cpu: u32, delta: u64) {
    let Some(policy) = cpu_to_policy(cpu) else {
        return;
    };
    let key = pack_tid_policy(tid, policy);
    match bank {
        0 => add_hash_thread_futex(&DAG_THREAD_POLICY_STATS_0, key, delta),
        1 => add_hash_thread_futex(&DAG_THREAD_POLICY_STATS_1, key, delta),
        2 => add_hash_thread_futex(&DAG_THREAD_POLICY_STATS_2, key, delta),
        3 => add_hash_thread_futex(&DAG_THREAD_POLICY_STATS_3, key, delta),
        4 => add_hash_thread_futex(&DAG_THREAD_POLICY_STATS_4, key, delta),
        5 => add_hash_thread_futex(&DAG_THREAD_POLICY_STATS_5, key, delta),
        6 => add_hash_thread_futex(&DAG_THREAD_POLICY_STATS_6, key, delta),
        7 => add_hash_thread_futex(&DAG_THREAD_POLICY_STATS_7, key, delta),
        _ => {}
    }
}

fn dag_add_edge(bank: u32, pred: u32, succ: u32, delta: u64) {
    if pred == 0 || succ == 0 || pred == succ || delta == 0 {
        return;
    }
    let key = ((pred as u64) << 32) | succ as u64;
    match bank {
        0 => add_hash_u64_u64(&DAG_EDGE_0, key, delta),
        1 => add_hash_u64_u64(&DAG_EDGE_1, key, delta),
        2 => add_hash_u64_u64(&DAG_EDGE_2, key, delta),
        3 => add_hash_u64_u64(&DAG_EDGE_3, key, delta),
        4 => add_hash_u64_u64(&DAG_EDGE_4, key, delta),
        5 => add_hash_u64_u64(&DAG_EDGE_5, key, delta),
        6 => add_hash_u64_u64(&DAG_EDGE_6, key, delta),
        7 => add_hash_u64_u64(&DAG_EDGE_7, key, delta),
        _ => {}
    }
}

fn cpu_to_policy(cpu: u32) -> Option<u32> {
    if !valid_cpu(cpu) {
        return None;
    }
    let p = CPU_TO_POLICY.get(cpu).copied().unwrap_or(INVALID_POLICY);
    if p == INVALID_POLICY { None } else { Some(p) }
}

fn pack_tid_policy(tid: u32, policy: u32) -> u64 {
    ((tid as u64) << 32) | policy as u64
}

fn add_hash_u64_u64(map: &HashMap<u64, u64>, key: u64, delta: u64) {
    if let Some(ptr) = map.get_ptr_mut(&key) {
        unsafe {
            let cur = *ptr;
            *ptr = cur.saturating_add(delta);
        }
    } else {
        let _ = map.insert(&key, &delta, 0);
    }
}

fn add_hash_thread_exec(map: &HashMap<u64, DagThreadMetrics>, key: u64, delta: u64) {
    if delta < EXEC_MIN_NS {
        return;
    }
    if let Some(ptr) = map.get_ptr_mut(&key) {
        unsafe {
            (*ptr).exec_ns = (*ptr).exec_ns.saturating_add(delta);
        }
    } else {
        let value = DagThreadMetrics {
            exec_ns: delta,
            rq_delay_ns: 0,
            futex_wait_ns: 0,
        };
        let _ = map.insert(&key, &value, 0);
    }
}

fn add_hash_thread_rq(map: &HashMap<u64, DagThreadMetrics>, key: u64, delta: u64) {
    if delta < RQ_MIN_NS {
        return;
    }
    if let Some(ptr) = map.get_ptr_mut(&key) {
        unsafe {
            (*ptr).rq_delay_ns = (*ptr).rq_delay_ns.saturating_add(delta);
        }
    } else {
        let value = DagThreadMetrics {
            exec_ns: 0,
            rq_delay_ns: delta,
            futex_wait_ns: 0,
        };
        let _ = map.insert(&key, &value, 0);
    }
}

fn add_hash_thread_futex(map: &HashMap<u64, DagThreadMetrics>, key: u64, delta: u64) {
    if delta < FUTEX_MIN_NS {
        return;
    }
    if let Some(ptr) = map.get_ptr_mut(&key) {
        unsafe {
            (*ptr).futex_wait_ns = (*ptr).futex_wait_ns.saturating_add(delta);
        }
    } else {
        let value = DagThreadMetrics {
            exec_ns: 0,
            rq_delay_ns: 0,
            futex_wait_ns: delta,
        };
        let _ = map.insert(&key, &value, 0);
    }
}

fn emit_simple_event(kind: EventKind, arg0: u64, arg1: u64, flags: u8) {
    if let Some(mut entry) = FRAME_RING.reserve::<Event>(0) {
        let ktime_ns = unsafe { bpf_ktime_get_ns() };
        let pid_tgid = bpf_get_current_pid_tgid();
        let pid = (pid_tgid >> 32) as u32;
        let tid = pid_tgid as u32;
        let cpu = unsafe { bpf_get_smp_processor_id() } as u32;
        entry.write(Event::new(ktime_ns, pid, tid, cpu, kind, flags, arg0, arg1));
        entry.submit(0);
    }
}

fn target_tgid() -> u32 {
    TARGET_TGID.get(0).copied().unwrap_or(0)
}

fn current_tgid_tid() -> (u32, u32) {
    let pid_tgid = bpf_get_current_pid_tgid();
    ((pid_tgid >> 32) as u32, pid_tgid as u32)
}

fn current_tid() -> u32 {
    current_tgid_tid().1
}

fn is_target_tid(tid: u32) -> bool {
    unsafe { TARGET_TIDS.get(&tid) }.is_some()
}

fn mark_target_tid(tid: u32) {
    if unsafe { TARGET_TIDS.get(&tid) }.is_none() {
        let _ = TARGET_TIDS.insert(&tid, &1u8, 0);
    }
}

fn allow_current_task() -> bool {
    let filter_tgid = target_tgid();
    if filter_tgid == 0 {
        return true;
    }
    let (tgid, tid) = current_tgid_tid();
    if tgid == filter_tgid {
        mark_target_tid(tid);
        return true;
    }
    is_target_tid(tid)
}

fn allow_sched_pair(a_tid: u32, b_tid: u32) -> bool {
    let filter_tgid = target_tgid();
    if filter_tgid == 0 {
        return true;
    }
    if is_target_tid(a_tid) || is_target_tid(b_tid) {
        return true;
    }
    let (tgid, tid) = current_tgid_tid();
    if tgid == filter_tgid {
        mark_target_tid(tid);
        return true;
    }
    false
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
