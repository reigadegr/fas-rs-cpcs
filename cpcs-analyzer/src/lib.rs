use std::{
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
    fs,
    os::fd::AsRawFd,
    path::Path,
    ptr,
    sync::mpsc::RecvTimeoutError,
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow};
use aya::{
    Ebpf, include_bytes_aligned,
    maps::{Array, HashMap as UserHashMap, MapData, RingBuf},
    programs::{TracePoint, UProbe},
};
use cpcs_analyzer_common::{Event, EventKind};
use ctor::ctor;
use log::{info, warn};
use mio::{Events, Interest, Poll, Token, event::Event as MioEvent, unix::SourceFd};

pub type Pid = i32;

const EVENT_MAX: usize = 1024;
const MAX_CPUS: u32 = 32;
const INVALID_POLICY: u32 = u32::MAX;

const DEFAULT_UPROBE_SYMBOL: &str =
    "_ZN7android7Surface11queueBufferEP19ANativeWindowBufferiPNS_24SurfaceQueueBufferOutputE";
const LEGACY_UPROBE_SYMBOL: &str = "_ZN7android7Surface11queueBufferEP19ANativeWindowBufferi";
const DEFAULT_UPROBE_LIB: &str = "/system/lib64/libgui.so";

#[ctor]
fn ebpf_workaround() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    unsafe {
        libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim);
    }
}

#[derive(Debug, Clone)]
pub struct PolicyWeights {
    pub pid: i32,
    pub frame_id: u64,
    pub confidence: f64,
    pub policy_weights: HashMap<i32, f64>,
}

#[derive(Debug, Clone)]
pub struct TimedPolicyWeights {
    pub received_at: Instant,
    pub data: PolicyWeights,
}

#[derive(Debug, Clone)]
pub struct AnalyzerConfig {
    pub uprobe_symbol: String,
    pub uprobe_lib: String,
    pub ema_lambda: f64,
    pub rq_weight: f64,
    pub futex_weight: f64,
    pub exec_weight: f64,
    pub subgraph_slack_ns: u64,
    pub subgraph_tau_ns: u64,
    pub norm_mix: f64,
    pub min_cluster_weight: f64,
    pub stale_timeout: Duration,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            uprobe_symbol: DEFAULT_UPROBE_SYMBOL.to_string(),
            uprobe_lib: DEFAULT_UPROBE_LIB.to_string(),
            ema_lambda: 0.8,
            // Runqueue delay is retained for diagnosis, but does not directly
            // participate in DVFS weight scoring by default.
            rq_weight: 0.0,
            // Futex time remains part of DAG/critical-subgraph extraction, but
            // does not directly participate in DVFS weight scoring.
            futex_weight: 0.0,
            exec_weight: 0.75,
            subgraph_slack_ns: 300_000,
            subgraph_tau_ns: 300_000,
            norm_mix: 0.3,
            min_cluster_weight: 0.05,
            // Keep last CPCS weights a bit longer to avoid control jitter when
            // analyzer updates are briefly sparse on some devices.
            stale_timeout: Duration::from_secs(2),
        }
    }
}

pub struct Analyzer {
    poll: Option<Poll>,
    map: HashMap<Pid, AnalyzeTarget>,
    buffer: VecDeque<Pid>,
    latest: HashMap<Pid, TimedPolicyWeights>,
    cfg: AnalyzerConfig,
    cpu_policy: HashMap<u32, u32>,
    policy_ids: Vec<u32>,
    policy_capacity: HashMap<u32, f64>,
}

impl Analyzer {
    pub fn new() -> Result<Self> {
        Self::with_config(AnalyzerConfig::default())
    }

    pub fn with_config(cfg: AnalyzerConfig) -> Result<Self> {
        validate_config(&cfg)?;
        let cpu_policy = load_cpu_policy_map()?;
        let policy_ids = sorted_policies(&cpu_policy);
        let policy_capacity = load_policy_capacity(&cpu_policy)?;

        Ok(Self {
            poll: None,
            map: HashMap::new(),
            buffer: VecDeque::with_capacity(EVENT_MAX),
            latest: HashMap::new(),
            cfg,
            cpu_policy,
            policy_ids,
            policy_capacity,
        })
    }

    pub fn attach_app(&mut self, pid: i32) -> Result<()> {
        if self.contains(pid) {
            return Ok(());
        }

        let target = AnalyzeTarget::new(
            pid,
            self.cfg.clone(),
            self.cpu_policy.clone(),
            self.policy_ids.clone(),
            self.policy_capacity.clone(),
        )?;
        self.map.insert(pid, target);
        self.register_poll()?;

        Ok(())
    }

    pub fn detach_app(&mut self, pid: i32) -> Result<()> {
        if !self.contains(pid) {
            return Ok(());
        }

        self.map.remove(&pid);
        self.buffer.retain(|buffer_pid| *buffer_pid != pid);
        self.latest.remove(&pid);
        self.register_poll()?;

        Ok(())
    }

    pub fn detach_apps(&mut self) {
        self.map.clear();
        self.buffer.clear();
        self.latest.clear();
        self.poll = None;
    }

    pub fn recv_timeout(
        &mut self,
        timeout: Duration,
    ) -> std::result::Result<(i32, PolicyWeights), RecvTimeoutError> {
        let deadline = Instant::now() + timeout;
        let mut polled_once = false;

        loop {
            // Some Android kernels/userspace combos do not reliably surface ringbuf
            // readiness via poll for eBPF maps. Probe each attached ring once so we
            // can still make progress even when poll misses notifications.
            let direct_pids: Vec<_> = self.map.keys().copied().collect();
            for pid in direct_pids {
                if let Some(weights) = self.process_pid_update(pid) {
                    return Ok((pid, weights));
                }
            }

            while let Some(pid) = self.buffer.pop_front() {
                if let Some(weights) = self.process_pid_update(pid) {
                    return Ok((pid, weights));
                }
            }

            let now = Instant::now();
            let timed_out = now >= deadline;
            if timed_out && polled_once {
                return Err(RecvTimeoutError::Timeout);
            }

            let remain = if timed_out {
                Duration::ZERO
            } else {
                deadline.duration_since(now)
            };
            let mut events = Events::with_capacity(EVENT_MAX);
            let Some(poll) = self.poll.as_mut() else {
                return Err(RecvTimeoutError::Timeout);
            };

            match poll.poll(&mut events, Some(remain)) {
                Ok(()) => {
                    polled_once = true;
                    if events.is_empty() {
                        if timed_out {
                            return Err(RecvTimeoutError::Timeout);
                        }
                        continue;
                    }
                    self.buffer.extend(events.iter().map(event_to_pid));
                }
                Err(_) => return Err(RecvTimeoutError::Disconnected),
            }
        }
    }

    pub fn latest_for(&self, pid: i32) -> Option<&PolicyWeights> {
        let item = self.latest.get(&pid)?;
        if item.received_at.elapsed() > self.cfg.stale_timeout {
            return None;
        }
        Some(&item.data)
    }

    #[must_use]
    pub fn contains(&self, pid: Pid) -> bool {
        self.map.contains_key(&pid)
    }

    pub fn pids(&self) -> impl Iterator<Item = Pid> + '_ {
        self.map.keys().copied()
    }

    fn register_poll(&mut self) -> Result<()> {
        if self.map.is_empty() {
            self.poll = None;
            return Ok(());
        }

        let poll = Poll::new()?;

        for (pid, handler) in &mut self.map {
            poll.registry().register(
                &mut SourceFd(&handler.ring.as_raw_fd()),
                Token(*pid as usize),
                Interest::READABLE,
            )?;
        }

        self.poll = Some(poll);
        Ok(())
    }

    fn process_pid_update(&mut self, pid: i32) -> Option<PolicyWeights> {
        let update_result = {
            let target = self.map.get_mut(&pid)?;
            target.update()
        };

        match update_result {
            Ok(Some(weights)) => {
                self.latest.insert(
                    pid,
                    TimedPolicyWeights {
                        received_at: Instant::now(),
                        data: weights.clone(),
                    },
                );
                Some(weights)
            }
            Ok(None) => None,
            Err(e) => {
                warn!("cpcs update failed for pid={pid}: {e:#}");
                let _ = self.detach_app(pid);
                None
            }
        }
    }
}

fn validate_config(cfg: &AnalyzerConfig) -> Result<()> {
    if !(0.0..=1.0).contains(&cfg.ema_lambda) {
        return Err(anyhow!("ema_lambda must be in [0, 1]"));
    }
    if !(0.0..=1.0).contains(&cfg.norm_mix) {
        return Err(anyhow!("norm_mix must be in [0, 1]"));
    }
    if cfg.rq_weight < 0.0 || cfg.futex_weight < 0.0 || cfg.exec_weight < 0.0 {
        return Err(anyhow!("rq/futex/exec weights must be >= 0"));
    }
    if cfg.rq_weight + cfg.exec_weight <= 0.0 {
        return Err(anyhow!("at least one of rq/exec weight must be > 0"));
    }
    if cfg.subgraph_tau_ns == 0 {
        return Err(anyhow!("subgraph_tau_ns must be > 0"));
    }
    if cfg.min_cluster_weight < 0.0 {
        return Err(anyhow!("min_cluster_weight must be >= 0"));
    }
    Ok(())
}

struct AnalyzeTarget {
    pid: i32,
    uprobe: UprobeHandler,
    ring: RingBuf<MapData>,
    cfg: AnalyzerConfig,
    policy_ids: Vec<u32>,
    policy_capacity: HashMap<u32, f64>,
    ema_scores: HashMap<u32, f64>,
}

impl AnalyzeTarget {
    fn new(
        pid: i32,
        cfg: AnalyzerConfig,
        cpu_policy: HashMap<u32, u32>,
        policy_ids: Vec<u32>,
        policy_capacity: HashMap<u32, f64>,
    ) -> Result<Self> {
        let mut uprobe = UprobeHandler::attach_app(pid, &cfg)?;

        init_target_filters(uprobe.bpf_mut(), Some(pid as u32))?;
        init_cpu_policy_filters(uprobe.bpf_mut(), &cpu_policy)?;
        init_dag_bank(uprobe.bpf_mut())?;
        let ring = uprobe.take_ring()?;

        let mut ema_scores = HashMap::new();
        for policy in &policy_ids {
            ema_scores.insert(*policy, 0.0);
        }

        Ok(Self {
            pid,
            uprobe,
            ring,
            cfg,
            policy_ids,
            policy_capacity,
            ema_scores,
        })
    }

    fn update(&mut self) -> Result<Option<PolicyWeights>> {
        let Some(item) = self.ring.next() else {
            return Ok(None);
        };
        let event = unsafe { trans(&item) };

        if event.kind != EventKind::FramePoint as u8 {
            return Ok(None);
        }

        let closed_frame_id = event.arg0.saturating_sub(1);
        if closed_frame_id == 0 {
            return Ok(None);
        }

        let bank = (event.arg1 & 1) as u32;
        let frame = collect_dag_frame(self.uprobe.bpf_mut(), closed_frame_id, bank)?;
        let cp = infer_critical_subgraph(
            &frame,
            event.tid,
            self.cfg.subgraph_slack_ns,
            self.cfg.subgraph_tau_ns,
        );

        let critical_stats = critical_subgraph_to_frame_stats(&frame, &cp);
        let rows = analyze_cluster_weights(
            &critical_stats,
            &self.policy_ids,
            &self.policy_capacity,
            &mut self.ema_scores,
            self.cfg.ema_lambda,
            self.cfg.rq_weight,
            self.cfg.futex_weight,
            self.cfg.exec_weight,
            self.cfg.norm_mix,
            self.cfg.min_cluster_weight,
        );

        let mut policy_weights = HashMap::new();
        for row in rows {
            policy_weights.insert(row.policy as i32, row.weight);
        }
        if policy_weights.is_empty() {
            return Ok(None);
        }

        Ok(Some(PolicyWeights {
            pid: self.pid,
            frame_id: closed_frame_id,
            confidence: critical_subgraph_confidence(&cp),
            policy_weights,
        }))
    }
}

struct UprobeHandler {
    bpf: Ebpf,
}

impl Drop for UprobeHandler {
    fn drop(&mut self) {
        if let Ok(program) = self.get_uprobe_program() {
            let _ = program.unload();
        }
    }
}

impl UprobeHandler {
    fn attach_app(pid: i32, cfg: &AnalyzerConfig) -> Result<Self> {
        let mut bpf = load_bpf()?;

        attach_frame_uprobe(&mut bpf, pid, cfg)?;
        attach_sched_tracepoints(&mut bpf)?;
        attach_futex_tracepoints(&mut bpf)?;

        Ok(Self { bpf })
    }

    fn take_ring(&mut self) -> Result<RingBuf<MapData>> {
        let ring: RingBuf<MapData> = RingBuf::try_from(self.bpf.take_map("FRAME_RING").unwrap())?;
        Ok(ring)
    }

    fn bpf_mut(&mut self) -> &mut Ebpf {
        &mut self.bpf
    }

    fn get_uprobe_program(&mut self) -> Result<&mut UProbe> {
        let program: &mut UProbe = self.bpf.program_mut("frame_point").unwrap().try_into()?;
        Ok(program)
    }
}

fn load_bpf() -> Result<Ebpf> {
    #[cfg(debug_assertions)]
    let bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ebpf_target/bpfel-unknown-none/debug/cpcs-analyzer"
    )))?;

    #[cfg(not(debug_assertions))]
    let bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ebpf_target/bpfel-unknown-none/release/cpcs-analyzer"
    )))?;

    Ok(bpf)
}

fn attach_frame_uprobe(bpf: &mut Ebpf, pid: i32, cfg: &AnalyzerConfig) -> Result<()> {
    let program: &mut UProbe = bpf.program_mut("frame_point").unwrap().try_into()?;
    program.load()?;

    // Mirror frame-analyzer's proven attach order for Android compatibility.
    let candidates = if cfg.uprobe_symbol != DEFAULT_UPROBE_SYMBOL
        && cfg.uprobe_symbol != LEGACY_UPROBE_SYMBOL
    {
        vec![
            cfg.uprobe_symbol.as_str(),
            LEGACY_UPROBE_SYMBOL,
            DEFAULT_UPROBE_SYMBOL,
        ]
    } else {
        vec![LEGACY_UPROBE_SYMBOL, DEFAULT_UPROBE_SYMBOL]
    };

    let mut seen = HashSet::new();
    let mut last_err = None;
    for symbol in candidates {
        if !seen.insert(symbol) {
            continue;
        }

        match program.attach(Some(symbol), 0, cfg.uprobe_lib.as_str(), Some(pid)) {
            Ok(_) => {
                info!(
                    "cpcs attached frame_point: symbol={} lib={} pid={}",
                    symbol, cfg.uprobe_lib, pid
                );
                return Ok(());
            }
            Err(e) => last_err = Some(e),
        }
    }

    Err(anyhow!(
        "attach frame_point failed: {}",
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown error".to_string())
    ))
}

fn attach_sched_tracepoints(bpf: &mut Ebpf) -> Result<()> {
    let program: &mut TracePoint = bpf.program_mut("sched_switch").unwrap().try_into()?;
    program.load()?;
    program
        .attach("sched", "sched_switch")
        .map_err(|e| anyhow!("attach sched:sched_switch failed: {e}"))?;

    let program: &mut TracePoint = bpf.program_mut("sched_wakeup").unwrap().try_into()?;
    program.load()?;
    program
        .attach("sched", "sched_wakeup")
        .map_err(|e| anyhow!("attach sched:sched_wakeup failed: {e}"))?;

    Ok(())
}

fn attach_futex_tracepoints(bpf: &mut Ebpf) -> Result<()> {
    if let Some((enter_evt, exit_evt)) = find_futex_syscall_pair() {
        let fast_result = (|| -> Result<()> {
            let exit_link = {
                let program: &mut TracePoint =
                    bpf.program_mut("sys_exit_futex").unwrap().try_into()?;
                program.load()?;
                program
                    .attach("syscalls", exit_evt)
                    .map_err(|e| anyhow!("attach syscalls:{exit_evt} failed: {e}"))?
            };

            let enter_result = {
                let program: &mut TracePoint =
                    bpf.program_mut("sys_enter_futex").unwrap().try_into()?;
                program.load()?;
                program
                    .attach("syscalls", enter_evt)
                    .map_err(|e| anyhow!("attach syscalls:{enter_evt} failed: {e}"))
            };

            if let Err(err) = enter_result {
                let program: &mut TracePoint =
                    bpf.program_mut("sys_exit_futex").unwrap().try_into()?;
                let _ = program.detach(exit_link);
                return Err(err);
            }

            Ok(())
        })();

        if fast_result.is_ok() {
            return Ok(());
        }

        if let Err(e) = fast_result {
            warn!("{e}; fallback to raw_syscalls");
        }
    }

    let program: &mut TracePoint = bpf.program_mut("raw_sys_enter").unwrap().try_into()?;
    program.load()?;
    program
        .attach("raw_syscalls", "sys_enter")
        .map_err(|e| anyhow!("attach raw_syscalls:sys_enter failed: {e}"))?;

    let program: &mut TracePoint = bpf.program_mut("raw_sys_exit").unwrap().try_into()?;
    program.load()?;
    program
        .attach("raw_syscalls", "sys_exit")
        .map_err(|e| anyhow!("attach raw_syscalls:sys_exit failed: {e}"))?;

    Ok(())
}

fn find_futex_syscall_pair() -> Option<(&'static str, &'static str)> {
    const CANDIDATES: [(&str, &str); 2] = [
        ("sys_enter_futex", "sys_exit_futex"),
        ("sys_enter_futex_time64", "sys_exit_futex_time64"),
    ];

    for (enter_evt, exit_evt) in CANDIDATES {
        if tracepoint_exists("syscalls", enter_evt) && tracepoint_exists("syscalls", exit_evt) {
            return Some((enter_evt, exit_evt));
        }
    }

    None
}

fn tracepoint_exists(category: &str, name: &str) -> bool {
    const BASES: [&str; 2] = [
        "/sys/kernel/tracing/events",
        "/sys/kernel/debug/tracing/events",
    ];

    for base in BASES {
        let id_path = Path::new(base).join(category).join(name).join("id");
        if id_path.exists() {
            return true;
        }
    }

    false
}

fn init_dag_bank(ebpf: &mut Ebpf) -> Result<()> {
    let mut frame_id: Array<&mut MapData, u64> =
        Array::try_from(ebpf.map_mut("FRAME_ID").unwrap())?;
    frame_id.set(0, 0u64, 0)?;

    let mut dag_active_bank: Array<&mut MapData, u32> =
        Array::try_from(ebpf.map_mut("DAG_ACTIVE_BANK").unwrap())?;
    dag_active_bank.set(0, 0u32, 0)?;

    Ok(())
}

fn init_cpu_policy_filters(ebpf: &mut Ebpf, cpu_policy: &HashMap<u32, u32>) -> Result<()> {
    let mut cpu_to_policy: Array<&mut MapData, u32> =
        Array::try_from(ebpf.map_mut("CPU_TO_POLICY").unwrap())?;

    for cpu in 0..MAX_CPUS {
        cpu_to_policy.set(cpu, INVALID_POLICY, 0)?;
    }

    for (cpu, policy) in cpu_policy {
        if *cpu < MAX_CPUS {
            cpu_to_policy.set(*cpu, *policy, 0)?;
        }
    }

    Ok(())
}

fn init_target_filters(ebpf: &mut Ebpf, pid: Option<u32>) -> Result<()> {
    let mut target_tgid: Array<&mut MapData, u32> =
        Array::try_from(ebpf.map_mut("TARGET_TGID").unwrap())?;
    let tgid = pid.unwrap_or(0);
    target_tgid.set(0, tgid, 0)?;

    let mut target_tids: UserHashMap<&mut MapData, u32, u8> =
        UserHashMap::try_from(ebpf.map_mut("TARGET_TIDS").unwrap())?;
    for tid in list_task_tids(tgid)? {
        let _ = target_tids.insert(tid, 1u8, 0);
    }

    Ok(())
}

fn list_task_tids(pid: u32) -> Result<Vec<u32>> {
    let dir = format!("/proc/{pid}/task");
    let mut tids = Vec::new();

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Ok(tid) = name.parse::<u32>() {
            tids.push(tid);
        }
    }

    Ok(tids)
}

#[derive(Default)]
struct DagFrame {
    thread_exec_ns: HashMap<u32, u64>,
    thread_rq_delay_ns: HashMap<u32, u64>,
    thread_futex_wait_ns: HashMap<u32, u64>,
    thread_policy_exec_ns: HashMap<(u32, u32), u64>,
    thread_policy_rq_delay_ns: HashMap<(u32, u32), u64>,
    thread_policy_futex_wait_ns: HashMap<(u32, u32), u64>,
    edges_ns: HashMap<(u32, u32), u64>,
}

impl DagFrame {
    fn new() -> Self {
        Self::default()
    }

    fn thread_total_ns(&self, tid: u32) -> u64 {
        self.thread_exec_ns.get(&tid).copied().unwrap_or(0)
            + self.thread_rq_delay_ns.get(&tid).copied().unwrap_or(0)
            + self.thread_futex_wait_ns.get(&tid).copied().unwrap_or(0)
    }
}

#[derive(Default)]
struct FrameStats {
    policy_exec_ns: HashMap<u32, u64>,
    policy_rq_delay_ns: HashMap<u32, u64>,
    policy_futex_wait_ns: HashMap<u32, u64>,
}

impl FrameStats {
    fn new() -> Self {
        Self::default()
    }
}

struct CriticalSubgraphResult {
    node_weights: HashMap<u32, f64>,
    best_path_ns: u64,
    node_total_ns: u64,
}

struct PolicyWeightRow {
    policy: u32,
    weight: f64,
    smooth_raw_score: f64,
    smooth_norm_score: f64,
}

fn collect_dag_frame(ebpf: &mut Ebpf, frame_id: u64, bank: u32) -> Result<DagFrame> {
    let _ = frame_id;
    let mut frame = DagFrame::new();

    let (exec_name, rq_name, futex_name, edge_name) = if bank == 0 {
        (
            "DAG_THREAD_POLICY_EXEC_0",
            "DAG_THREAD_POLICY_RQ_0",
            "DAG_THREAD_POLICY_FUTEX_0",
            "DAG_EDGE_0",
        )
    } else {
        (
            "DAG_THREAD_POLICY_EXEC_1",
            "DAG_THREAD_POLICY_RQ_1",
            "DAG_THREAD_POLICY_FUTEX_1",
            "DAG_EDGE_1",
        )
    };

    pull_tid_policy_u64_map(
        ebpf,
        exec_name,
        &mut frame.thread_exec_ns,
        &mut frame.thread_policy_exec_ns,
    )?;
    pull_tid_policy_u64_map(
        ebpf,
        rq_name,
        &mut frame.thread_rq_delay_ns,
        &mut frame.thread_policy_rq_delay_ns,
    )?;
    pull_tid_policy_u64_map(
        ebpf,
        futex_name,
        &mut frame.thread_futex_wait_ns,
        &mut frame.thread_policy_futex_wait_ns,
    )?;
    pull_edge_map(ebpf, edge_name, &mut frame.edges_ns)?;

    Ok(frame)
}

fn pull_tid_policy_u64_map(
    ebpf: &mut Ebpf,
    map_name: &str,
    by_tid: &mut HashMap<u32, u64>,
    by_tid_policy: &mut HashMap<(u32, u32), u64>,
) -> Result<()> {
    let mut map: UserHashMap<&mut MapData, u64, u64> =
        UserHashMap::try_from(ebpf.map_mut(map_name).unwrap())?;

    let mut keys = Vec::new();
    for item in map.iter() {
        let (k, v) = item?;
        let tid = (k >> 32) as u32;
        let policy = k as u32;
        add_u64(by_tid, tid, v);
        by_tid_policy.insert((tid, policy), v);
        keys.push(k);
    }

    for k in keys {
        let _ = map.remove(&k);
    }

    Ok(())
}

fn pull_edge_map(
    ebpf: &mut Ebpf,
    map_name: &str,
    out: &mut HashMap<(u32, u32), u64>,
) -> Result<()> {
    let mut map: UserHashMap<&mut MapData, u64, u64> =
        UserHashMap::try_from(ebpf.map_mut(map_name).unwrap())?;

    let mut keys = Vec::new();
    for item in map.iter() {
        let (k, v) = item?;
        let pred = (k >> 32) as u32;
        let succ = k as u32;
        out.insert((pred, succ), v);
        keys.push(k);
    }

    for k in keys {
        let _ = map.remove(&k);
    }

    Ok(())
}

fn infer_critical_subgraph(
    frame: &DagFrame,
    tail_tid: u32,
    slack_ns: u64,
    tau_ns: u64,
) -> CriticalSubgraphResult {
    let mut succ: HashMap<u32, Vec<(u32, u64)>> = HashMap::new();
    let mut pred: HashMap<u32, Vec<(u32, u64)>> = HashMap::new();

    for ((pred_tid, succ_tid), edge_ns) in &frame.edges_ns {
        succ.entry(*pred_tid)
            .or_default()
            .push((*succ_tid, *edge_ns));
        pred.entry(*succ_tid)
            .or_default()
            .push((*pred_tid, *edge_ns));
    }

    let mut reachable = HashSet::new();
    let mut stack = vec![tail_tid];
    reachable.insert(tail_tid);
    while let Some(cur) = stack.pop() {
        if let Some(preds) = pred.get(&cur) {
            for (pred_tid, _) in preds {
                if reachable.insert(*pred_tid) {
                    stack.push(*pred_tid);
                }
            }
        }
    }

    let mut score_to_tail: HashMap<u32, u64> = HashMap::new();
    let mut visiting_tail = HashSet::new();
    for tid in &reachable {
        let _ = longest_score_to_tail(
            *tid,
            tail_tid,
            frame,
            &succ,
            &reachable,
            &mut score_to_tail,
            &mut visiting_tail,
        );
    }

    let mut score_to_head: HashMap<u32, u64> = HashMap::new();
    let mut visiting_head = HashSet::new();
    for tid in &reachable {
        let _ = longest_score_to_head(
            *tid,
            frame,
            &pred,
            &reachable,
            &mut score_to_head,
            &mut visiting_head,
        );
    }

    let best_path_ns = (*score_to_head
        .get(&tail_tid)
        .unwrap_or(&frame.thread_total_ns(tail_tid)))
    .max(frame.thread_total_ns(tail_tid));

    let longest_chain = build_longest_chain_from_tail(tail_tid, frame, &pred, &score_to_head);
    let longest_nodes: HashSet<u32> = longest_chain.iter().copied().collect();

    let tau = tau_ns.max(1) as f64;
    let mut near_weights = HashMap::new();

    for tid in &reachable {
        let own = frame.thread_total_ns(*tid);
        let head = *score_to_head.get(tid).unwrap_or(&own);
        let tail = *score_to_tail.get(tid).unwrap_or(&own);
        let through = head
            .saturating_add(tail)
            .saturating_sub(own)
            .min(best_path_ns);
        let slack = best_path_ns.saturating_sub(through);
        if slack <= slack_ns {
            let crit = (-(slack as f64) / tau).exp();
            near_weights.insert(*tid, crit);
        }
    }

    let mut node_weights = near_weights;
    for tid in &longest_nodes {
        let cur = node_weights.get(tid).copied().unwrap_or(0.0);
        node_weights.insert(*tid, cur.max(1.0));
    }
    if node_weights.is_empty() {
        node_weights.insert(tail_tid, 1.0);
    }

    let mut node_total_ns = 0u64;
    for tid in node_weights.keys() {
        node_total_ns = node_total_ns.saturating_add(frame.thread_total_ns(*tid));
    }

    CriticalSubgraphResult {
        node_weights,
        best_path_ns,
        node_total_ns,
    }
}

fn longest_score_to_tail(
    tid: u32,
    tail_tid: u32,
    frame: &DagFrame,
    succ: &HashMap<u32, Vec<(u32, u64)>>,
    reachable: &HashSet<u32>,
    memo: &mut HashMap<u32, u64>,
    visiting: &mut HashSet<u32>,
) -> u64 {
    if let Some(v) = memo.get(&tid) {
        return *v;
    }
    if !reachable.contains(&tid) {
        return 0;
    }

    let own = frame.thread_total_ns(tid);
    if tid == tail_tid {
        memo.insert(tid, own);
        return own;
    }

    if !visiting.insert(tid) {
        return own;
    }

    let mut best_succ = 0u64;
    if let Some(succs) = succ.get(&tid) {
        for (next_tid, edge_ns) in succs {
            if !reachable.contains(next_tid) {
                continue;
            }
            let next_score =
                longest_score_to_tail(*next_tid, tail_tid, frame, succ, reachable, memo, visiting);
            let cand = edge_ns.saturating_add(next_score);
            if cand > best_succ {
                best_succ = cand;
            }
        }
    }

    visiting.remove(&tid);
    let score = own.saturating_add(best_succ);
    memo.insert(tid, score);
    score
}

fn longest_score_to_head(
    tid: u32,
    frame: &DagFrame,
    pred: &HashMap<u32, Vec<(u32, u64)>>,
    reachable: &HashSet<u32>,
    memo: &mut HashMap<u32, u64>,
    visiting: &mut HashSet<u32>,
) -> u64 {
    if let Some(v) = memo.get(&tid) {
        return *v;
    }
    if !reachable.contains(&tid) {
        return 0;
    }

    let own = frame.thread_total_ns(tid);
    if !visiting.insert(tid) {
        return own;
    }

    let mut best_pred = 0u64;
    if let Some(preds) = pred.get(&tid) {
        for (prev_tid, edge_ns) in preds {
            if !reachable.contains(prev_tid) {
                continue;
            }
            let prev_score =
                longest_score_to_head(*prev_tid, frame, pred, reachable, memo, visiting);
            let cand = prev_score.saturating_add(*edge_ns);
            if cand > best_pred {
                best_pred = cand;
            }
        }
    }

    visiting.remove(&tid);
    let score = own.saturating_add(best_pred);
    memo.insert(tid, score);
    score
}

fn build_longest_chain_from_tail(
    tail_tid: u32,
    frame: &DagFrame,
    pred: &HashMap<u32, Vec<(u32, u64)>>,
    score_to_head: &HashMap<u32, u64>,
) -> Vec<u32> {
    let mut rev = vec![tail_tid];
    let mut seen = HashSet::new();
    seen.insert(tail_tid);

    let mut cur = tail_tid;
    for _ in 0..64 {
        let cur_head = *score_to_head
            .get(&cur)
            .unwrap_or(&frame.thread_total_ns(cur));
        let cur_own = frame.thread_total_ns(cur);
        let target_gain = cur_head.saturating_sub(cur_own);

        let mut best_prev = None;
        let mut best_prev_gain = 0u64;
        if let Some(preds) = pred.get(&cur) {
            for (prev_tid, edge_ns) in preds {
                if seen.contains(prev_tid) {
                    continue;
                }
                let prev_head = *score_to_head
                    .get(prev_tid)
                    .unwrap_or(&frame.thread_total_ns(*prev_tid));
                let gain = prev_head.saturating_add(*edge_ns);
                if gain > best_prev_gain {
                    best_prev_gain = gain;
                    best_prev = Some(*prev_tid);
                }
            }
        }

        let Some(prev_tid) = best_prev else {
            break;
        };

        if target_gain > 0 && best_prev_gain == 0 {
            break;
        }

        if !seen.insert(prev_tid) {
            break;
        }

        rev.push(prev_tid);
        cur = prev_tid;
    }

    rev.reverse();
    rev
}

fn critical_subgraph_to_frame_stats(
    frame: &DagFrame,
    subgraph: &CriticalSubgraphResult,
) -> FrameStats {
    let mut out = FrameStats::new();

    for ((tid, policy), value) in &frame.thread_policy_exec_ns {
        if let Some(weight) = subgraph.node_weights.get(tid) {
            let weighted = (*value as f64 * *weight).round() as u64;
            if weighted > 0 {
                add_u64(&mut out.policy_exec_ns, *policy, weighted);
            }
        }
    }

    for ((tid, policy), value) in &frame.thread_policy_rq_delay_ns {
        if let Some(weight) = subgraph.node_weights.get(tid) {
            let weighted = (*value as f64 * *weight).round() as u64;
            if weighted > 0 {
                add_u64(&mut out.policy_rq_delay_ns, *policy, weighted);
            }
        }
    }

    for ((tid, policy), value) in &frame.thread_policy_futex_wait_ns {
        if let Some(weight) = subgraph.node_weights.get(tid) {
            let weighted = (*value as f64 * *weight).round() as u64;
            if weighted > 0 {
                add_u64(&mut out.policy_futex_wait_ns, *policy, weighted);
            }
        }
    }

    out
}

fn analyze_cluster_weights(
    frame: &FrameStats,
    policies: &[u32],
    policy_capacity: &HashMap<u32, f64>,
    ema_scores: &mut HashMap<u32, f64>,
    ema_lambda: f64,
    rq_weight: f64,
    _futex_weight: f64,
    exec_weight: f64,
    norm_mix: f64,
    min_cluster_weight: f64,
) -> Vec<PolicyWeightRow> {
    let mut rows = Vec::with_capacity(policies.len());

    for policy in policies {
        let exec = *frame.policy_exec_ns.get(policy).unwrap_or(&0);
        let rq = *frame.policy_rq_delay_ns.get(policy).unwrap_or(&0);
        let raw_score = exec_weight * exec as f64 + rq_weight * rq as f64;
        let prev = *ema_scores.get(policy).unwrap_or(&0.0);
        let smooth_raw = ema_lambda * prev + (1.0 - ema_lambda) * raw_score;
        ema_scores.insert(*policy, smooth_raw);
        let capacity = policy_capacity.get(policy).copied().unwrap_or(1.0).max(1.0);
        let smooth_norm = smooth_raw / capacity;

        rows.push(PolicyWeightRow {
            policy: *policy,
            weight: 0.0,
            smooth_raw_score: smooth_raw,
            smooth_norm_score: smooth_norm,
        });
    }

    normalize_weights(&mut rows, min_cluster_weight, norm_mix);
    rows.sort_by(|a, b| {
        b.weight
            .partial_cmp(&a.weight)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    rows
}

fn normalize_weights(rows: &mut [PolicyWeightRow], min_cluster_weight: f64, norm_mix: f64) {
    if rows.is_empty() {
        return;
    }

    let sum_raw: f64 = rows.iter().map(|r| r.smooth_raw_score).sum();
    let sum_norm: f64 = rows.iter().map(|r| r.smooth_norm_score).sum();
    let uniform = 1.0 / rows.len() as f64;

    for row in rows.iter_mut() {
        let p_raw = if sum_raw > 0.0 {
            row.smooth_raw_score / sum_raw
        } else {
            uniform
        };

        let p_norm = if sum_norm > 0.0 {
            row.smooth_norm_score / sum_norm
        } else {
            uniform
        };

        row.weight = (1.0 - norm_mix) * p_raw + norm_mix * p_norm;
    }

    let sum_mix: f64 = rows.iter().map(|r| r.weight).sum();
    if sum_mix > 0.0 {
        for row in rows.iter_mut() {
            row.weight /= sum_mix;
        }
    }

    let max_floor = 1.0 / rows.len() as f64;
    let floor = min_cluster_weight.min(max_floor).max(0.0);
    if floor > 0.0 {
        for row in rows.iter_mut() {
            if row.weight < floor {
                row.weight = floor;
            }
        }

        let sum2: f64 = rows.iter().map(|r| r.weight).sum();
        if sum2 > 0.0 {
            for row in rows.iter_mut() {
                row.weight /= sum2;
            }
        }
    }
}

fn critical_subgraph_confidence(subgraph: &CriticalSubgraphResult) -> f64 {
    if subgraph.best_path_ns == 0 {
        return 0.0;
    }

    (subgraph.node_total_ns as f64 / subgraph.best_path_ns as f64).clamp(0.0, 1.0)
}

fn load_cpu_policy_map() -> Result<HashMap<u32, u32>> {
    let mut map = HashMap::new();
    let base = "/sys/devices/system/cpu/cpufreq";

    for entry in fs::read_dir(base)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("policy") {
            continue;
        }

        let policy_id: u32 = name.trim_start_matches("policy").parse().unwrap_or(0);
        let related = entry.path().join("related_cpus");
        let data = fs::read_to_string(&related)?;
        for cpu_str in data.split_whitespace() {
            if let Ok(cpu_id) = cpu_str.parse::<u32>() {
                map.insert(cpu_id, policy_id);
            }
        }
    }

    if map.is_empty() {
        return Err(anyhow!("cpu->policy map is empty"));
    }

    Ok(map)
}

fn load_policy_capacity(cpu_policy: &HashMap<u32, u32>) -> Result<HashMap<u32, f64>> {
    let mut cpu_count: HashMap<u32, u32> = HashMap::new();
    for policy in cpu_policy.values() {
        cpu_count
            .entry(*policy)
            .and_modify(|v| *v = v.saturating_add(1))
            .or_insert(1);
    }

    let mut cap = HashMap::new();
    for policy in sorted_policies(cpu_policy) {
        let count = *cpu_count.get(&policy).unwrap_or(&1) as f64;
        let path = format!("/sys/devices/system/cpu/cpufreq/policy{policy}/cpuinfo_max_freq");
        let freq_khz = fs::read_to_string(&path)
            .ok()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .unwrap_or(0.0);
        let c = if freq_khz > 0.0 {
            freq_khz * count
        } else {
            count
        };
        cap.insert(policy, c.max(1.0));
    }

    Ok(cap)
}

fn sorted_policies(cpu_policy: &HashMap<u32, u32>) -> Vec<u32> {
    let mut set = BTreeSet::new();
    for policy in cpu_policy.values() {
        set.insert(*policy);
    }
    set.into_iter().collect()
}

fn add_u64(map: &mut HashMap<u32, u64>, key: u32, delta: u64) {
    map.entry(key)
        .and_modify(|v| *v = v.saturating_add(delta))
        .or_insert(delta);
}

fn event_to_pid(event: &MioEvent) -> Pid {
    let token = event.token();
    let Token(pid) = token;
    pid as Pid
}

const unsafe fn trans(buf: &[u8]) -> Event {
    unsafe { ptr::read_unaligned(buf.as_ptr().cast::<Event>()) }
}
