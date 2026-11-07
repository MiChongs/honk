//! Socket-identity hooks held by a foreign single-program owner.
//!
//! Android 15+ netd attaches a program to every socket-address hook of the
//! cgroup v2 root without `BPF_F_ALLOW_MULTI`. The kernel then keeps each hook
//! in single-program mode and refuses every multi-program attachment there and
//! in every descendant cgroup, `BPF_LINK_CREATE` included. The programs on the
//! connect and sendmsg hooks are pass-through placeholders that reserve them,
//! so honk replaces such an owner with its identity program, which also always
//! allows, and puts it back on release.
//!
//! netd attaches again without flags when it restarts and aborts unless the
//! hook then reports exactly one program, so a hook must never be emptied or
//! converted to multi-program mode: the swap and the restore both reuse the
//! hook's own flags. An owner is displaced only when its translated
//! instructions reduce to `r0 = 1; exit`, when the kernel withholds them and it
//! is netd's pinned program for the hook, or when it is honk's own program
//! left behind by a process that never released it. netd's socket-creation
//! program does real work and is never displaced.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

use aya_obj::generated::{bpf_attach_type, bpf_cmd, bpf_prog_type};
use tracing::{info, warn};

const BPF_F_ALLOW_MULTI: u32 = 2;
const BPF_F_RDONLY: u32 = 1 << 3;
/// A pass-through is two instructions, three with a zero extension.
const MAX_PASS_THROUGH_INSNS: usize = 8;
/// Prefix of every honk socket-identity program within the kernel's
/// 15-byte program name.
const HONK_PROGRAM_PREFIX: &str = "tproxy_wan_cg_";
const NETD_PIN_ROOTS: [&str; 3] = [
    "/sys/fs/bpf/netd_shared",
    "/sys/fs/bpf/netd_readonly",
    "/sys/fs/bpf",
];

/// A hook honk may take over, with the prefix of the program AOSP netd pins
/// for it ("prog_netd_<section>"; the suffix varies between releases).
#[derive(Clone, Copy, Debug)]
pub(super) struct SockAddrHook {
    attach_type: bpf_attach_type,
    netd_pin_prefix: &'static str,
}

impl SockAddrHook {
    pub(super) fn for_program(name: &str) -> Option<Self> {
        let (attach_type, netd_pin_prefix) = if name.contains("connect4") {
            (
                bpf_attach_type::BPF_CGROUP_INET4_CONNECT,
                "prog_netd_connect4_",
            )
        } else if name.contains("connect6") {
            (
                bpf_attach_type::BPF_CGROUP_INET6_CONNECT,
                "prog_netd_connect6_",
            )
        } else if name.contains("sendmsg4") {
            (
                bpf_attach_type::BPF_CGROUP_UDP4_SENDMSG,
                "prog_netd_sendmsg4_",
            )
        } else if name.contains("sendmsg6") {
            (
                bpf_attach_type::BPF_CGROUP_UDP6_SENDMSG,
                "prog_netd_sendmsg6_",
            )
        } else {
            return None;
        };
        Some(Self {
            attach_type,
            netd_pin_prefix,
        })
    }
}

/// honk's program on a hook it took over from a single-program owner. Drop
/// puts that owner back.
pub(super) struct Takeover {
    cgroup: OwnedFd,
    hook: SockAddrHook,
    flags: u32,
    ours: u32,
    displaced: OwnedFd,
}

impl std::fmt::Debug for Takeover {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Takeover")
            .field("attach_type", &self.hook.attach_type)
            .field("ours", &self.ours)
            .finish_non_exhaustive()
    }
}

impl Takeover {
    /// Replace the hook's single-program owner with `program` when that owner
    /// may be displaced; the error says why it was kept.
    pub(super) fn take(
        cgroup: &std::fs::File,
        hook: SockAddrHook,
        program: RawFd,
        program_name: &str,
    ) -> anyhow::Result<Self> {
        let owners = query(cgroup.as_raw_fd(), hook.attach_type)?;
        let [owner_id] = owners.ids[..] else {
            anyhow::bail!(
                "{program_name}: the hook holds {} programs in mode 0x{:x}",
                owners.ids.len(),
                owners.flags
            );
        };
        anyhow::ensure!(
            owners.flags & BPF_F_ALLOW_MULTI == 0,
            "{program_name}: the hook is in multi-program mode but refused the attachment"
        );
        let owner = prog_fd_by_id(owner_id)?;
        let info = prog_info(owner.as_raw_fd())?;
        let displaced = match info.verdict() {
            Owner::PassThrough => owner,
            Owner::Honk => netd_pinned(hook)
                .map_or_else(|| placeholder(hook), Ok)
                .map_err(|error| {
                    anyhow::anyhow!("{program_name}: load a pass-through for the hook: {error}")
                })?,
            Owner::Withheld if netd_pinned_id(hook) == Some(owner_id) => owner,
            Owner::Withheld => anyhow::bail!(
                "{program_name}: the kernel withholds the instructions of `{}` on the hook \
                 and it is not netd's pinned program, so it is kept",
                info.name()
            ),
            Owner::Effectful(count) => anyhow::bail!(
                "{program_name}: `{}` on the hook does more than allow ({count} \
                 instructions), so it is kept",
                info.name()
            ),
        };
        attach(cgroup.as_raw_fd(), program, hook.attach_type, owners.flags)?;
        let ours = prog_info(program)?.id;
        info!(
            program = program_name,
            displaced = %info.name(),
            "took over a single-program cgroup hook"
        );
        Ok(Self {
            cgroup: cgroup.try_clone()?.into(),
            hook,
            flags: owners.flags,
            ours,
            displaced,
        })
    }

    fn restore(&self) -> anyhow::Result<()> {
        let owners = query(self.cgroup.as_raw_fd(), self.hook.attach_type)?;
        // Another owner, such as netd's own program after a netd restart, is
        // not ours to displace.
        if owners.ids.is_empty() || owners.ids == [self.ours] {
            attach(
                self.cgroup.as_raw_fd(),
                self.displaced.as_raw_fd(),
                self.hook.attach_type,
                self.flags,
            )?;
        }
        Ok(())
    }
}

impl Drop for Takeover {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            warn!(
                attach_type = ?self.hook.attach_type,
                error = %format_args!("{error:#}"),
                "could not restore the displaced cgroup program"
            );
        }
    }
}

/// Whether `error` from a link attachment means the hook is held by a
/// single-program owner.
pub(super) fn refused_by_owner(error: &aya::programs::ProgramError) -> bool {
    matches!(
        error,
        aya::programs::ProgramError::SyscallError(syscall)
            if syscall.io_error.raw_os_error() == Some(libc::EPERM)
    )
}

/// The name of a foreign single-program owner of `attach_type`, if any.
pub(super) fn single_program_owner(
    cgroup: &std::fs::File,
    attach_type: bpf_attach_type,
) -> Option<String> {
    let owners = query(cgroup.as_raw_fd(), attach_type).ok()?;
    let [id] = owners.ids[..] else { return None };
    if owners.flags & BPF_F_ALLOW_MULTI != 0 {
        return None;
    }
    Some(
        prog_fd_by_id(id)
            .and_then(|fd| prog_info(fd.as_raw_fd()))
            .map_or_else(|_| format!("program {id}"), |info| info.name()),
    )
}

struct Owners {
    flags: u32,
    ids: Vec<u32>,
}

enum Owner {
    PassThrough,
    Honk,
    Withheld,
    Effectful(usize),
}

struct ProgInfo {
    id: u32,
    insns: Option<Vec<[u8; 8]>>,
    total: usize,
    name: [u8; 16],
}

impl ProgInfo {
    fn name(&self) -> String {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(16);
        String::from_utf8_lossy(&self.name[..end]).into_owned()
    }

    fn verdict(&self) -> Owner {
        if self.name().starts_with(HONK_PROGRAM_PREFIX) {
            return Owner::Honk;
        }
        match &self.insns {
            _ if self.total > MAX_PASS_THROUGH_INSNS => Owner::Effectful(self.total),
            Some(insns) if always_allows(insns) => Owner::PassThrough,
            Some(insns) => Owner::Effectful(insns.len()),
            None => Owner::Withheld,
        }
    }
}

/// Straight-line register moves ending in `exit` with `r0 = 1`: "return 1" in
/// either ALU width, plus the zero extension some verifiers insert. Any load,
/// store, call or branch is real work.
fn always_allows(insns: &[[u8; 8]]) -> bool {
    const BPF_ALU: u8 = 0x04;
    const BPF_JMP: u8 = 0x05;
    const BPF_ALU64: u8 = 0x07;
    const BPF_MOV: u8 = 0xb0;
    const BPF_EXIT: u8 = 0x90;
    const BPF_X: u8 = 0x08;
    let mut value: [Option<u64>; 11] = [None; 11];
    for (index, insn) in insns.iter().enumerate() {
        let code = insn[0];
        let dst = usize::from(insn[1] & 0x0f);
        let src = usize::from(insn[1] >> 4);
        let offset = i16::from_le_bytes([insn[2], insn[3]]);
        let imm = i32::from_le_bytes([insn[4], insn[5], insn[6], insn[7]]);
        match code & 0x07 {
            class @ (BPF_ALU | BPF_ALU64) => {
                if code & 0xf0 != BPF_MOV || offset != 0 || dst > 9 || src > 10 {
                    return false;
                }
                let result = if code & BPF_X == 0 {
                    Some(i64::from(imm) as u64)
                } else {
                    value[src]
                };
                value[dst] = if class == BPF_ALU {
                    result.map(|value| u64::from(value as u32))
                } else {
                    result
                };
            }
            BPF_JMP => {
                return code & 0xf0 == BPF_EXIT && index == insns.len() - 1 && value[0] == Some(1);
            }
            _ => return false,
        }
    }
    false
}

fn bpf<T>(cmd: bpf_cmd, attr: &mut T) -> io::Result<i64> {
    // SAFETY: each caller's `T` is the leading part of the command's
    // `union bpf_attr` member, and the kernel reads at most `size_of::<T>()`.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd as libc::c_long,
            (attr as *mut T).cast::<libc::c_void>(),
            std::mem::size_of::<T>(),
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn owned_fd(fd: i64) -> OwnedFd {
    // SAFETY: the kernel just returned this descriptor to us.
    unsafe { OwnedFd::from_raw_fd(fd as RawFd) }
}

fn query(cgroup: RawFd, attach_type: bpf_attach_type) -> io::Result<Owners> {
    #[repr(C)]
    struct Query {
        target_fd: u32,
        attach_type: u32,
        query_flags: u32,
        attach_flags: u32,
        prog_ids: u64,
        prog_cnt: u32,
        _pad: u32,
    }
    let mut ids = [0u32; 64];
    let mut attr = Query {
        target_fd: cgroup as u32,
        attach_type: attach_type as u32,
        query_flags: 0,
        attach_flags: 0,
        prog_ids: ids.as_mut_ptr() as u64,
        prog_cnt: ids.len() as u32,
        _pad: 0,
    };
    bpf(bpf_cmd::BPF_PROG_QUERY, &mut attr)?;
    let count = (attr.prog_cnt as usize).min(ids.len());
    Ok(Owners {
        flags: attr.attach_flags,
        ids: ids[..count].to_vec(),
    })
}

fn prog_fd_by_id(id: u32) -> io::Result<OwnedFd> {
    #[repr(C)]
    struct GetFd {
        prog_id: u32,
        next_id: u32,
        open_flags: u32,
    }
    let mut attr = GetFd {
        prog_id: id,
        next_id: 0,
        open_flags: 0,
    };
    bpf(bpf_cmd::BPF_PROG_GET_FD_BY_ID, &mut attr).map(owned_fd)
}

fn prog_info(fd: RawFd) -> io::Result<ProgInfo> {
    /// The leading part of `struct bpf_prog_info`, through `name`.
    #[repr(C)]
    #[derive(Default)]
    struct Info {
        prog_type: u32,
        id: u32,
        tag: [u8; 8],
        jited_prog_len: u32,
        xlated_prog_len: u32,
        jited_prog_insns: u64,
        xlated_prog_insns: u64,
        load_time: u64,
        created_by_uid: u32,
        nr_map_ids: u32,
        map_ids: u64,
        name: [u8; 16],
    }
    #[repr(C)]
    struct GetInfo {
        bpf_fd: u32,
        info_len: u32,
        info: u64,
    }
    let mut insns = [[0u8; 8]; MAX_PASS_THROUGH_INSNS];
    let mut info = Info {
        xlated_prog_len: std::mem::size_of_val(&insns) as u32,
        xlated_prog_insns: insns.as_mut_ptr() as u64,
        ..Default::default()
    };
    let mut attr = GetInfo {
        bpf_fd: fd as u32,
        info_len: std::mem::size_of::<Info>() as u32,
        info: (&raw mut info) as u64,
    };
    bpf(bpf_cmd::BPF_OBJ_GET_INFO_BY_FD, &mut attr)?;
    let total = info.xlated_prog_len as usize / 8;
    // Without raw dump access (constant blinding) the kernel reports the
    // length but copies nothing.
    let disclosed = total > 0 && total <= MAX_PASS_THROUGH_INSNS && info.xlated_prog_insns != 0;
    Ok(ProgInfo {
        id: info.id,
        insns: disclosed.then(|| insns[..total].to_vec()),
        total,
        name: info.name,
    })
}

fn attach(
    cgroup: RawFd,
    program: RawFd,
    attach_type: bpf_attach_type,
    flags: u32,
) -> io::Result<()> {
    #[repr(C)]
    struct Attach {
        target_fd: u32,
        attach_bpf_fd: u32,
        attach_type: u32,
        attach_flags: u32,
        replace_bpf_fd: u32,
    }
    // Without BPF_F_ALLOW_MULTI the kernel swaps the hook's single program for
    // this one atomically and keeps the hook's mode.
    let mut attr = Attach {
        target_fd: cgroup as u32,
        attach_bpf_fd: program as u32,
        attach_type: attach_type as u32,
        attach_flags: flags,
        replace_bpf_fd: 0,
    };
    bpf(bpf_cmd::BPF_PROG_ATTACH, &mut attr).map(drop)
}

/// netd's pinned program for `hook`, opened read-only.
fn netd_pinned(hook: SockAddrHook) -> Option<OwnedFd> {
    #[repr(C)]
    struct ObjGet {
        pathname: u64,
        bpf_fd: u32,
        file_flags: u32,
    }
    for root in NETD_PIN_ROOTS {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            if !name.to_string_lossy().starts_with(hook.netd_pin_prefix) {
                continue;
            }
            let Ok(path) = CString::new(Path::new(root).join(&name).as_os_str().as_encoded_bytes())
            else {
                continue;
            };
            let mut attr = ObjGet {
                pathname: path.as_ptr() as u64,
                bpf_fd: 0,
                file_flags: BPF_F_RDONLY,
            };
            if let Ok(fd) = bpf(bpf_cmd::BPF_OBJ_GET, &mut attr) {
                return Some(owned_fd(fd));
            }
        }
    }
    None
}

fn netd_pinned_id(hook: SockAddrHook) -> Option<u32> {
    netd_pinned(hook)
        .and_then(|fd| prog_info(fd.as_raw_fd()).ok())
        .map(|info| info.id)
}

/// A "return 1" program for `hook`, the same as netd's own placeholder.
fn placeholder(hook: SockAddrHook) -> io::Result<OwnedFd> {
    #[repr(C)]
    struct Load {
        prog_type: u32,
        insn_cnt: u32,
        insns: u64,
        license: u64,
        log_level: u32,
        log_size: u32,
        log_buf: u64,
        kern_version: u32,
        prog_flags: u32,
        prog_name: [u8; 16],
        prog_ifindex: u32,
        expected_attach_type: u32,
    }
    // mov64 r0, 1; exit
    let insns: [[u8; 8]; 2] = [[0xb7, 0, 0, 0, 1, 0, 0, 0], [0x95, 0, 0, 0, 0, 0, 0, 0]];
    let license = c"GPL";
    let mut name = [0u8; 16];
    name[..13].copy_from_slice(b"honk_hook_ok\0");
    let mut attr = Load {
        prog_type: bpf_prog_type::BPF_PROG_TYPE_CGROUP_SOCK_ADDR as u32,
        insn_cnt: insns.len() as u32,
        insns: insns.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: 0,
        log_size: 0,
        log_buf: 0,
        kern_version: 0,
        prog_flags: 0,
        prog_name: name,
        prog_ifindex: 0,
        expected_attach_type: hook.attach_type as u32,
    };
    bpf(bpf_cmd::BPF_PROG_LOAD, &mut attr).map(owned_fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(code: u8, regs: u8, imm: i32) -> [u8; 8] {
        let imm = imm.to_le_bytes();
        [code, regs, 0, 0, imm[0], imm[1], imm[2], imm[3]]
    }

    #[test]
    fn only_straight_line_return_one_is_a_pass_through() {
        let exit = insn(0x95, 0, 0);
        // netd's placeholder: mov64 r0, 1; exit.
        assert!(always_allows(&[insn(0xb7, 0, 1), exit]));
        // 32-bit move plus a zero extension through another register.
        assert!(always_allows(&[
            insn(0xb4, 1, 1),
            insn(0xbc, 0x10, 0),
            exit
        ]));
        assert!(!always_allows(&[insn(0xb7, 0, 0), exit]));
        assert!(!always_allows(&[insn(0xb7, 0, 1)]));
        // A store before the return does real work.
        assert!(!always_allows(&[
            insn(0xb7, 2, 0),
            insn(0x63, 0x21, 0),
            insn(0xb7, 0, 1),
            exit
        ]));
        // An unknown source register is not a known 1.
        assert!(!always_allows(&[insn(0xbf, 0x30, 0), exit]));
    }

    #[test]
    fn honk_owners_are_reclaimed_by_name_before_instructions() {
        let mut name = [0u8; 16];
        name[..15].copy_from_slice(b"tproxy_wan_cg_c");
        let stale = ProgInfo {
            id: 7,
            insns: None,
            total: 40,
            name,
        };
        assert!(matches!(stale.verdict(), Owner::Honk));
        let foreign = ProgInfo {
            id: 8,
            insns: None,
            total: 40,
            name: [0; 16],
        };
        assert!(matches!(foreign.verdict(), Owner::Effectful(40)));
    }
}
