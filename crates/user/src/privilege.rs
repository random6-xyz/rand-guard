use anyhow::Context;

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const CAP_SYS_ADMIN: u32 = 21;
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[derive(Debug, PartialEq, Eq)]
struct PrivilegeStatus {
    euid: u32,
    effective_caps: [u32; 2],
}

impl PrivilegeStatus {
    fn is_sufficient(&self) -> bool {
        self.euid == 0
            || self.has_cap(CAP_SYS_ADMIN)
            || (self.has_cap(CAP_BPF) && self.has_cap(CAP_PERFMON))
    }

    fn has_cap(&self, cap: u32) -> bool {
        let index = (cap / 32) as usize;
        let bit = cap % 32;

        self.effective_caps
            .get(index)
            .is_some_and(|caps| caps & (1_u32 << bit) != 0)
    }
}

pub fn ensure_sufficient() -> anyhow::Result<()> {
    let status = current_status().context("failed to inspect process privileges")?;

    if status.is_sufficient() {
        return Ok(());
    }

    anyhow::bail!(
        "insufficient privileges to load eBPF programs: run as root or grant CAP_BPF and CAP_PERFMON (CAP_SYS_ADMIN also works on older kernels)"
    );
}

fn current_status() -> anyhow::Result<PrivilegeStatus> {
    let euid = unsafe { libc::geteuid() };
    let mut header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];

    let result = unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("capget syscall failed");
    }

    Ok(PrivilegeStatus {
        euid,
        effective_caps: [data[0].effective, data[1].effective],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap_bit(cap: u32) -> [u32; 2] {
        let mut caps = [0; 2];
        caps[(cap / 32) as usize] = 1_u32 << (cap % 32);
        caps
    }

    #[test]
    fn root_is_sufficient_without_capabilities() {
        let status = PrivilegeStatus {
            euid: 0,
            effective_caps: [0, 0],
        };

        assert!(status.is_sufficient());
    }

    #[test]
    fn cap_sys_admin_is_sufficient_for_non_root() {
        let status = PrivilegeStatus {
            euid: 1000,
            effective_caps: cap_bit(CAP_SYS_ADMIN),
        };

        assert!(status.is_sufficient());
    }

    #[test]
    fn cap_bpf_and_cap_perfmon_are_sufficient_for_non_root() {
        let mut caps = cap_bit(CAP_BPF);
        caps[1] |= cap_bit(CAP_PERFMON)[1];
        let status = PrivilegeStatus {
            euid: 1000,
            effective_caps: caps,
        };

        assert!(status.is_sufficient());
    }

    #[test]
    fn partial_capabilities_are_rejected_for_non_root() {
        let status = PrivilegeStatus {
            euid: 1000,
            effective_caps: cap_bit(CAP_BPF),
        };

        assert!(!status.is_sufficient());
    }
}
