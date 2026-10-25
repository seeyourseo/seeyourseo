use std::{error::Error, fmt, path::PathBuf};

#[derive(Clone, Debug)]
pub enum Service {
    Website,
    Crawler,
    Analyzer,
    Renderer,
    Obscura(PathBuf),
}

#[derive(Debug)]
pub struct SandboxError(String);

impl fmt::Display for SandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for SandboxError {}

/// Confines a long-running service before it creates its async runtime.
/// Non-Linux targets intentionally keep their existing behavior.
pub fn apply(service: Service) -> Result<(), SandboxError> {
    #[cfg(target_os = "linux")]
    {
        apply_linux(service, None)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = service;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn apply_linux(
    service: Service,
    allowed_execveat_fd: Option<std::os::fd::RawFd>,
) -> Result<(), SandboxError> {
    use landlock::{
        ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetStatus,
    };

    let executable = std::env::current_exe()
        .map_err(|e| SandboxError(format!("locate service executable: {e}")))?;
    let bin_dir = executable
        .parent()
        .ok_or_else(|| SandboxError("service executable has no parent directory".into()))?;
    // Grant runtime, certificate, and DNS inputs explicitly. This keeps all
    // other home and system files inaccessible to the service process.
    let abi = ABI::V1;
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| SandboxError(format!("configure Landlock: {e}")))?
        .create()
        .map_err(|e| SandboxError(format!("create Landlock ruleset: {e}")))?;
    // Read runtime and certificate inputs explicitly. Browser execution is
    // handled separately through a single pre-opened executable descriptor.
    let read = AccessFs::ReadFile | AccessFs::ReadDir;
    let write = AccessFs::from_write(abi);
    let mut skipped = Vec::new();
    for path in [
        "/usr",
        "/lib",
        "/lib64",
        "/bin",
        "/sbin",
        "/etc/ssl/certs",
        "/etc/ld.so.cache",
        "/etc/ssl/cert.pem",
        "/etc/ssl",
        "/etc/ca-certificates",
        "/etc/pki/tls/certs",
        "/etc/pki/ca-trust/extracted",
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/nsswitch.conf",
        "/etc/host.conf",
        "/etc/gai.conf",
        "/etc/passwd",
        "/etc/group",
        "/etc/hostname",
        "/run/systemd/resolve",
    ] {
        if PathBuf::from(path).exists() {
            ruleset = add_path_rule(ruleset, path, read, &mut skipped)?;
        }
    }
    for path in ["/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/local/lib"] {
        if PathBuf::from(path).is_dir() {
            ruleset = add_path_rule(ruleset, path, read | AccessFs::Execute, &mut skipped)?;
        }
    }
    match service {
        Service::Website => {
            let static_dir = bin_dir.join("static");
            if static_dir.is_dir() {
                ruleset =
                    add_path_rule(ruleset, &static_dir.to_string_lossy(), read, &mut skipped)?;
            }
            for (key, default) in [
                ("SCAN_ANALYTICS_PATH", "data/scan-analytics.jsonl"),
                ("VISITOR_LOG_PATH", "data/visitor-access.jsonl"),
            ] {
                let path = std::env::var_os(key)
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from(default));
                let path = prepare_data_file(path)?;
                ruleset = add_path_rule(
                    ruleset,
                    &path.to_string_lossy(),
                    read | AccessFs::WriteFile,
                    &mut skipped,
                )?;
            }
            let payment_env = std::env::var_os("PAYMENTS_ENV_FILE")
                .map(PathBuf::from)
                .or_else(|| {
                    std::env::var_os("HOME")
                        .map(PathBuf::from)
                        .map(|home| home.join(".config/seeyourseo/payments.env"))
                });
            if let Some(path) = payment_env.filter(|path| path.is_file()) {
                ruleset = add_path_rule(ruleset, &path.to_string_lossy(), read, &mut skipped)?;
            }
        }
        Service::Crawler | Service::Analyzer => {}
        Service::Renderer => {
            let temp_dir = service_temp_dir()?;
            ruleset = add_path_rule(
                ruleset,
                &temp_dir.to_string_lossy(),
                read | write,
                &mut skipped,
            )?;
            if PathBuf::from("/proc").is_dir() {
                ruleset = add_path_rule(ruleset, "/proc", read, &mut skipped)?;
            }
            if PathBuf::from("/sys/devices/system/cpu").is_dir() {
                ruleset = add_path_rule(ruleset, "/sys/devices/system/cpu", read, &mut skipped)?;
            }
            for path in ["/dev/zero", "/dev/random", "/dev/urandom"] {
                if PathBuf::from(path).exists() {
                    ruleset = add_path_rule(ruleset, path, read, &mut skipped)?;
                }
            }
            if PathBuf::from("/dev/null").exists() {
                ruleset = add_path_rule(
                    ruleset,
                    "/dev/null",
                    read | AccessFs::WriteFile,
                    &mut skipped,
                )?;
            }
        }
        Service::Obscura(ref binary) => {
            let temp_dir = service_temp_dir()?;
            ruleset = add_path_rule(
                ruleset,
                &temp_dir.to_string_lossy(),
                read | write,
                &mut skipped,
            )?;
            ruleset = add_path_rule(
                ruleset,
                &binary.to_string_lossy(),
                read | AccessFs::Execute,
                &mut skipped,
            )?;
        }
    }

    let status = ruleset
        .restrict_self()
        .map_err(|e| SandboxError(format!("apply Landlock restrictions: {e}")))?;
    if status.ruleset != RulesetStatus::FullyEnforced {
        return Err(SandboxError(format!(
            "Linux filesystem sandbox is only partially enforced ({status:?}); refusing to start"
        )));
    }
    install_seccomp(allowed_execveat_fd)?;
    eprintln!(
        "Linux Landlock{} sandbox active for {service:?}",
        " and seccomp"
    );
    if !skipped.is_empty() {
        eprintln!(
            "Linux sandbox skipped unavailable paths: {}",
            skipped.join(", ")
        );
    }
    Ok(())
}

/// Confine an Obscura worker and replace it with the configured browser binary.
/// The executable FD is opened before Landlock is applied, so execution needs
/// permission on that one file without granting Execute to its parent tree.
#[cfg(target_os = "linux")]
pub fn exec_obscura(binary: &std::path::Path, args: &[std::ffi::OsString]) -> std::io::Error {
    use std::{
        ffi::CString,
        fs::OpenOptions,
        os::{fd::AsRawFd, unix::ffi::OsStrExt},
    };

    let binary = match std::fs::canonicalize(binary) {
        Ok(binary) => binary,
        Err(error) => return error,
    };
    let executable = match OpenOptions::new().read(true).open(&binary) {
        Ok(file) => file,
        Err(error) => return error,
    };
    let fd = executable.as_raw_fd();
    // execveat(AT_EMPTY_PATH) needs the descriptor to survive the exec.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } == -1 {
        return std::io::Error::last_os_error();
    }

    if let Err(error) = apply_linux(Service::Obscura(binary.clone()), Some(fd)) {
        return std::io::Error::other(error);
    }

    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(CString::new(binary.as_os_str().as_bytes()).expect("binary path contains NUL"));
    for arg in args {
        match CString::new(arg.as_os_str().as_bytes()) {
            Ok(arg) => argv.push(arg),
            Err(error) => return std::io::Error::other(error),
        }
    }
    let mut argv_ptrs = argv.iter().map(|arg| arg.as_ptr()).collect::<Vec<_>>();
    argv_ptrs.push(std::ptr::null());

    let mut env = Vec::new();
    for (key, value) in std::env::vars_os() {
        let mut entry = key.as_os_str().as_bytes().to_vec();
        entry.push(b'=');
        entry.extend_from_slice(value.as_os_str().as_bytes());
        match CString::new(entry) {
            Ok(entry) => env.push(entry),
            Err(error) => return std::io::Error::other(error),
        }
    }
    let mut env_ptrs = env.iter().map(|entry| entry.as_ptr()).collect::<Vec<_>>();
    env_ptrs.push(std::ptr::null());

    let empty = b"\0";
    unsafe {
        libc::syscall(
            libc::SYS_execveat,
            fd,
            empty.as_ptr(),
            argv_ptrs.as_ptr(),
            env_ptrs.as_ptr(),
            libc::AT_EMPTY_PATH,
        );
    }
    std::io::Error::last_os_error()
}

/// Make a browser worker die with its renderer parent, including abrupt exits.
#[cfg(target_os = "linux")]
pub fn set_parent_death_signal(expected_parent: i32) -> std::io::Result<()> {
    let parent_before = unsafe { libc::getppid() };
    if parent_before != expected_parent {
        return Err(std::io::Error::other(
            "renderer parent exited before worker startup",
        ));
    }
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::getppid() } != expected_parent {
        return Err(std::io::Error::other(
            "renderer parent exited during worker startup",
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn exec_obscura(_binary: &std::path::Path, _args: &[std::ffi::OsString]) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Obscura fd-exec requires Linux",
    )
}

#[cfg(target_os = "linux")]
fn prepare_data_file(path: PathBuf) -> Result<PathBuf, SandboxError> {
    use std::{
        fs::OpenOptions,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
    };

    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map_err(|e| SandboxError(format!("locate website working directory: {e}")))?
            .join(path)
    };
    let parent = path
        .parent()
        .ok_or_else(|| SandboxError("website data file has no parent directory".into()))?;
    std::fs::create_dir_all(parent)
        .map_err(|e| SandboxError(format!("prepare website data directory: {e}")))?;
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| SandboxError(format!("prepare website data file {}: {e}", path.display())))?;
    drop(file);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| SandboxError(format!("protect website data file {}: {e}", path.display())))?;
    std::fs::canonicalize(&path)
        .map_err(|e| SandboxError(format!("resolve website data file {}: {e}", path.display())))
}

#[cfg(target_os = "linux")]
fn service_temp_dir() -> Result<PathBuf, SandboxError> {
    let path = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .filter(|path| path.is_dir())
        .ok_or_else(|| SandboxError("private TMPDIR is not configured".into()))?;
    Ok(path)
}

#[cfg(target_os = "linux")]
fn add_path_rule(
    ruleset: landlock::RulesetCreated,
    path: &str,
    access: landlock::BitFlags<landlock::AccessFs>,
    skipped: &mut Vec<String>,
) -> Result<landlock::RulesetCreated, SandboxError> {
    use landlock::{AccessFs, RulesetCreatedAttr};

    let fd = match landlock::PathFd::new(path) {
        Ok(fd) => fd,
        Err(_) => {
            skipped.push(path.to_owned());
            return Ok(ruleset);
        }
    };
    let metadata = std::fs::metadata(path)
        .map_err(|e| SandboxError(format!("inspect sandbox path {path}: {e}")))?;
    let object_access = if metadata.is_dir() {
        AccessFs::Execute
            | AccessFs::ReadFile
            | AccessFs::ReadDir
            | AccessFs::WriteFile
            | AccessFs::RemoveDir
            | AccessFs::RemoveFile
            | AccessFs::MakeChar
            | AccessFs::MakeDir
            | AccessFs::MakeReg
            | AccessFs::MakeSock
            | AccessFs::MakeFifo
            | AccessFs::MakeBlock
            | AccessFs::MakeSym
    } else {
        AccessFs::Execute | AccessFs::ReadFile | AccessFs::WriteFile
    };
    ruleset
        .add_rule(landlock::PathBeneath::new(fd, access & object_access))
        .map_err(|e| SandboxError(format!("allow sandbox path {path}: {e}")))
}

#[cfg(target_os = "linux")]
fn install_seccomp(allowed_execveat_fd: Option<std::os::fd::RawFd>) -> Result<(), SandboxError> {
    use seccompiler::{
        SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule, apply_filter,
    };
    use std::collections::BTreeMap;

    let mut rules = BTreeMap::new();
    for syscall in [
        libc::SYS_ptrace,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
        libc::SYS_bpf,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_pivot_root,
        libc::SYS_setns,
        libc::SYS_unshare,
    ] {
        rules.insert(syscall, Vec::new());
    }
    rules.insert(libc::SYS_execve, Vec::new());
    match allowed_execveat_fd {
        Some(fd) => {
            // Permit execveat only for the inherited executable descriptor and
            // only with AT_EMPTY_PATH. All other descriptors and path-based
            // execution are rejected by seccomp.
            let fd_mismatch = SeccompRule::new(vec![
                SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Ne, fd as u64)
                    .map_err(|e| SandboxError(format!("build execveat fd filter: {e}")))?,
            ])
            .map_err(|e| SandboxError(format!("build execveat fd rule: {e}")))?;
            let flags_mismatch = SeccompRule::new(vec![
                SeccompCondition::new(
                    4,
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::Ne,
                    libc::AT_EMPTY_PATH as u64,
                )
                .map_err(|e| SandboxError(format!("build execveat flags filter: {e}")))?,
            ])
            .map_err(|e| SandboxError(format!("build execveat flags rule: {e}")))?;
            rules.insert(libc::SYS_execveat, vec![fd_mismatch, flags_mismatch]);

            // Keep the inherited descriptor bound to the already-opened
            // browser image after execveat transfers control to Obscura.
            for (syscall, argument) in [
                (libc::SYS_close, 0),
                (libc::SYS_dup2, 1),
                (libc::SYS_dup3, 1),
            ] {
                let replacement = SeccompRule::new(vec![
                    SeccompCondition::new(
                        argument,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::Eq,
                        fd as u64,
                    )
                    .map_err(|e| SandboxError(format!("build protected fd rule: {e}")))?,
                ])
                .map_err(|e| SandboxError(format!("build protected fd rule: {e}")))?;
                rules.insert(syscall, vec![replacement]);
            }
            rules.insert(libc::SYS_close_range, Vec::new());
        }
        None => {
            rules.insert(libc::SYS_execveat, Vec::new());
        }
    }
    let arch = std::env::consts::ARCH
        .try_into()
        .map_err(|e| SandboxError(format!("unsupported seccomp architecture: {e:?}")))?;
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(|e| SandboxError(format!("build seccomp filter: {e}")))?;
    let program: seccompiler::BpfProgram = filter
        .try_into()
        .map_err(|e| SandboxError(format!("compile seccomp filter: {e}")))?;
    apply_filter(&program).map_err(|e| SandboxError(format!("apply seccomp filter: {e}")))
}
