//! Source write restrictions for local host subprocesses, independent of tool sandboxing.
use codex_utils_absolute_path::AbsolutePathBuf;
use std::path::Path;

pub fn protect_read_only_paths(
    program: String,
    args: Vec<String>,
    cwd: &Path,
    paths: &[AbsolutePathBuf],
) -> anyhow::Result<Vec<String>> {
    if paths.is_empty() {
        return Ok(std::iter::once(program).chain(args).collect());
    }
    #[cfg(target_os = "macos")]
    {
        use crate::SandboxCommand;
        use crate::SandboxManager;
        use crate::SandboxTransformRequest;
        use crate::SandboxType;
        use codex_protocol::config_types::WindowsSandboxLevel;
        use codex_protocol::models::PermissionProfile;
        use codex_protocol::permissions::FileSystemAccessMode;
        use codex_protocol::permissions::FileSystemPath;
        use codex_protocol::permissions::FileSystemSandboxEntry;
        use codex_protocol::permissions::FileSystemSandboxKind;
        use codex_protocol::permissions::FileSystemSandboxPolicy;
        use codex_protocol::permissions::FileSystemSpecialPath;
        use codex_protocol::permissions::NetworkSandboxPolicy;
        use codex_utils_path_uri::PathUri;
        use std::collections::HashMap;

        // Hooks previously ran as trusted host processes. Retain filesystem writes
        // outside the requested read-only carveouts; model tools keep their own
        // existing permission profile. Native policy generation handles aliases,
        // protected ancestors, and child-process inheritance.
        let mut entries = vec![FileSystemSandboxEntry::new(
            FileSystemPath::Special {
                value: FileSystemSpecialPath::Root,
            },
            FileSystemAccessMode::Write,
        )];
        entries.extend(
            paths
                .iter()
                .cloned()
                .map(|path| FileSystemSandboxEntry::new(path.into(), FileSystemAccessMode::Read)),
        );
        let policy = FileSystemSandboxPolicy {
            kind: FileSystemSandboxKind::Restricted,
            glob_scan_max_depth: None,
            entries,
        };
        let permissions =
            PermissionProfile::from_runtime_permissions(&policy, NetworkSandboxPolicy::Enabled);
        let cwd = PathUri::from(AbsolutePathBuf::from_absolute_path(cwd)?);
        let request = SandboxManager::default().transform(SandboxTransformRequest {
            command: SandboxCommand {
                program: program.into(),
                args,
                cwd: cwd.clone(),
                env: HashMap::new(),
                managed_network: None,
                additional_permissions: None,
            },
            permissions: &permissions,
            sandbox: SandboxType::MacosSeatbelt,
            enforce_managed_network: false,
            environment_id: None,
            network: None,
            sandbox_policy_cwd: &cwd,
            sandbox_exe: None,
            use_legacy_landlock: false,
            windows_sandbox_level: WindowsSandboxLevel::default(),
        })?;
        Ok(request.command)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (program, args, cwd);
        anyhow::bail!("process_read_only_paths is not supported on this platform")
    }
}
