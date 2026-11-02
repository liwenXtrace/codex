//! Additional source protection for trusted command hooks. This wraps only the
//! hook process, so the native tool sandbox can still be applied independently.
use codex_config::ConfigLayerStack;
use codex_utils_absolute_path::AbsolutePathBuf;
use serde::Deserialize;
use std::path::Path;

use crate::engine::CommandShell;

pub(crate) fn configured_paths(
    stack: Option<&ConfigLayerStack>,
) -> Result<Vec<AbsolutePathBuf>, String> {
    let Some(value) = stack.and_then(|stack| {
        stack
            .effective_config()
            .get("process_read_only_paths")
            .cloned()
    }) else {
        return Ok(Vec::new());
    };
    Vec::<AbsolutePathBuf>::deserialize(value)
        .map_err(|err| format!("invalid process_read_only_paths: {err}"))
}

pub(crate) fn protected_shell(
    shell: CommandShell,
    cwd: &Path,
    paths: &[AbsolutePathBuf],
) -> anyhow::Result<CommandShell> {
    let mut argv =
        codex_sandboxing::protect_read_only_paths(shell.program, shell.args, cwd, paths)?
            .into_iter();
    let program = argv
        .next()
        .ok_or_else(|| anyhow::anyhow!("process sandbox produced an empty command"))?;
    Ok(CommandShell {
        program,
        args: argv.collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::configured_paths;
    use codex_config::ConfigLayerEntry;
    use codex_config::ConfigLayerSource;
    use codex_config::ConfigLayerStack;
    use codex_config::TomlValue;
    use codex_utils_absolute_path::test_support::PathBufExt;
    use codex_utils_absolute_path::test_support::test_path_buf;

    fn stack(paths: serde_json::Value) -> ConfigLayerStack {
        ConfigLayerStack::new(
            vec![ConfigLayerEntry::new(
                ConfigLayerSource::SessionFlags,
                TomlValue::try_from(serde_json::json!({"process_read_only_paths": paths})).unwrap(),
            )],
            Default::default(),
            Default::default(),
        )
        .unwrap()
    }

    #[test]
    fn hook_path_configuration_preserves_absolute_paths_and_rejects_malformed_values() {
        let path = test_path_buf("/source").abs();
        assert_eq!(configured_paths(None).unwrap(), Vec::new());
        assert_eq!(
            configured_paths(Some(&stack(serde_json::json!([path])))).unwrap(),
            vec![path]
        );
        assert!(configured_paths(Some(&stack(serde_json::json!("/source")))).is_err());
        assert!(configured_paths(Some(&stack(serde_json::json!([42])))).is_err());
    }
}
