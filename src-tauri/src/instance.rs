//! Explicit instance isolation; default startup remains unchanged.
use crate::error::{AppError, AppResult};
use marty_secure_storage::InstanceNamespace;
use std::ffi::OsString;
use std::path::Path;

/// Bounded cleanup command: requires explicit instance paths and retired data.
pub fn cleanup_if_requested() -> Option<i32> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if !args.iter().any(|arg| arg == "--remove-instance-keys") {
        return None;
    }
    let result = (|| -> AppResult<()> {
        if args.len() != 1 {
            return Err(AppError::Config(
                "instance cleanup accepts no additional arguments".into(),
            ));
        }
        let namespace = from_environment()?.ok_or_else(|| {
            AppError::Config("instance cleanup requires MARTY_VERIFIER_INSTANCE".into())
        })?;
        let data = std::env::var_os("MARTY_VERIFIER_DATA_DIR").expect("validated data path");
        if Path::new(&data).try_exists()? {
            return Err(AppError::Config(
                "retire the instance data directory before removing its keys".into(),
            ));
        }
        namespace.remove_keys()?;
        Ok(())
    })();
    Some(match result {
        Ok(()) => {
            println!("Isolated instance keys removed");
            0
        }
        Err(error) => {
            eprintln!("Instance cleanup failed: {error}");
            1
        }
    })
}

pub(crate) fn from_environment() -> AppResult<Option<InstanceNamespace>> {
    validate(
        std::env::var_os("MARTY_VERIFIER_INSTANCE"),
        std::env::var_os("MARTY_VERIFIER_DATA_DIR"),
        std::env::var_os("MARTY_VERIFIER_CONFIG_PATH"),
    )
}

fn validate(
    instance: Option<OsString>,
    data: Option<OsString>,
    config: Option<OsString>,
) -> AppResult<Option<InstanceNamespace>> {
    let Some(instance) = instance else {
        return Ok(None);
    };
    let invalid = || {
        AppError::Config("isolated instance requires a valid namespace, absolute instance-named data directory and config inside that directory".into())
    };
    let instance = instance.to_str().ok_or_else(invalid)?;
    let namespace = InstanceNamespace::new(instance).map_err(|_| invalid())?;
    let data = data.ok_or_else(invalid)?;
    let config = config.ok_or_else(invalid)?;
    let data = Path::new(&data);
    let config = Path::new(&config);
    if !data.is_absolute()
        || !config.is_absolute()
        || data.file_name().and_then(|v| v.to_str()) != Some(instance)
        || config.parent() != Some(data)
        || data.components().chain(config.components()).any(|p| {
            matches!(
                p,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(invalid());
    }
    Ok(Some(namespace))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn isolated_startup_requires_scoped_paths_and_explicit_valid_namespace() {
        let root = std::env::temp_dir().join("d09-instance-1");
        let config = root.join("config.json");
        let call = |instance: &str, data: &Path, config: &Path| {
            validate(
                Some(instance.into()),
                Some(data.as_os_str().into()),
                Some(config.as_os_str().into()),
            )
        };
        assert!(call("d09-instance-1", &root, &config).unwrap().is_some());
        for bad in ["", "default", "prod", "../x", "com.marty.verifier"] {
            assert!(call(bad, &root, &config).is_err());
        }
        assert!(call("another-instance", &root, &config).is_err());
        assert!(call("d09-instance-1", Path::new("d09-instance-1"), &config).is_err());
        assert!(call("d09-instance-1", &root, &root.with_extension("json")).is_err());
        assert!(validate(Some("d09-instance-1".into()), None, None).is_err());
        assert!(validate(None, None, None).unwrap().is_none());
    }
}
