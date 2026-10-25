use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use marty_sync::demo_fixtures::{
    complete_public_trust_refresh, generate_demo_fixtures, prepare_public_trust_refresh,
};

fn main() -> Result<()> {
    let values: Vec<_> = std::env::args_os().skip(1).collect();
    if values.first().is_some_and(|arg| arg == "--prepare-trust") {
        if values.len() != 4 {
            bail!("usage: marty-demo-fixtures --prepare-trust <dtc|emrtd> <public-key-directory> <new-output-directory>");
        }
        return prepare_public_trust_refresh(
            values[1].to_str().context("invalid trust kind")?,
            &PathBuf::from(&values[2]),
            &PathBuf::from(&values[3]),
        );
    }
    if values.first().is_some_and(|arg| arg == "--complete-trust") {
        if values.len() != 3 {
            bail!("usage: marty-demo-fixtures --complete-trust <prepared-directory> <public-signature-file>");
        }
        return complete_public_trust_refresh(
            &PathBuf::from(&values[1]),
            &PathBuf::from(&values[2]),
        );
    }
    let mut args = values.into_iter();
    let Some(output_dir) = args.next() else {
        bail!("usage: marty-demo-fixtures <output-directory>");
    };
    if args.next().is_some() {
        bail!("usage: marty-demo-fixtures <output-directory>");
    }

    let manifest = generate_demo_fixtures(&PathBuf::from(output_dir))?;
    println!(
        "{}",
        serde_json::to_string(&manifest).context("serialize fixture manifest")?
    );
    Ok(())
}
