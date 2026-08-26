use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use marty_sync::demo_fixtures::generate_demo_fixtures;

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
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
