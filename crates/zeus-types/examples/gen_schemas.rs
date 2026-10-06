//! Writes the generated JSON Schemas to `schemas/` at the repository root.
//!
//! Run: `cargo run -p zeus-types --example gen_schemas` (optionally pass an output directory).

#![allow(clippy::print_stdout, reason = "command-line tool")]

use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let out = std::env::args().nth(1).map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas"),
        PathBuf::from,
    );
    std::fs::create_dir_all(&out)?;
    let path = out.join("zeus-types.schema.json");
    let mut text = serde_json::to_string_pretty(&zeus_types::schema::bundle())
        .map_err(std::io::Error::other)?;
    text.push('\n');
    std::fs::write(&path, text)?;
    println!("wrote {}", path.display());
    Ok(())
}
