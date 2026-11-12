//! Minimal end-to-end example: one APK, every fact layer, no boilerplate.
//!
//! Run with a real input:
//! `cargo run -p mdd-facts --example quickstart -- app.apk`
//!
//! This demonstrates the one-stop `FactsSession` facade. The staged APIs
//! (`MetadataFacts::build`, `DefinitionFacts::build`, ...) remain available and
//! are what the facade composes internally.
use mdd_facts::session::FactsSession;
use mdd_types::MddResult;
use std::{path::PathBuf, process::ExitCode};

fn run(path: PathBuf) -> MddResult<()> {
    let session = FactsSession::open(&path)?;
    println!(
        "input={} dex_occurrences={}",
        path.display(),
        session.dex_count()
    );
    for index in 0..session.dex_count() {
        // Layers are built on first use and then reused, so requesting
        // references does not rebuild definitions or annotations.
        let metadata = session.metadata(index)?;
        let definitions = session.definitions(index)?;
        let code = session.code(index)?;
        // Annotations are optional and expensive; only request the layer you need.
        // `session.annotations(index)?` would build it the same way on demand.
        println!(
            "dex[{index}] occurrence={} strings={} classes={} methods={} code_items={} \
             metadata={:?} definitions={:?} code_layout={:?}",
            session.occurrence(index)?,
            metadata.strings().len(),
            definitions.definitions().classes.len(),
            definitions.definitions().method_definitions.len(),
            code.items().len(),
            metadata.metadata_coverage(),
            definitions.definition_coverage(),
            code.code_layout_coverage(),
        );
    }
    Ok(())
}

fn main() -> ExitCode {
    let Some(path) = std::env::args_os().nth(1).map(PathBuf::from) else {
        eprintln!("usage: quickstart INPUT.(apk|dex)");
        return ExitCode::from(2);
    };
    match run(path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::to_string_pretty(&error).unwrap_or_default()
            );
            ExitCode::FAILURE
        }
    }
}
