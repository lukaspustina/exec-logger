use std::env;

const CRATE_PATH: &str = env!("CARGO_MANIFEST_DIR");
const DEBUG_TARGET_PATH: &str = "target/debug";

fn bin() -> String {
    format!(
        "{}/{}/exec_logger{}",
        CRATE_PATH,
        DEBUG_TARGET_PATH,
        env::consts::EXE_SUFFIX
    )
}

#[ignore]
#[test]
fn cli_output_tests() {
    lit::run::tests(lit::event_handler::Default::default(), |config| {
        config.add_search_path("tests/lit");
        config.add_extension("output");
        config.constants.insert("bin".to_owned(), bin());
        config
            .constants
            .insert("bin_version".to_owned(), env!("CARGO_PKG_VERSION").to_owned());
    })
    .expect("cli output tests failed");
}
