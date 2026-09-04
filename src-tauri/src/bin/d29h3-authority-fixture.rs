fn main() {
    if let Err(error) = digital_life_lib::run_d29h3_authority_fixture() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
