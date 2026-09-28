fn main() {
    let mut args = std::env::args_os().skip(1);
    let result = match (args.next(), args.next()) {
        (None, None) => digital_life_lib::run_d29h7_authority_fixture(),
        (Some(mode), None) if mode == "--d29h3-host-fixture" => {
            digital_life_lib::run_d29h3_authority_fixture()
        }
        (Some(mode), None) if mode == "--d29h4-host-fixture" => {
            digital_life_lib::run_d29h4_authority_fixture()
        }
        (Some(mode), None) if mode == "--d29h5-host-fixture" => {
            digital_life_lib::run_d29h5_authority_fixture()
        }
        _ => Err("unsupported authority fixture mode".to_string()),
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
