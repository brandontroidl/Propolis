use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let [_, out_dir, gateway_dns, collector_id] = args.as_slice() else {
        eprintln!("usage: provision-certs <out-dir> <gateway-dns> <collector-id>");
        return ExitCode::FAILURE;
    };

    let out = Path::new(out_dir);
    if let Err(err) = std::fs::create_dir_all(out) {
        eprintln!("failed to create output dir {out_dir}: {err}");
        return ExitCode::FAILURE;
    }

    if let Err(err) = provision_certs::provision(out, gateway_dns, collector_id) {
        eprintln!("provisioning failed: {err}");
        return ExitCode::FAILURE;
    }

    for file in [
        "ca.crt".to_string(),
        "gateway.crt".to_string(),
        "gateway.key".to_string(),
        format!("{collector_id}.crt"),
        format!("{collector_id}.key"),
    ] {
        println!("wrote {}", out.join(&file).display());
    }

    ExitCode::SUCCESS
}
