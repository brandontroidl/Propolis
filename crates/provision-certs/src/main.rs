use std::path::Path;
use std::process::ExitCode;

use provision_certs::SensorTlsOutcome;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--sensor-tls") {
        return sensor_tls(&args[2..]);
    }
    legacy(&args)
}

fn sensor_tls(args: &[String]) -> ExitCode {
    let [out_dir, sensors @ ..] = args else {
        eprintln!("usage: provision-certs --sensor-tls <out-dir> <sensor>...");
        return ExitCode::FAILURE;
    };
    if sensors.is_empty() {
        eprintln!("usage: provision-certs --sensor-tls <out-dir> <sensor>...");
        return ExitCode::FAILURE;
    }
    let out = Path::new(out_dir);
    // The directory's mode and owner are deploy/provision.sh's decision; creating it here would
    // silently create it with the process umask instead.
    if !out.is_dir() {
        eprintln!("output dir {out_dir} does not exist (deploy/provision.sh creates it)");
        return ExitCode::FAILURE;
    }
    for sensor in sensors {
        match provision_certs::provision_sensor_tls(out, sensor) {
            Ok(outcome) => {
                let verb = match outcome {
                    SensorTlsOutcome::Minted => "minted",
                    SensorTlsOutcome::Kept => "kept",
                };
                println!("{verb} {}", out.join(format!("{sensor}.crt")).display());
                println!("{verb} {}", out.join(format!("{sensor}.key")).display());
            }
            Err(err) => {
                eprintln!("provisioning {sensor} failed: {err}");
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

fn legacy(args: &[String]) -> ExitCode {
    let [_, out_dir, gateway_dns, collector_id] = args else {
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
