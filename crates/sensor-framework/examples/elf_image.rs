//! Write one modeled executable's generated image to a file, to inspect with the real tools
//! (`file`, `readelf -lhS --wide`, `strings`, `objdump -d`):
//!
//! `cargo run -p sensor-framework --example elf_image -- ls /tmp/ls.elf`
//!
//! The file is data. Nothing here marks it executable, and nothing should run it.

use std::process::ExitCode;

use sensor_framework::binaries;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let [_, name, out] = args.as_slice() else {
        eprintln!("usage: elf_image NAME OUTPUT");
        return ExitCode::from(2);
    };
    let Some(binary) = binaries::find(name) else {
        eprintln!("elf_image: no modeled binary {name}");
        return ExitCode::from(1);
    };
    let bytes = binary.blob().read_range(0, u64::MAX);
    if let Err(error) = std::fs::write(out, bytes) {
        eprintln!("elf_image: {out}: {error}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}
