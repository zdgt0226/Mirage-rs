use aya::Ebpf;

fn main() {
    let bytes = include_bytes!("../../ebpf-src/transparent.elf");
    match Ebpf::load(bytes) {
        Ok(_) => println!("Successfully loaded transparent.elf!"),
        Err(e) => println!("Error loading transparent.elf: {}", e),
    }
}
