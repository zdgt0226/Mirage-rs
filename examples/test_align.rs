fn main() {
    println!("{}", aya::include_bytes_aligned!(env!("BPF_SOCKMAP_ELF")).len());
}
