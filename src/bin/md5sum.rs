fn main() {
    for file in std::env::args().skip(1) {
        match std::fs::read(&file) {
            Err(err) => {
                eprintln!("error reading {file}: {err}")
            }
            Ok(content) => {
                let sum = crypto_hype::hashes::md5::hash(&content);
                println!("{sum}  {file}");
            }
        };
    }
}
