fn main() {
    let src = std::fs::read_to_string("weld.rules").unwrap();
    let start = std::time::Instant::now();
    let ir = weld_lang::compile(&src).unwrap();
    println!("parsed OK, rules={}", ir.denies.len());
    match weld_synth::synthesize(&ir) {
        Ok(sup) => println!("synthesized OK, states={}", sup.state_count()),
        Err(e) => println!("synth error: {e}"),
    }
    println!("elapsed: {:?}", start.elapsed());
}
