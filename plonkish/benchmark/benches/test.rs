use std::hint::black_box;
use std::time::Instant;

fn main() {
    let timer = Instant::now();
    for i in 0..100000000 {
        let j = i;
    }
    println!("time 1: {:?}", timer.elapsed());

    let timer = Instant::now();
    for i in 0..100000000 {
        let j = black_box(i * 2);
    }
    println!("time 2: {:?}", timer.elapsed());
}
