use criterion::{black_box, criterion_group, criterion_main, Criterion};

use nekoton::crypto::get_hints;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("word_exists", |b| b.iter(|| get_hints(black_box("en"))));
    c.bench_function("word_non_exists", |b| {
        b.iter(|| get_hints(black_box("apwdlkp")))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
