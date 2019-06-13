use ring::rand::{self, SecureRandom};
use std::vec;

#[test]
fn rand_test_system_random_lengths() {
    // Test that `fill` succeeds for various interesting lengths. `256` and
    // multiples thereof are interesting because that's an edge case for
    // `getrandom` on Linux.
    let lengths = [0, 1, 2, 3, 96, 255, 256, 257, 511, 512, 513, 4096];

    for len in lengths.iter() {
        let mut buf = vec![0; *len];

        let rng = rand::SystemRandom::new();
        assert!(rng.fill(&mut buf).is_ok());

        // If `len` < 96 then there's a big chance of false positives, but
        // otherwise the likelihood of a false positive is so too low to
        // worry about.
        if *len >= 96 {
            assert!(buf.iter().any(|x| *x != 0));
        }
    }
}
