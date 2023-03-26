# Week 13 homework for Uncloak CryptoEng course

Exercise migration of https://github.com/cjeudy/EllipticCurves to Rust. It aims to be as close as possible to "drop-in" replacement.

Please add `-- --nocapture` to `cargo test` if you want to get the output similar to the tests from the source, as source only prints tests/examples with no assertions.

Throughout the code there a lot of notes and snippets for myself to track the learning curve I had during the exercise. Of course, it would be removed in production commit, but I feel them to be appropriate for the exercise (including most of debug printing preserved).