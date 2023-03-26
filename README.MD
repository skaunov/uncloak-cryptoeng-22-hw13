# Week 13 homework for Uncloak CryptoEng course

Exercise migration of https://github.com/cjeudy/EllipticCurves to Rust. It aims to be as close as possible to be "drop-in" replacement.

Please add `-- --nocapture` to `cargo test` if you want to get the output similar to the tests from the source, as source only prints tests/examples with no assertions. (Mentions of "source" through-out the crate usually means the original code at the forementioned link.)

Throughout the code there a lot of notes and snippets for myself to track the learning curve I had during the exercise. Of course, it would be removed in a production commit, but I feel them appropriate to be kept here for the exercise (including most of debug printing preserved).