# Week 13 homework for Uncloak CryptoEng course

Exercise migration of https://github.com/cjeudy/EllipticCurves to Rust. Solution aims to be as close as possible to "drop-in" replacement.

Running `cargo run --example example` mimics `example.py` from the source. (Mentions of "source" through-out the crate usually means the original code at the forementioned link.)

Throughout the code there a lot of notes and snippets left to track the learning curve I had during the exercise. Of course, it would been removed in a production commit, but I feel them appropriate to be kept here for the exercise (including most of debug printing preserved).
## Review
[REDACTED]
> - `panic_dont` - make names non-negative, because it adds confusion when you're in `else` part of `if(!dont_something)`
> - still not so much tests
> - Exceptions' names don't convey situations they occur in `ValueError` occurs if EC is not smooth IIRC