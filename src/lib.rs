#![feature(result_option_inspect)]
#![feature(iter_intersperse)]
// there's a small `bench` in `mod tests` added when I tried to make initial implementation work in reasonable time
#![feature(test)]
/// This is migration of https://github.com/cjeudy/EllipticCurves to Rust. It aims to be as close as possible to "drop-in" replacement, Mentions of "source" through-out the crate usually means 
/// the original code at the forementioned link. Diviations from the source are mostly labeled (in the comments) or induced by Clippy.
/// 
/// A big up-front deviation is decision to use `crypto-bigint` for big integers. It breaks absent of limit on integers value which source have, but it's a deliberate choice for the exercise 
/// to learn and practice the cryptographic library while migrating. To compensate this divergency a feature introduced (namely `u8192`), which switch all computation to 8192-bit integers, 
/// which is practically is quite similar to the unlimited integers source have, but very computationally intensive for integers of any length smaller than this huge limit. For default 
/// implementation 512-bit integers are chosen so that it would work with all the tests introduced in the source repository and have minimal computational burden.
/// 
/// Please add `-- --nocapture` to `cargo test` if you want to get the output similar to the tests from the source, as source only prints tests/examples with no assertions.
/// 
/// Throughout the code there a lot of notes and snippets for myself to track the learning curve I had during the exercise. Of course, it would be removed in production commit, but I feel them
/// to be appropriate for the exercise (including most of debug printing preserved).
// ~~TODO: align error system~~
// ~~TODO limit p to be > 2~~
// ~~TODO add U8192 back; behind a feature flag?~~
// ~~TODO research if it's ok and secure to store coordinates as DynResidues and `retrieve()` 'em on access~~
    /* seems to be reasonable if points and curve parameters would be accessed via getters in source: but to mimic it better I tend to make them public, so only `p` going to be processed with this 
    approach */
    /* looks like DynResidues _should be_ ok, but with superficial looking through it's not obvious; e g how `subtle` is used there, nevertheless it seems to be constant time (which isn't directly)
    about safe usage in structs; without `zeroize` feature both are very comparable */
        /* With default feature flags of crypto bigint crate I see no difference in terms of security between storing `UInt` and DynResidue... . Didn't look into `subtle` and
        zeroize features though. */
extern crate test;

use crypto_bigint::Uint;
#[cfg(not(feature = "u8192"))]
use crypto_bigint::U512;
#[cfg(feature = "u8192")]
use crypto_bigint::U8192;

use thiserror::Error;

#[cfg(not(feature = "u8192"))]
type Ufeat = U512;
#[cfg(feature = "u8192")]
type Ufeat = U8192;

#[derive(Error, Debug)]
pub enum Errs {
    #[error("The point is not on the curve")]
    ValueError,
    #[error("Curve is not smooth.")]
    Exception,
    #[error("One of coordinates is out of the underlying field.")]
    NccModulus,
    #[error("Can't create a point as the coordinates aren't on the given curve.")]
    NccOutOfTheCurve
}

mod ec;
mod point;
use ec::EllipticCurve;
use point::Point;

/// Computes the non adjacent form of an integer n
pub fn non_adjacent<const T: usize>(n: Uint<T>) -> Vec<i8> {
    // let length = n.bits() - n.leading_zeros();
    let length = n.bits();
    // println!("DEBUG: bits {length}");
    #[derive(Debug)]
    enum States {A, B, C}
    let mut state = States::A;
    let mut non_adj_repr = Vec::new();

    /* source function looks at the first bit but its index in string representation there -- is last */
    for i in 0..length {
        match &state {
            States::A => {
                if n.bit(i).into() {state = States::B;}
                else {non_adj_repr.push(0);}
            }
            States::B => {
                if n.bit(i).into() {
                    non_adj_repr.push(-1);
                    non_adj_repr.push(0);
                    state = States::C;
                }
                else {
                    non_adj_repr.push(1);
                    non_adj_repr.push(0);
                    state = States::A;
                }
            }
            _ => {
                if n.bit(i).into() {non_adj_repr.push(0)}
                else {state = States::B}
            }
        }
        // println!("DEBUG: step {i}, state {:?}", &state);
    }
    match state {
        States::A => {}
        _ => {
            non_adj_repr.push(1);
            non_adj_repr.push(0);
        }
    }
    // println!("DEBUG: `non_adj_repr.len()` {}", non_adj_repr.len());
    non_adj_repr
}
// ~~TODO would be cool to enforce p > 2 with types~~
    // not sure it's possible with types outside something like Flux, but I more or less satisfied with `mod`s which restricts creation of structs with arbitrary values even inside my own crate

#[cfg(test)] #[allow(non_snake_case)]
mod tests {
    use crypto_bigint::CheckedAdd;
    use std::rc::Rc;

    use super::*;
    use test::Bencher;

    // here I wanted to facilitate testing of `non_adjacent` and learned that _ternary expansion_ and _balanced ternary_ have common ideas behind, but are significantly different
    // #[test]
    // fn ternary() {
    //     let output_translated = non_adjacent(Ufeat::from(u64::MAX)).iter().rev().map(|i| {match i {
    //             1 => "+".to_string(),
    //             0 => "0".to_string(),
    //             -1 => "-".to_string(),
    //             _ => self::panic!("invalid value in `Vec`<bal ternary>")
    //         }}).collect::<String>();
    //     let output_testing = cbb::util::cbb::int_to_bal_ternary(u64::MAX as i128);
    //     // assert_eq!(output_translated.len(), output_testing.len());
    //     assert_eq!(output_translated, output_testing)
    // }

    fn setup() -> (Ufeat, Rc<EllipticCurve>, Point) {
        // ~~TODO check that value_fromSource - 1 is the right shift value~~
        /* 10724754759635747624044531514068121842070756627434833028965540808827675062043 is 17B5FEFF30C7F5677AB2AEEBD13779A2AC125042A6AA10BFA54C15BAB76BAF1B in hex */
        
        let nM511: Ufeat = Ufeat::ONE.shl_vartime(508).checked_add(
            &Ufeat::from_be_hex(&("0".repeat(Ufeat::BITS / 4 - 64) + "17B5FEFF30C7F5677AB2AEEBD13779A2AC125042A6AA10BFA54C15BAB76BAF1B"))
        ).expect("Uint size is too small");

        let  CM511 = Rc::new(EllipticCurve::new(
            "M-511".to_string(),
            nM511,
            Ufeat::ONE.shl_vartime(511).wrapping_sub(&Ufeat::from(0xbbu16)),
            [530438,1,0]
        ));

        let GM511: Point = Point::new(
            CM511.clone(), Some(Ufeat::from(0x5u8)), 
            Some(Ufeat::from_be_hex(
                &("0".repeat(Ufeat::BITS / 4 - 128) + "2fbdc0ad8530803d28fdbad354bb488d32399ac1cf8f6e01ee3f96389b90c809422b9429e8a43dbf49308ac4455940abe9f1dbca542093a895e30a64af056fa5")
            ))
        ).unwrap();
        (nM511, CM511, GM511)
    }

    #[bench]
    fn kkkk(b: &mut Bencher) {
        let (_, _, GM511) = setup();
        b.iter(|| {
            // let n = U512::from(u128::MAX);
            let n = Ufeat::ONE.shl_vartime(20);
            let P = (&GM511.clone() * n).unwrap();
            let _Q = P - GM511.clone();
        });
    }
    
    #[test]
    fn l16() {
        let (_, CM511, GM511) = setup();
        // let mut Z = Point::default();
        let /* mut */ Z = Point::new(CM511, None, Default::default()).unwrap();
        // Z.curve = CM511.clone();
        // let Z = Z;
        println!("{}", (Z + GM511.clone()).unwrap() == GM511);
    }

    #[test]
    fn l27() {
        let (nM511, CM511, GM511) = setup();
        // let n = U8192::from_be_hex(&("0".repeat(1958) + "475C2D3FC6FC8C94275E8E10630E286A07E2A4F0C823100F0465ABA3C494598DCD00553ABC9A40CD18138F65B5"));
        let n = Ufeat::from_be_hex(&("0".repeat(Ufeat::BITS / 4 - 90) + "475C2D3FC6FC8C94275E8E10630E286A07E2A4F0C823100F0465ABA3C494598DCD00553ABC9A40CD18138F65B5"));
        let P = (n * &GM511).unwrap();
        let Q = (P.clone() - GM511.clone()).unwrap();
        println!("{}", Q == (&GM511 * (n.wrapping_sub(&Ufeat::ONE))).unwrap());
    
        let Z = Point::new(CM511, None, Default::default()).unwrap();
        // println!("{nM511}");
        // println!("(GM511 * nM511) {}", (&GM511 * nM511).unwrap() /* == Z */);
        println!("{}", (&P * nM511).unwrap() == Z);
        println!("{}", (nM511 * &Q).unwrap() == Z);
        println!("{}", (&Z * Ufeat::from(265321u32)).unwrap() == Z);
    }
}