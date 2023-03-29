// there's a small `bench` in `mod tests` added when I tried to make initial implementation work in reasonable time
#![feature(test)]
#![allow(non_snake_case)]
extern crate test;

use hw_13::Point;
mod common;

use crypto_bigint::U512;

use test::Bencher;

#[bench]
fn kkkk(b: &mut Bencher) {
    let (_, _, GM511) = common::setup();
    b.iter(|| {
        // let n = U512::from(u128::MAX);
        let n = U512::ONE.shl_vartime(20);
        let P = (&GM511.clone() * n).unwrap();
        let _Q = P - GM511.clone();
    });
}

#[test]
fn l16() {
    let (_, CM511, GM511) = common::setup();
    // let mut Z = Point::default();
    let /* mut */ Z = Point::new(CM511, None, Default::default()).unwrap();
    // Z.curve = CM511.clone();
    // let Z = Z;
    println!("{}", (Z + GM511.clone()).unwrap() == GM511);
}

#[test]
fn l27() {
    let (nM511, CM511, GM511) = common::setup();
    // let n = U8192::from_be_hex(&("0".repeat(1958) + "475C2D3FC6FC8C94275E8E10630E286A07E2A4F0C823100F0465ABA3C494598DCD00553ABC9A40CD18138F65B5"));
    let n = U512::from_be_hex(&("0".repeat(U512::BITS / 4 - 90) + "475C2D3FC6FC8C94275E8E10630E286A07E2A4F0C823100F0465ABA3C494598DCD00553ABC9A40CD18138F65B5"));
    let P = (n * &GM511).unwrap();
    let Q = (P.clone() - GM511.clone()).unwrap();
    println!("{}", Q == (&GM511 * (n.wrapping_sub(&U512::ONE))).unwrap());

    let Z = Point::new(CM511, None, Default::default()).unwrap();
    // println!("{nM511}");
    // println!("(GM511 * nM511) {}", (&GM511 * nM511).unwrap() /* == Z */);
    println!("{}", (&P * nM511).unwrap() == Z);
    println!("{}", (nM511 * &Q).unwrap() == Z);
    println!("{}", (&Z * U512::from(265321u32)).unwrap() == Z);
}
