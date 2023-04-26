// ~~there's a small `bench` in `mod tests` added when I tried to make initial implementation work in reasonable time~~
//      maintaining the toy `bench` became unnatural when `example` moved to </examples>, though left as part of history
// #![feature(test)]
#![allow(non_snake_case)]
// extern crate test;

// TODO would be nice to enable this example to use `u8192` feature, though it's way too impractical.

use hw_13::Point;
mod common {
    use std::rc::Rc;

    use crypto_bigint::{CheckedAdd, U512};
    use hw_13::{EllipticCurve, Point};

    pub fn setup() -> (U512, Rc<EllipticCurve>, Point) {
        // ~~TODO check that value_fromSource - 1 is the right shift value~~
        /* 10724754759635747624044531514068121842070756627434833028965540808827675062043 is 17B5FEFF30C7F5677AB2AEEBD13779A2AC125042A6AA10BFA54C15BAB76BAF1B in hex */

        let nM511: U512 = U512::ONE
            .shl_vartime(508)
            .checked_add(&U512::from_be_hex(
                &("0".repeat(U512::BITS / 4 - 64)
                    + "17B5FEFF30C7F5677AB2AEEBD13779A2AC125042A6AA10BFA54C15BAB76BAF1B"),
            ))
            .expect("Uint size is too small");

        let CM511 = Rc::new(EllipticCurve::new(
            "M-511".to_string(),
            nM511,
            U512::ONE // }
                .shl_vartime(511)
                .wrapping_sub(&U512::from(0xbbu16)),
            [530438, 1, 0],
        ));

        let GM511: Point = Point::new(
            CM511.clone(), Some(U512::from(0x5u8)),
            Some(U512::from_be_hex(
                &("0".repeat(U512::BITS / 4 - 128) + "2fbdc0ad8530803d28fdbad354bb488d32399ac1cf8f6e01ee3f96389b90c809422b9429e8a43dbf49308ac4455940abe9f1dbca542093a895e30a64af056fa5")
            ))
        ).unwrap();
        (nM511, CM511, GM511)
    }
}

fn main() {
    use crypto_bigint::U512;

    // use test::Bencher;

    // #[bench]
    // fn kkkk(b: &mut Bencher) {
    //     let (_, _, GM511) = common::setup();
    //     b.iter(|| {
    //         // let n = U512::from(u128::MAX);
    //         let n = U512::ONE.shl_vartime(20);
    //         let P = (&GM511.clone() * n).unwrap();
    //         let _Q = P - GM511.clone();
    //     });
    // }

    let (_, CM511, GM511) = common::setup();
    // let mut Z = Point::default();
    let /* mut */ Z = Point::new(CM511, None, Default::default()).unwrap();
    // Z.curve = CM511.clone();
    // let Z = Z;
    println!("{}", (Z + GM511.clone()).unwrap() == GM511);

    let (nM511, CM511, GM511) = common::setup();
    // let n = U8192::from_be_hex(&("0".repeat(1958) + "475C2D3FC6FC8C94275E8E10630E286A07E2A4F0C823100F0465ABA3C494598DCD00553ABC9A40CD18138F65B5"));
    let n = U512::from_be_hex(&("0".repeat(U512::BITS / 4 - 90) + "475C2D3FC6FC8C94275E8E10630E286A07E2A4F0C823100F0465ABA3C494598DCD00553ABC9A40CD18138F65B5"));
    let P = (n * &GM511).unwrap();
    let Q = (P.clone() - GM511.clone()).unwrap();
    println!("{}", Q == (&GM511 * (n.wrapping_sub(&U512::ONE))).unwrap());

    let Z = Point::new(CM511, None, Default::default()).unwrap();
    // println!("{nM511}");
    println!(
        /* "(GM511 * nM511)  */ "{}",
        (&GM511 * nM511).unwrap() == Z
    );
    println!("{}", (&P * nM511).unwrap() == Z);
    println!("{}", (nM511 * &Q).unwrap() == Z);
    println!("{}", (&Z * U512::from(265321u32)).unwrap() == Z);
}
