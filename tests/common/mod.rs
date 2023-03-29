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
