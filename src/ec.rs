use crate::Errs;
use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    Checked,
};
use std::fmt;

use super::{Point, Ufeat};

///     Object of an elliptic curve over prime fields (Montgomery & Weierstrass equations only)
// #[derive(Clone)]
pub struct EllipticCurve {
    pub name: String,
    order: Ufeat,
    a2: DynResidue<{ Ufeat::LIMBS }>,
    a4: DynResidue<{ Ufeat::LIMBS }>,
    a6: DynResidue<{ Ufeat::LIMBS }>,
    p: DynResidueParams<{ Ufeat::LIMBS }>, // shouldn't be `pub` to respect imperative limitation to be > 2
    pub type_: String, // would make it an `enum` if source was checking this type
    /* approach with storing "original_..." is based on assumption that no function in the crate would ever mutate curve parameters (which holds for source)
    in case of changing of this assumption `get` method should be ammended and overall design reviewed */
    original_p: Ufeat,
    original_coefficients: [isize; 3],
}

impl EllipticCurve {
    pub fn new(name: String, order: Ufeat, modulus: Ufeat, coefficients: [isize; 3]) -> Self {
        if order <= Ufeat::from(2u8) {
            panic!("Binary fields are a different realm.")
        }

        // if NonZero::new(modulus).expect(
        //     "modulus should not be zero"
        // ) % NonZero::<Ufeat>::from(std::num::NonZeroU8::new(2).unwrap()) == 0 {panic!("Fields over even modulus are useless here.")}

        if modulus.wrapping_rem(&Ufeat::from(2u8)) == Ufeat::ZERO {
            panic!("Fields over even modulus are useless here also modulus can't be zero.")
        }

        // ~~TODO check that I remember this nuance right; does it called Froebenius track of value 1, btw?~~
        //      it's "trace", not "track"
        if order == modulus {
            println!("This curve could be susceptible to Smart's attack! https://crypto.stackexchange.com/questions/70454/why-smarts-attack-doesnt-work-on-this-ecdlp")
        }
        // printing to stdout is ridiculous for a `lib` crate, but proper handliing of such nuances would require redesigning the whole thing, including defining new purpose of it

        // ~~TODO test what source would do when coefficient(s) would be greater than `modulus` (and reflect here)~~
        /*      it seems to be a boring case as no material jumps out of the Internet on me trying to superficially research the issue; without definitive parameters testing source is quite
                inefficient; so let's just prohibit it since it anyway shouldn't ever happen, and watch if somebody would answer to https://www.reddit.com/r/ef1p/comments/xgsco5/comment/jd9ner7 */
        let panic_dont = true; // if modulus > Ufeat::from(isize::MAX as u64) {true} else {false};
                               // no need for it: the coefficients are ok to "wrap around"

        // `is_smooth` never used in the source, though it would go here

        let p = DynResidueParams::new(&modulus);
        let helper_coef_to_dynres = |coef: isize| -> DynResidue<{ Ufeat::LIMBS }> {
            let mut r = DynResidue::new(&Ufeat::try_from(coef.unsigned_abs() as u64).unwrap(), p);
            if coef.is_negative() {
                r = r.neg();
            }
            if !panic_dont {
                // Seems to me that small negatives could be easily be greater than `modulus` after wrapping in the field
                // if r.retrieve() >= modulus {panic!("coefficient is greater or equal to `modulus`")}
                //      so it's more appropriate to cast the (checked above) `modulus` down to `u64` and compare it with `isize`
                // written blindly and can contain errors in implementation; it is just to practice a bit with limbs without any particular purpose
                if modulus.as_words().last().unwrap() <= &(coef.unsigned_abs() as u64) {
                    panic!("coefficient is greater or equal to `modulus`")
                }
            }
            r
        };
        EllipticCurve {
            name,
            order,
            a2: helper_coef_to_dynres(coefficients[0]),
            a4: helper_coef_to_dynres(coefficients[1]),
            a6: helper_coef_to_dynres(coefficients[2]),
            // p: NonZero::from_uint(modulus),
            p,
            original_p: modulus,
            type_: if coefficients[0] == 0 {
                "Weierstrass".to_string()
            } else {
                "Montgomery".to_string()
            },
            original_coefficients: coefficients,
        }
    }
    pub fn p(&self) -> &DynResidueParams<{ Ufeat::LIMBS }> {
        &self.p
    }
    pub fn original_p(&self) -> Ufeat {
        self.original_p
    }
    pub fn a2(&self) -> &DynResidue<{ Ufeat::LIMBS }> {
        &self.a2
    }
    pub fn a4(&self) -> &DynResidue<{ Ufeat::LIMBS }> {
        &self.a4
    }
    pub fn a6(&self) -> &DynResidue<{ Ufeat::LIMBS }> {
        &self.a6
    }
    pub fn get(&self) -> (&str, &Ufeat, &[isize], &Ufeat) {
        (
            &self.name,
            &self.order,
            &self.original_coefficients,
            &self.original_p,
        )
    }

    ///        Computes the discriminant delta of C: $y^2 = x^3 + a2.x^2 + a4.x + a6 (mod p)$
    pub fn discriminant(&self) -> isize {
        let b2 = 4 * self.original_coefficients[0]; // self.a2;
        let (b4, b6, b8) = (
            2 * self.original_coefficients[1], // self.a4,
            4 * self.original_coefficients[2], // self.a6,
            // b2 * self.a6 - self.a4.checked_pow(2).unwrap()
            b2 * self.original_coefficients[2]
                - self.original_coefficients[1].checked_pow(2).unwrap(),
        );
        -b8 * b2
            .checked_pow(2)
            .expect("discriminant calculation overflow")
            - 8 * b4
                .checked_pow(3)
                .expect("discriminant calculation overflow")
            - 27 * b6
                .checked_pow(2)
                .expect("discriminant calculation overflow")
            + 9 * b2 * b4 * b6
    }

    ///        Tests if the elliptic curve is smooth or not
    pub fn is_smooth(&self) -> Result<bool, Errs> {
        if self.discriminant() == 0 {
            Err(Errs::Exception)
        } else {
            Ok(true)
        }
    }

    /// Checks whether `Point` is in the set of current `EllipticCurve` points
    pub fn contains(&self, point: &Point) -> bool {
        // source relies on checks in another method when calling this (public!) method, so it doesn't check the None case of point at infinity -- adding `.unwrap()` here and at the last line
        //      basically this means that source states that point on infinity isn't contained by `curve`, which makes me ammend `Point::new`
        let x_modp = point.x().unwrap();
        let rhs =
            x_modp.pow(&Ufeat::from(3u8)) + self.a2 * x_modp.square() + self.a4 * x_modp + self.a6;
        // debug print
        // println!("{} | y^2", point.y().unwrap().square().retrieve());
        // println!("{} | `rhs`", rhs.retrieve());
        // println!("{} | diff", point.y().unwrap().square().retrieve().wrapping_sub(&rhs.retrieve()));//.expect("does {{y^2}} > `rhs`"));

        point.y().unwrap().square() == rhs
    }
}

/// Default curve: Secp256k1 : y**2 = x**3 + 7 (mod 2**256 - 2**32 - 977)
impl Default for EllipticCurve {
    fn default() -> Self {
        //     U256 variant
        // EllipticCurve {
        //     name: "Secp256k1".to_string(),
        //     order: // as source construct the number from "2**256" which is unrepresentable by `U256` by exactly `ONE`, the closest migration is to add this `ONE` in the end back https://github.com/cjeudy/EllipticCurves/blob/77ec97ff1de146e03dd65c36813c0aad61254242/EC.py#L22
        //         (
        //             Checked::new(U256::MAX)
        //             - Checked::new(U256::from_be_hex("0x14551231950b75fc4402da1732fc9bebf"))
        //             + Checked::new(U256::ONE)
        //         ).0.unwrap(),
        //     a2: 0, a4: 0, a6: 7,
        //     p: // as source construct the number from "2**256" which is unrepresentable by `U256` by exactly `ONE`, the closest migration is to add this `ONE` in the end back https://github.com/cjeudy/EllipticCurves/blob/77ec97ff1de146e03dd65c36813c0aad61254242/EC.py#L23
        //         (
        //             Checked::new(U256::MAX)
        //             - Checked::new(U256::from_u64(2u64.checked_pow(32).unwrap()))
        //             - Checked::new(U256::from_u16(977))
        //             + Checked::new(U256::ONE)
        //         ).0.unwrap(),
        //     type_: "Weierstrass".to_string()
        // }

        // ~~TODO check that value_fromSource - 1 is the proper shift value~~
        let two_pow256 = Ufeat::ONE.shl_vartime(256);
        // println!("{two_pow256}");
        // println!("{}", U8192::from_be_hex(&("0".repeat(2014) + "014551231950b75fc4402da1732fc9bebf")));
        EllipticCurve::new(
            "Secp256k1".to_string(),
            (Checked::new(two_pow256)
                - Checked::new(Ufeat::from_be_hex(
                    &("0".repeat(Ufeat::BITS / 4 - 34) + "014551231950b75fc4402da1732fc9bebf"),
                )))
            .0
            .unwrap(),
            (Checked::new(two_pow256)
                - Checked::new(Ufeat::from(u32::MAX))
                    - Checked::new(Ufeat::ONE) // shifting seems cleaner for the same purpose
                - Checked::new(Ufeat::from(977u16)))
            .0
            .unwrap(),
            [0, 0, 7],
        )
    }
}
///        Controls the display in the command prompt
///         Controls the display through the print function
impl fmt::Display for EllipticCurve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "< Elliptic Curve Object >
-------------------------
    name: {}
    order: {:#x}
    a2: {:#x}
    a4: {:#x}
    a6: {:#x}
    p: {:#x}
    equation: y^2 = x^3 + a2.x^2 + a4.x + a6 (mod p)",
            self.name,
            self.order,
            self.original_coefficients[0],
            self.original_coefficients[1],
            self.original_coefficients[2],
            self.original_p
        )
    }
}

///         Overload of the == operator for two EllipticCurve objects
// ~~TODO check what happens when `order` is > `p` `modulus`~~
//      nothing particularly interesting -- they're quite disjoint, though it reminded me that I should restrict when Frobenius track is 1...
impl PartialEq for EllipticCurve {
    fn eq(&self, other: &Self) -> bool {
        self.a2 == other.a2 && self.a4 == other.a4 && self.a6 == other.a6 && self.p == other.p
    }
}
impl Eq for EllipticCurve {}
