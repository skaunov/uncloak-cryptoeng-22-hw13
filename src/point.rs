use super::{non_adjacent, EllipticCurve, Errs, Ufeat};
use crypto_bigint::modular::runtime_mod::DynResidue;
use std::{fmt, ops::Neg, rc::Rc};

const MSG_ASSIGNS_SHOULD_NOT_FAIL: &str = "use Assign traits only if you're sure it won't fail";

// #[derive(PartialEq, Eq, Clone, Copy)]
// enum PointType {
//     infinite, regular
// }
///     Point of an elliptic curve
#[derive(/* PartialEq,  */ Eq, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Point {
    AtInfinity {
        curve: Rc<EllipticCurve>,
    },
    Regular {
        x: DynResidue<{ Ufeat::LIMBS }>,
        y: DynResidue<{ Ufeat::LIMBS }>,
        // type_: PointType,
        // curve: /* &'curve */ EllipticCurve
        curve: Rc<EllipticCurve>,
    },
}

// impl Point::Point_regular {
//     pub fn x(&self) -> DynResidue<{Ufeat::LIMBS}> {&self.x}
//     pub fn y(&self) -> DynResidue<{Ufeat::LIMBS}> {&self.y}
//     // pub fn curve(&self) -> Rc<EllipticCurve> {&self.curve}
// }

impl Point /* <'_> */ {
    #[inline]
    pub fn new(
        curve: Rc<EllipticCurve>,
        x: Option<Ufeat>,
        y: Option<Ufeat>,
    ) -> Result<Point, Errs> {
        let (x_original, y_original) = (x.unwrap_or_default(), y.unwrap_or_default()); // dunb line to logically separate source migration and NCC-based addition

        // should notice that it's disputable design from a few angles; can't say I fond of the approach
        // let type_ = if x.is_some() {PointType::regular} else {PointType::infinite};
        if x.is_none() {
            return Ok(Point::AtInfinity { curve });
        };

        let (x, y) = (
            DynResidue::new(&x.unwrap(), *curve.p()),
            DynResidue::new(&y.unwrap(), *curve.p()),
        );

        // here's start of the added checks listed at https://research.nccgroup.com/2021/11/18/an-illustrated-guide-to-elliptic-curve-cryptography-validation
        if x_original >= curve.original_p() || y_original >= curve.original_p() {
            return Err(Errs::NccModulus);
        }
        let curve_ = Rc::clone(&curve);
        let result = Point::Regular { x, y, curve };
        if !EllipticCurve::contains(curve_.as_ref(), &result) {
            return Err(Errs::NccOutOfTheCurve);
        }
        // points at infinity are allowed to create, just not as a silent default
        // this implementation won't check subgroups as defining acceptable criteria would drive the exercise way off

        Ok(result)
    }
    pub fn x(&self) -> Option<&DynResidue<{ Ufeat::LIMBS }>> {
        if let Point::Regular { x, y: _, curve: _ } = self {
            Some(x)
        } else {
            None
        }
    }
    pub fn y(&self) -> Option<&DynResidue<{ Ufeat::LIMBS }>> {
        if let Point::Regular { x: _, y, curve: _ } = self {
            Some(y)
        } else {
            None
        }
    }
    pub fn curve(&self) -> Rc<EllipticCurve> {
        match self {
            Point::AtInfinity { curve } => Rc::clone(curve),
            Point::Regular { x: _, y: _, curve } => Rc::clone(curve),
        }
    }
    /// in format suitable for creating `new`
    pub fn get(&self) -> (&EllipticCurve, Option<Ufeat>, Option<Ufeat>) {
        match self {
            Point::AtInfinity { curve } => (curve, None, None),
            Point::Regular { x, y, curve } => (curve, Some(x.retrieve()), Some(y.retrieve())),
        }
    }

    // #[inline]
    // fn helper_new_point_at_infinity(&self) -> Self {
    //     // Point{curve: self.curve.clone(), ..Default::default()}
    //     Point::new(self.curve.clone(), None, Default::default()).expect("point at infinity creation doesn't fail")

    //     // let mut result = Point::default();
    //     // result.curve = Rc::clone(&self.curve);
    //     // return result;
    // }
}
/// Default point: Infinite point of Secp256k1 curve
#[cfg(test)]
impl Default for Point /* <'_> */ {
    #[inline]
    fn default() -> Self {
        // Point::new(*Box::new(EllipticCurve::default()), None, None)
        Point::new(Rc::new(EllipticCurve::default()), None, None)
            .expect("point at infinity creation doesn't fail")
    }
}
///         Controls the display in the command prompt
///         Controls the display through the print function
impl fmt::Display for Point /* <'_> */ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Point::Regular { x, y, curve } => {
                write!(
                    f,
                    "< Point object of Elliptic curve {} >\n--------------------------------------------\nx: {:x}\ny: {:x}\n",
                    curve.name, x.retrieve(), y.retrieve()
                )
            }
            Point::AtInfinity { curve } => {
                write!(
                    f,
                    "< Point object of Elliptic curve {} >\n--------------------------------------------\nInfinite Point\n",
                    curve.name
                )
            }
        }
    }
}
///         Overload of the == operator for two Point objects
impl PartialEq for Point {
    fn eq(&self, other: &Self) -> bool {
        // ~~TODO replace to `return false`, but for debugging it's better to panic~~
        // if self.curve != other.curve {panic!("comparison of points from different curves")}
        if self.curve() != other.curve() {
            return false;
        }

        match (self, other) {
            (
                Point::AtInfinity { curve: _ },
                Point::Regular {
                    curve: _,
                    x: _,
                    y: _,
                },
            ) => false,
            (
                Point::Regular {
                    x: _,
                    y: _,
                    curve: _,
                },
                Point::AtInfinity { curve: _ },
            ) => false,
            (Point::AtInfinity { curve: _ }, Point::AtInfinity { curve: _ }) => true,
            (
                Point::Regular {
                    x: self_x,
                    y: self_y,
                    curve: _,
                },
                Point::Regular {
                    x: other_x,
                    y: other_y,
                    curve: _,
                },
            ) => (self_x == other_x) && (self_y == other_y),
        }
        // /* it would be cleaner if source would derive point type from presence of value in both of its coordinates */
        // if self.type_ != other.type_ {return false;}
        // if let (PointType::infinite, PointType::infinite) = (self.type_, other.type_) {
        //     return true;
        // };
        // let have_self_none = self.x.is_none() || self.y.is_none();
        // let have_other_none = other.x.is_none() || other.y.is_none();
        // if have_self_none && have_other_none {return true;}
        // // at this point we know that `type_` of both are `regular`
        // if (self.x == other.x) && (self.y == other.y) {true}
        // else {false}
    }
}
///         Gives the symmetric point of the object
impl std::ops::Neg for &Point /* <'_> */ {
    type Output = Point;
    fn neg(self) -> Self::Output {
        match self {
            Point::Regular{ x, y, curve } =>
                /* ~~TODO check for y < p is needed due to~~
                    * the method docs
                        // this one was solved by switching to DynRes...
                    * NCC res. group page https://research.nccgroup.com/2021/11/18/an-illustrated-guide-to-elliptic-curve-cryptography-validation/#general */
                        // ~~Since we're here TODO a branch regarding this one.~~
                            /* after reading this page (which was linked at [session 8](https://uncloak.org/courses/rust+cryptography+engineering/course-2023-01-20+Session+8+Notes)) I feel that defaulting to point at 
                            infinity actually forms a bad habbit, so let me try to feature-gate this behavior instead of branching the recommendations on validation, so that defaulting to point at infinity would be opt-in
                                // turned out no need to introduce another feature, just hid `Point::default` behind `test` macro, so that it would be only available to conform https://github.com/cjeudy/EllipticCurves/blob/master/example.py
                                unfortunately I don't see a way to preserve the core of the exercise (migrating existing repo to Rust) and make the crate to default to a good generator, so maybe defaulting to 
                                _a_ generator would be good enough */
                    // solved via proper creation of the `Point` via `new` method; I wonder if there's a way to forbid construction of some types in code... `mod`s?
                Point::Regular { x: *x, y: y.neg(), curve: Rc::clone(curve) } /* {
                    x: self.x, 
                    // y: Some(self.y.unwrap().neg_mod(&self.curve.p_original)), 
                    y: Some(self.y.unwrap().neg()), 
                    type_: self.type_, 
                    curve: self.curve.clone()
                } */,
            Point::AtInfinity { curve: _ } => self.clone()
        }
    }
}
// impl std::ops::Neg for Point {
//     type Output = Point;
//     fn neg(self) -> Self::Output {
//         // let result: Point = &self.neg();
//         // result
//         <&Point as std::ops::Neg>::neg(&self)
//     }
// }
///        Overload of the + operator for two `&Point` objects (+ is commutative)
impl std::ops::Add for &Point /* <'_> */ {
    type Output = Result<Point, Errs>;
    fn add(self, point: Self) -> Self::Output {
        match point {
            Point::AtInfinity { curve: _ } => Ok(self.clone()),
            Point::Regular {
                x: point_x_dynres,
                y: point_y_dynres,
                curve: _,
            } => {
                match self {
                    Point::AtInfinity { curve: _ } => Ok(point.clone()),
                    Point::Regular {
                        x: self_x_dynres,
                        y: self_y_dynres,
                        curve,
                    } => {
                        if point == &self.neg() {
                            return Ok(Point::AtInfinity {
                                curve: Rc::clone(curve),
                            });
                        }
                        let /* (invL,  */lambd/* ) */ = {
                            if self == point {
                                // if self.y.unwrap() == Ufeat::ZERO {return self.helper_new_point_at_infinity();}
                                if *self_y_dynres == DynResidue::zero(*curve.p()) {return Ok(Point::AtInfinity { curve: Rc::clone(curve) });}

                                // let L: U8192 = self.y.unwrap().checked_mul(&U8192::from(2u8)).unwrap() % self.curve.p;
                                // let L = (DynResidue::new(&self.y.unwrap(), dynres_p) * DynResidue::new(&U8192::from(2u8), dynres_p)).retrieve();
                                let two_dynres = DynResidue::new(&Ufeat::from(2u8), *curve.p());
                                #[allow(non_snake_case)]
                                let L = self_y_dynres * two_dynres;
                                #[allow(non_snake_case)]
                                let invL = L.invert().0;
                                // let self_x_square = {
                                //     let x_sq = self_x.square_wide();
                                //     if x_sq.1 == U8192::ZERO {x_sq.0 % self.curve.p}
                                //     else {panic!("Field is too big for this implementation. Couldn't square _x_.")}
                                // };
                                // let self_x_square = self_x.square_wide().0 % self.curve.p;

                                invL * (
                                    self_x_dynres.square() * DynResidue::new(&Ufeat::from(3u8), *curve.p())
                                    + self_x_dynres * curve.a2() * two_dynres
                                    + curve.a4()
                                )
                            }
                            else {
                                #[allow(non_snake_case)]
                                let invL = (point_x_dynres - self_x_dynres).invert().0;
                                (point_y_dynres - self_y_dynres) * invL
                            }
                        };
                        let x = lambd.square() - curve.a2() - self_x_dynres - point_x_dynres;
                        // let y = lambd.checked_mul(&self_x.sub_mod(&x, &self.curve.p)).unwrap() % self.curve.p;
                        let y = lambd * (self_x_dynres - x) - self_y_dynres;
                        // let y = y.sub_mod(&self.y.unwrap(), &self.curve.p);

                        // let M = Point::new(self.curve, Some(x.retrieve()), Some(y.retrieve()));
                        #[allow(non_snake_case)]
                        let M = Point::Regular {
                            x,
                            y,
                            curve: Rc::clone(curve),
                        }; //{curve: Rc::clone(&self.curve), x: Some(x), y: Some(y), type_: PointType::regular};
                        if EllipticCurve::contains(curve, &M) {
                            Ok(M)
                        }
                        // ~~TODO is there a more graceful way? Given that trait isn't suitable for `Result`.~~
                        //      turns out that `Add` actually *can* return `Result`!
                        else {
                            Err(Errs::ValueError)
                        }
                    }
                }
            }
        }
    }
}
/// Overload of the + operator for two Point objects (+ is commutative)
impl std::ops::Add for Point /* <'_> */ {
    type Output = Result<Self, Errs>;
    fn add(self, rhs: Self) -> Self::Output {
        &self + &rhs
    }
}
//      ~~TODO~~ `AddAssign` needs Deref https://github.com/cjeudy/EllipticCurves/blob/77ec97ff1de146e03dd65c36813c0aad61254242/EC.py#L231
// impl std::ops::Deref for Point {
//     type Target: ?Sized;
//     fn deref(&self) -> &Self::Target {
//         &self.
//     }
// }
// impl std::ops::Add<&Point> for &mut Point {
//     type Output = Result<Point, Errs>;
//     fn add(self, rhs: &Point) -> Self::Output {
//         Ok((*self + *rhs)?)
//     }
// }
///         Overload of the += operator for two Point objects
impl std::ops::AddAssign for Point {
    fn add_assign(&mut self, rhs: Self) {
        // let tmp = self;
        // *self = tmp.add(rhs);
        *self = (self.clone() + rhs).expect(MSG_ASSIGNS_SHOULD_NOT_FAIL);
    }
}
///         Overload of the - operator for two `&Point` objects
impl std::ops::Sub for &Point /* <'_> */ {
    type Output = Result<Point, Errs>;
    fn sub(self, rhs: Self) -> Self::Output {
        self + &-rhs
    }
}
///         Overload of the - operator for two Point objects
impl std::ops::Sub for Point /* <'_> */ {
    type Output = Result<Self, Errs>;
    fn sub(self, rhs: Self) -> Self::Output {
        &self - &rhs
        // let tmp = &self;
        // tmp - &rhs
    }
}
///        Overload of the - operator for two Point objects
impl std::ops::SubAssign for Point {
    fn sub_assign(&mut self, rhs: Self) {
        // let tmp = self;
        // *self = tmp.add(rhs);
        *self = (self.clone() - rhs).expect(MSG_ASSIGNS_SHOULD_NOT_FAIL);
    }
}
/// Overload of the * operator for a Point and an integer
impl std::ops::Mul<Ufeat> for &Point /* <'_> */ {
    type Output = Result<Point, Errs>;
    fn mul(self, rhs: Ufeat) -> Self::Output {
        // println!("DEBUG: is `self` a correct point? {}", self.curve().contains(self));
        // println!("DEBUG: is double `self` a correct point? {}", (self + self).is_ok()); //.curve().contains(self));
        let non_adj_repr = non_adjacent(rhs);
        // let length = non_adj_repr.len();
        // println!("DEBUG: l {}", non_adj_repr.len());
        // let mut R = Point::default();
        // R.curve = Rc::clone(&self.curve);
        /* a small trick which I should think over again: `&Point` can't be dereferencing, and I feel like I shouldn't `impl` a _deref_ for it, and the simplest way to
        obtain `Point` and avoid troubles with short lived values inside following cycle is just to add a reference to _point at infinity_, which yields a new `Point`,
        but actually do nothing to with the value itself as it's _identity_ element */
        //      which turned out to be the same to `self.clone()`
        // let mut self_ = self + &self.helper_new_point_at_infinity();
        Ok(non_adj_repr
            .iter()
            .fold(
                // Ok((Point{curve: Rc::clone(&self.curve), ..Default::default()}, self.clone())),
                // TODO return here to understand `Rc` dereferencing
                // Ok((Point::new(self.curve.clone(), None, Default::default())?, self.clone())),
                Ok((
                    Point::AtInfinity {
                        curve: self.curve(),
                    },
                    self.clone(),
                )),
                |b_tuple_result_runner, ternary_sign| {
                    let (result, runner) = b_tuple_result_runner?;
                    // println!("DEBUG: res is {result}");
                    // println!("DEBUG: runner is {runner}");
                    // println!("DEBUG: sign is {ternary_sign}");
                    Ok((
                        match ternary_sign {
                            1 => (&result + &runner)?,
                            -1 => (&result - &runner)?,
                            0 => result,
                            _ => panic!("other values in `non_adj_repr` aren't expected"),
                        },
                        (&runner + &runner)?,
                    ))
                },
            )?
            .0)
        // for i in 0..length {
        //     println!("DEBUG:`mul` round {i}");
        //     match non_adj_repr[i] {
        //         // ~~TODO evade excesiive cloning~~
        //         1 => R += self_.clone(),
        //         -1 => R -= self_.clone(),
        //         _ => {}
        //     }
        //     self_ += self_.clone()
        // }
        // R
    }
}
impl std::ops::Mul<Ufeat> for Point {
    type Output = Result<Point, Errs>;
    fn mul(self, rhs: Ufeat) -> Self::Output {
        &self * rhs
    }
}
///   Overload of the * operator for a Point and an integer (* is commutative)
impl std::ops::Mul<&Point> for Ufeat {
    type Output = Result<Point, Errs>;
    fn mul(self, rhs: &Point) -> Self::Output {
        rhs * self
    }
}
// impl std::ops::Mul<Ufeat> for &mut Point {
//     type Output = Result<Point, Errs>;
//     fn mul(self, rhs: Ufeat) -> Self::Output {
//         Ok((*self * rhs)?)
//     }
// }
///         Overload of the *= operator for a Point and an integer
// ~~TODO is it possible not to `clone` in ...Assign traits `impl`s?~~
//      it seems to me that with plain borrowing the answer is more or less "no": `AddAssign` `impl` would need to clone to be able to move the value out of exclusive borrow
//      I guess it could be possible with more complex and smart pointers, but as soon as `Point` consists of lightweight `Rc` and `Copy`-types -- there will be no benefit from taking this path
impl std::ops::MulAssign<Ufeat> for Point {
    fn mul_assign(&mut self, rhs: Ufeat) {
        *self = (self.clone() * rhs).expect(MSG_ASSIGNS_SHOULD_NOT_FAIL);
    }
}
