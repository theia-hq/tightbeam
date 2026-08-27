use core::time::Duration;

use crate::duration::{Lifetime, LifetimeParseError};

#[test]
fn parses_each_unit() {
    assert_eq!(
        "90s".parse::<Lifetime>().unwrap().duration(),
        Duration::from_secs(90)
    );
    assert_eq!(
        "30m".parse::<Lifetime>().unwrap().duration(),
        Duration::from_secs(1800)
    );
    assert_eq!(
        "2h".parse::<Lifetime>().unwrap().duration(),
        Duration::from_secs(7200)
    );
    assert_eq!(
        "1d".parse::<Lifetime>().unwrap().duration(),
        Duration::from_secs(86400)
    );
}

#[test]
fn rejects_a_bad_unit() {
    assert_eq!("2y".parse::<Lifetime>(), Err(LifetimeParseError::BadUnit));
    // A bare number has its last char taken as the unit, so `2` reads as unit `2`, an unknown unit.
    assert_eq!("2".parse::<Lifetime>(), Err(LifetimeParseError::BadUnit));
}

#[test]
fn rejects_zero() {
    assert_eq!("0h".parse::<Lifetime>(), Err(LifetimeParseError::Zero));
}

#[test]
fn rejects_a_non_number() {
    assert!(matches!(
        "abch".parse::<Lifetime>(),
        Err(LifetimeParseError::BadNumber(_))
    ));
}
