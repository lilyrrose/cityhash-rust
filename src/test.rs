#[macro_export]
macro_rules! define_test {
    ($bits:expr, $input_size:expr, $input:literal, $expected_output:expr) => {
        paste::item! {
            #[test]
            fn [<bits_ $bits _$input_size>]() {
                assert_eq!(super::[<city_hash_$bits>]($input), $expected_output);
            }
        }
    };
}
