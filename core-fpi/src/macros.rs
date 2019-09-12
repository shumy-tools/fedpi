#![macro_use]

macro_rules! loaders {
    ($($var:ident),+ $(; $def:ident)*) => (
        pub fn new<S: Into<String>>($($var: S, )* s: Scalar, key: CompressedRistretto) -> Self {
            $(
            let $var: String = $var.into();
            )*

            let data = vec![$($var.clone().into_boxed_str().into()),*];
            let esig = ExtSignature::new(s, key, &data);
            
            Self::load($($var, )* esig)
        }

        pub fn load<S: Into<String>>($($var: S, )* _esig: ExtSignature) -> Self {
            Self { $($var: $var.into(), )* esig: _esig $(, $def: Default::default())* }
        }
    )
}