    use curve25519_dalek::scalar::Scalar;
    use rand_os::OsRng;

    pub fn rnd_scalar() -> Scalar {
        let mut csprng: OsRng = OsRng::new().unwrap();
        Scalar::random(&mut csprng)
    }