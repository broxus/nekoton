use anyhow::Error;

pub trait TrustMe<T>: Sized {
    #[track_caller]
    fn trust_me(self) -> T;
}

impl<T, E> TrustMe<T> for Result<T, E>
where
    E: std::fmt::Debug,
{
    #[track_caller]
    fn trust_me(self) -> T {
        self.expect("Shouldn't fail")
    }
}

impl<T> TrustMe<T> for Option<T> {
    #[track_caller]
    fn trust_me(self) -> T {
        self.expect("Shouldn't fail")
    }
}
