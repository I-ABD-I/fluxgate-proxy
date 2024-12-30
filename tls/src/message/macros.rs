macro_rules! enum_builder {
    (
        $(#[doc = $comment:literal])*
        #[repr($uint:ty)]
        $enum_vis:vis enum $enum_name:ident
        {
            $( $enum_var:ident => $enum_val:literal),* $(,)?
        }
    ) => {
        $(#[doc = $comment])*
        #[derive(PartialEq, Eq, Clone, Copy)]
        $enum_vis enum $enum_name {
            $( $enum_var ),*
            ,Unknown($uint)
        }

        impl From<$uint> for $enum_name {
            fn from(x: $uint) -> Self {
                match x {
                    $($enum_val => $enum_name::$enum_var),*
                    , x => $enum_name::Unknown(x),
                }
            }
        }

        impl From<$enum_name> for $uint {
            fn from(value: $enum_name) -> Self {
                match value {
                    $( $enum_name::$enum_var => $enum_val),*
                    ,$enum_name::Unknown(x) => x
                }
            }
        }
    };
}
