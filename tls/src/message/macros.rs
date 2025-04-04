/// Macro to generate an enum with associated values and implement common traits and methods.
///
/// This macro generates an enum with the specified variants and their associated values.
/// It also implements the `PartialEq`, `Eq`, `Clone`, `Copy`, and `Debug` traits for the enum.
/// Additionally, it provides methods for encoding and decoding the enum, and converting between the enum and its underlying integer type.
///
/// # Arguments
/// * `comment` - Documentation comment for the enum.
/// * `uint` - The underlying integer type for the enum.
/// * `enum_vis` - The visibility of the enum.
/// * `enum_name` - The name of the enum.
/// * `enum_var` - The name of an enum variant.
/// * `enum_val` - The value associated with the enum variant.
#[macro_export]
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
        #[derive(PartialEq, Eq, Clone, Copy, Debug)]
        $enum_vis enum $enum_name {
            $( $enum_var ),*
            ,Unknown($uint)
        }

        impl $enum_name {
            /// Converts the enum variant to an array of bytes.
            ///
            /// # Returns
            /// * `[u8; core::mem::size_of::<$uint>()]` - The byte array representation of the enum variant.
            $enum_vis fn to_array(self) -> [u8; core::mem::size_of::<$uint>()] {
                <$uint>::from(self).to_be_bytes()
            }
        }

        impl Codec<'_> for $enum_name {
            /// Encodes the enum variant into a byte vector.
            ///
            /// # Arguments
            /// * `bytes` - A mutable reference to a vector of bytes where the encoded data will be stored.
            fn encode(&self, bytes: &mut Vec<u8>) {
                <$uint>::from(*self).encode(bytes);
            }

            /// Reads and decodes an enum variant from a byte slice.
            ///
            /// # Arguments
            /// * `r` - A mutable reference to a `Reader` that provides the byte slice to read from.
            ///
            /// # Returns
            /// * `Result<Self, InvalidMessage>` - The decoded enum variant or an error if decoding fails.
            fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
                match <$uint>::read(r) {
                    Ok(x) => Ok($enum_name::from(x)),
                    Err(_) => Err($crate::error::InvalidMessage::MissingData(stringify!($enum_name))),
                }
            }
        }

        impl From<$uint> for $enum_name {
            /// Converts an integer value to the corresponding enum variant.
            ///
            /// # Arguments
            /// * `x` - The integer value to convert.
            ///
            /// # Returns
            /// * `Self` - The corresponding enum variant.
            fn from(x: $uint) -> Self {
                match x {
                    $($enum_val => $enum_name::$enum_var),*
                    , x => $enum_name::Unknown(x),
                }
            }
        }

        impl From<$enum_name> for $uint {
            /// Converts an enum variant to its underlying integer value.
            ///
            /// # Arguments
            /// * `value` - The enum variant to convert.
            ///
            /// # Returns
            /// * `Self` - The underlying integer value of the enum variant.
            fn from(value: $enum_name) -> Self {
                match value {
                    $( $enum_name::$enum_var => $enum_val),*
                    ,$enum_name::Unknown(x) => x
                }
            }
        }
    };
}