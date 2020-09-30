// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.

macro_rules! impl_serde {
    ($w : ident) => {
        impl Serialize for $w {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_bytes(&self.to_bytes()[..])
            }
        }

        impl<'de> Deserialize<'de> for $w {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct StructVisitor;

                impl<'de> Visitor<'de> for StructVisitor {
                    type Value = $w;

                    fn expecting(
                        &self,
                        formatter: &mut ::core::fmt::Formatter,
                    ) -> ::core::fmt::Result {
                        let struct_name = String::from(stringify!($w));
                        formatter.write_fmt(format_args!("expected a valid {}", struct_name))
                    }

                    fn visit_bytes<E>(self, v: &[u8]) -> Result<$w, E>
                    where
                        E: serde::de::Error,
                    {
                        return $w::from_bytes(v).map_err(serde::de::Error::custom);
                    }
                }

                deserializer.deserialize_bytes(StructVisitor)
            }
        }
    };
}
