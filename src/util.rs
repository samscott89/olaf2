use oauth2::prelude::*;
use serde::{de::Error, Deserialize, Serialize};
use serde_derive::{Deserialize, Serialize};
use url::Url;

use std::ops::Deref;

pub mod serde_newtype {
	use super::*;

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
        where D: serde::Deserializer<'de>,
              T: NewType<String>,
    {
        String::deserialize(deserializer).map(T::new)
    }

    pub fn serialize<S, T>(secret: &T, serializer: S) -> Result<S::Ok, S::Error>
        where S: serde::Serializer,
              T: NewType<String> + Deref<Target=String>,
    {
        serializer.serialize_str(&secret.deref())
    } 
}

pub mod serde_newtype_url {
	use super::*;

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
        where D: serde::Deserializer<'de>,
              T: NewType<Url>,
    {
        url_serde::deserialize(deserializer).map(T::new)
    }

    pub fn serialize<S, T>(secret: &T, serializer: S) -> Result<S::Ok, S::Error>
        where S: serde::Serializer,
              T: NewType<Url> + Deref<Target=Url>,
    {
        serializer.serialize_str(&secret.deref().to_string())
    } 
}

pub mod serde_secret_newtype {
	use super::*;

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
        where D: serde::Deserializer<'de>,
              T: SecretNewType<String>
    {
        String::deserialize(deserializer).map(T::new)
    }

    pub fn serialize<S, T>(secret: &T, serializer: S) -> Result<S::Ok, S::Error>
        where S: serde::Serializer,
              T: SecretNewType<String>,
    {
        serializer.serialize_str(secret.secret())
    } 
}

pub mod serde_newtype_vec {
	use super::*;

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
        where D: serde::Deserializer<'de>,
              T: NewType<String>
    {
        <Vec<String> as Deserialize>::deserialize(deserializer)
        	.map(|v| v.into_iter().map(T::new).collect())
    }

    pub fn serialize<S, T>(val: &[T], serializer: S) -> Result<S::Ok, S::Error>
        where S: serde::Serializer,
              T: NewType<String> + Deref<Target=String>,
    {
    	serializer.collect_seq(val.iter().map(|x| x.deref()))
    } 
}
