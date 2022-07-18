#![cfg_attr(not(feature = "std"), no_std)]
#![feature(trace_macros)]

use fat_utils::attestation;
use ink_env::AccountId;
use ink_lang as ink;
use ink_prelude::{string::String, vec::Vec};
use pink_extension as pink;

#[ink::trait_definition]
pub trait SubmittableOracle {
    #[ink(message)]
    fn admin(&self) -> AccountId;

    #[ink(message)]
    fn verifier(&self) -> attestation::Verifier;

    #[ink(message)]
    fn attest(&self, arg: String) -> Result<attestation::Attestation, Vec<u8>>;
}

#[pink::contract(env=PinkEnvironment)]
mod twitter_oracle {
    use super::pink;
    use super::SubmittableOracle;

    use ink_prelude::{string::{String, ToString}, vec::Vec};
    use ink_prelude::vec;
    use ink_storage::traits::SpreadAllocate;
    use ink_storage::Mapping;
    use pink::{http_get, PinkEnvironment};
    use scale::{Decode, Encode};
    use fat_utils::attestation;

    use ink_prelude::borrow::ToOwned;
    use serde::Deserialize;
    use serde_json_core;

    #[ink(storage)]
    #[derive(SpreadAllocate)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct TwitterOracle {
        admin: AccountId,
        badge_contract_options: Option<(AccountId, u32)>,
        attestation_verifier: attestation::Verifier,
        attestation_generator: attestation::Generator,
        linked_users: Mapping<String, ()>,
    }

    #[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        BadOrigin,
        BadgeContractNotSetUp,
        InvalidUrl,
        RequestFailed,
        NoClaimFound,
        InvalidAddressLength,
        InvalidAddress,
        NoPermission,
        InvalidSignature,
        UsernameAlreadyInUse,
        AccountAlreadyInUse,
        FailedToIssueBadge,
        InvalidBody
    }

    impl TwitterOracle {

        #[ink(constructor)]
        pub fn new() -> Self {
            let (generator, verifier) = attestation::create(b"gist-attestation-key");
            let admin: AccountId = Self::env().caller();

            ink_lang::utils::initialize_contract(|this: &mut Self| {
                this.admin = admin;
                this.badge_contract_options = None;
                this.attestation_generator = generator;
                this.attestation_verifier = verifier
            })
        }

    }

    impl SubmittableOracle for TwitterOracle {

        #[ink(message)]
        fn attest(&self, url: String) -> core::result::Result<attestation::Attestation, Vec<u8>> {

            // Get username, tweet_id from "https://twitter.com/FokChristopher/status/1546748557595930625"
            let tweet_url = parse_tweet_url(&url).map_err(|e| e.encode())?;

            // Format API url with tweet_id in "https://api.twitter.com/2/tweets?ids={id}"
            let mut req_url: String = "https://api.twitter.com/2/tweets?ids=".to_owned();
            let tweet_id: &str = &tweet_url.tweet_id;
            req_url.push_str(tweet_id);

            // Fetch the tweet content: curl "https://api.twitter.com/2/tweets?ids=1426724855672541191" -H "Authorization: Bearer $BEARER_TOKEN"
            let bearer_token: String = "Bearer AAAAAAAAAAAAAAAAAAAAACXsegEAAAAAmmADAF97nZBWgu1JDKG8ALb6lf8%3DduplCmqITqrQcjsIkovyPPbsu5WY6GNrcjsamf61obQrkJbE44".to_string();
            let headers: Vec<(String, String)> = vec![("Authorization".into(), bearer_token)];
            let response = http_get!(req_url, headers);
            if response.status_code != 200 {
                return Err(Error::RequestFailed.encode());
            }

            // TODO: Parse JSON body {"data": [{"id": <tweet_id>, "text": <tweet_content>}], e.g. {"data":[{"id":"1426724855672541191","text":"This tweet belongs to address:... "}]}
            let body = response.body;
            let account_id = extract_claim(&body).map_err(|e| e.encode())?;
            let content = TweetContent { username: tweet_url.username, account_id, };
            let result = self.attestation_generator.sign(content);
            Ok(result)
        }

        #[ink(message)]
        fn admin(&self) -> AccountId {
            self.admin.clone()
        }

        /// The attestation verifier
        #[ink(message)]
        fn verifier(&self) -> attestation::Verifier {
            self.attestation_verifier.clone()
        }
    }

    // TODO: Create struct for JSON to deserialize into {"data": [{"id": <tweet_id>, "text": <tweet_content>}]}
    #[derive(Deserialize, Debug)]
    pub struct Data<'a> {
        #[serde(borrow)]
        data: Vec<Params<'a>>
    }

    // TODO: Create struct for JSON to deserialize into {"data": [{"id": <tweet_id>, "text": <tweet_content>}]}
    #[derive(Deserialize, Debug)]
    pub struct Params<'a> {
        id: &'a str,
        text: &'a str
    }

    #[derive(Clone, Encode, Decode, Debug)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct TweetContent {
        username: String,
        account_id: AccountId,
    }

    fn parse_tweet_url(url: &str) -> Result<TweetURL, Error> {
        let path = url
            .strip_prefix("https://twitter.com/")
            .ok_or(Error::InvalidUrl)?;
        let components: Vec<_> = path.split('/').collect(); // e.g. Vec!["FokChristopher", "status", "1546748557595930625"]
        if components.len() < 3 {
            return Err(Error::InvalidUrl);
        }
        Ok(TweetURL {
            username: components[0].to_string(),
            tweet_id: components[2].to_string(),
        })
    }

    #[derive(PartialEq, Eq, Debug)]
    struct TweetURL { // e.g. "https://twitter.com/FokChristopher/status/1546748557595930625"
        username: String, // e.g. FokChristopher
        tweet_id: String, // e.g. 1546748557595930625
    }

    const CLAIM_PREFIX: &str = "This tweet is owned by address: 0x";
    const ADDRESS_LEN: usize = 64;

    fn extract_claim(body: &[u8]) -> Result<AccountId, Error> {

        // TODO: extract actual tweet from bytes of JSON text
        let (data, _): (Data, usize) =
                serde_json_core::from_slice(body).or(Err(Error::InvalidBody))?;
        let text: &str = data.data[0].text;

        let pos = text.find(CLAIM_PREFIX).ok_or(Error::NoClaimFound)?;
        let addr: String = text
            .chars()
            .skip(pos)
            .skip(CLAIM_PREFIX.len())
            .take(ADDRESS_LEN)
            .collect();
        let addr: &[u8] = addr.as_bytes();
        let account_id = decode_account_id_256(addr)?;
        Ok(account_id)
    }

    fn decode_account_id_256(addr: &[u8]) -> Result<AccountId, Error> {
        use hex::FromHex;
        if addr.len() != ADDRESS_LEN {
            return Err(Error::InvalidAddressLength);
        }
        let bytes = <[u8; 32]>::from_hex(addr).or(Err(Error::InvalidAddress))?;
        Ok(AccountId::from(bytes))
    }

    #[cfg(test)]
    mod tests {
        use ink_env::test::{default_accounts, DefaultAccounts};
        use super::*;
        use ink_lang as ink;

        #[ink::test]
        fn can_parse_tweet_url() {
            let url: String = "https://twitter.com/FokChristopher/status/1546748557595930625".to_string();
            let result: Result<TweetURL, Error> = parse_tweet_url(&url);
            assert_eq!(
                result,
                Ok(TweetURL {
                    username: "FokChristopher".to_string(),
                    tweet_id: "1546748557595930625".to_string(),
                })
            );
            let err: Result<TweetURL, Error> = parse_tweet_url("http://example.com");
            assert_eq!(err, Err(Error::InvalidUrl));
        }

        #[ink::test]
        fn can_decode_claim() {

            // Test JSON response from twitter API
            let json: &str = r#"{"{"data":[{"id":"1426724855672541191","text":"This tweet belongs to address: 0123456789012345678901234567890123456789012345678901234567890123"}]}"#;
            let body = json.as_bytes();

            let ok: Result<AccountId, Error> = extract_claim(body);
            assert_eq!(
                ok,
                decode_account_id_256(
                    b"0123456789012345678901234567890123456789012345678901234567890123"
                )
            );
            // Bad cases
            assert_eq!(
                extract_claim(b"This tweet is owned by"),
                Err(Error::NoClaimFound),
            );
            assert_eq!(
                extract_claim(b"This tweet is owned by address: 0xAB"),
                Err(Error::InvalidAddressLength),
            );
            assert_eq!(
                extract_claim(b"This tweet is owned by address: 0xXX23456789012345678901234567890123456789012345678901234567890123"),
                Err(Error::InvalidAddress),
            );
        }

        #[ink::test]
        fn can_attest_http_get() {

            // import Phala's test suite?
            use pink_extension::chain_extension::{mock, HttpResponse};
            fat_utils::test_helper::mock_all();
            let accounts: DefaultAccounts<PinkEnvironment> = default_accounts();

            let mut contract = TwitterOracle::new();

            mock::mock_http_request(|_| {
                HttpResponse::ok(
                    b"This tweet is owned by address: 0x0101010101010101010101010101010101010101010101010101010101010101".to_vec())
            });
            let result = contract.attest(
                "https://twitter.com/FokChristopher/status/1546748557595930625".to_string());
            assert!(result.is_ok());

            let attestation = result.unwrap();
            let data: TweetContent = Decode::decode(&mut &attestation.data[..]).unwrap();
            assert_eq!(data.username, "FokChristopher");
            assert_eq!(data.account_id, accounts.alice);
        }
    }
}
