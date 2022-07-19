#![cfg_attr(not(feature = "std"), no_std)]
#![feature(trace_macros)]

#[macro_use]
extern crate alloc;

// Imports for SubmittableOracle trait definition
use fat_utils::attestation;
use ink_env::AccountId;
use ink_lang as ink;
use ink_prelude::{string::String, vec::Vec};
use pink_extension as pink;

// Required trait for testing the oracle
#[ink::trait_definition]
pub trait SubmittableOracle {
    #[ink(message)]
    fn admin(&self) -> AccountId;

    #[ink(message)]
    fn verifier(&self) -> attestation::Verifier;

    #[ink(message)]
    fn attest(&self, arg: String) -> Result<attestation::Attestation, Vec<u8>>;
}

// Twitter Oracle contract
#[pink::contract(env=PinkEnvironment)]
mod twitter_oracle {
    use super::pink;
    use super::SubmittableOracle;

    use ink_prelude::{string::{String, ToString}, vec::Vec};
    use ink_prelude::vec;
    use ink_storage::traits::SpreadAllocate;
    use ink_storage::Mapping;
    use ink_env;
    use scale::{Decode, Encode};

    use fat_utils::attestation;
    use pink::logger::{Level, Logger};
    use pink::{http_get, PinkEnvironment};

    // Imports for handling JSON responses
    use ink_prelude::borrow::ToOwned;
    use serde::{Deserialize, Serialize};
    use serde_json_core;

    static LOGGER: Logger = Logger::with_max_level(Level::Info);
    pink::register_logger!(&LOGGER);

    // Function parameter to map_err for realizing serde_json's actual error
    fn from_debug(e: impl core::fmt::Debug) -> Vec<u8> {
        ink_env::debug_println!("Error: {:?}", e);
        format!("{:?}", e).into_bytes()
    }

    #[ink(storage)]
    #[derive(SpreadAllocate)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct TwitterOracle {
        admin: AccountId,
        // badge_contract_options: Option<(AccountId, u32)>,
        attestation_verifier: attestation::Verifier,
        attestation_generator: attestation::Generator,
        linked_users: Mapping<String, AccountId>,
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
        InvalidBody,
        InvalidTweets
    }

    impl TwitterOracle {

        #[ink(constructor)]
        pub fn new() -> Self {
            let (generator, verifier) = attestation::create(b"gist-attestation-key");
            let admin: AccountId = Self::env().caller();

            ink_lang::utils::initialize_contract(|this: &mut Self| {
                this.admin = admin;
                // this.badge_contract_options = None;
                this.attestation_generator = generator;
                this.attestation_verifier = verifier
            })
        }

        #[ink(message)]
        pub fn verify_identity(&mut self, attestation: attestation::Attestation) -> Result<(), Error> {

            // Verify the attestation
            let data: TweetQuote = self
                .attestation_verifier
                .verify_as(&attestation)
                .ok_or(Error::InvalidSignature)?;

            // The caller must be the attested account
            if data.account_id != self.env().caller() {
                pink::warn!("No permission.");
                return Err(Error::NoPermission);
            }

            // The twitter username can only link to one account
            if self.linked_users.contains(&data.username) {
                pink::warn!("Username already in use.");
                return Err(Error::UsernameAlreadyInUse);
            }
            self.linked_users.insert(&data.username, &data.account_id);
            Ok(())
        }
    }

    // Implement SubmittableOracle trait
    impl SubmittableOracle for TwitterOracle {

        #[ink(message)]
        fn admin(&self) -> AccountId {
            self.admin.clone()
        }

        /// The attestation verifier
        #[ink(message)]
        fn verifier(&self) -> attestation::Verifier {
            self.attestation_verifier.clone()
        }

        #[ink(message)]
        fn attest(&self, url: String) -> core::result::Result<attestation::Attestation, Vec<u8>> {

            // Get username, tweet_id from e.g. "https://twitter.com/FokChristopher/status/1546748557595930625"
            let tweet_url = parse_tweet_url(&url).map_err(|e| e.encode())?;
            ink_env::debug_println!("Tweet URL: {:?}", tweet_url);

            // Format tweet_id into api base url "https://api.twitter.com/2/tweets?ids={id}"
            let mut api_url: String = "https://api.twitter.com/2/tweets?ids=".to_owned();
            let tweet_id: &str = &tweet_url.tweet_id;
            api_url.push_str(tweet_id);
            ink_env::debug_println!("API URL {:?}", api_url);

            // Fetch like in comman line: curl "<api_url>" -H "Authorization: Bearer $BEARER_TOKEN"
            let bearer_token: String = "Bearer AAAAAAAAAAAAAAAAAAAAACXsegEAAAAAmmADAF97nZBWgu1JDKG8ALb6lf8%3DduplCmqITqrQcjsIkovyPPbsu5WY6GNrcjsamf61obQrkJbE44".to_string();
            let headers: Vec<(String, String)> = vec![("Authorization".into(), bearer_token)];
            ink_env::debug_println!("API headers {:?}", headers);

            let response = http_get!(api_url, headers);
            if response.status_code != 200 {
                return Err(Error::RequestFailed.encode());
            }
            ink_env::debug_println!("Response body: {:?}", String::from_utf8_lossy(&response.body));

            // Deserialize JSON byte array into Rust structs, e.g. {"data": [{"id": <tweet_id>, "text": <tweet>}]}
            let data: TweetData = serde_json_core::from_slice(&response.body)
                .map_err(from_debug)?
                .0;

            // Extract polkadot account ID from fetched tweet
            let account_id = extract_claim(&data).map_err(|e| e.encode())?;
            ink_env::debug_println!("Account ID: {:?}", account_id);

            // Compose twitter username <> polkadot account ID mapping
            let quote = TweetQuote { username: tweet_url.username, account_id, };

            // Generate attestation by signing the quote
            let result = self.attestation_generator.sign(quote);
            Ok(result)
        }
    }

    // Outer dictionary
    #[derive(Deserialize, Debug, Serialize)]
    pub struct TweetData<'a> {
        #[serde(borrow)]
        data: Vec<TweetDataParams<'a>>
    }

    // Inner dictionary
    #[derive(Deserialize, Debug, Serialize)]
    pub struct TweetDataParams<'a> {
        id: &'a str,
        text: &'a str
    }

    // Twitter username <> Polkadot account ID mapping to be stored
    #[derive(Clone, Encode, Decode, Debug)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct TweetQuote {
        username: String,
        account_id: AccountId,
    }

    // Get username and tweet_id from tweet url
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

    // Extract Polkadot account ID from TweetData struct (deserialized from JSON byte array)
    fn extract_claim(data: &TweetData) -> Result<AccountId, Error> {
        let text = data.data[0].text.to_string();
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

    // Decode account ID from HEX address
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
        use super::*;
        use ink_lang as ink;
        use ink_env::Clear;

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

            let params = TweetDataParams {
                id: "1426724855672541191",
                text: "This tweet is owned by address: 0x0123456789012345678901234567890123456789012345678901234567890123"
            };
            let data = TweetData { data: vec![params] };
            let ok: Result<AccountId, Error> = extract_claim(&data);
            assert_eq!(
                ok,
                decode_account_id_256(b"0123456789012345678901234567890123456789012345678901234567890123")
            );

            // Bad cases
            let params = TweetDataParams { id: "1426724855672541191", text: "This tweet is owned by address:" };
            let data = TweetData { data: vec![params] };
            assert_eq!(
                extract_claim(&data),
                Err(Error::NoClaimFound),
            );

            let params = TweetDataParams { id: "1426724855672541191", text: "This tweet is owned by address: 0xAB" };
            let data = TweetData { data: vec![params] };
            assert_eq!(
                extract_claim(&data),
                Err(Error::InvalidAddressLength),
            );

            let params = TweetDataParams { id: "1426724855672541191", text: "This tweet is owned by address: 0xXX23456789012345678901234567890123456789012345678901234567890123" };
            let data = TweetData { data: vec![params] };
            assert_eq!(
                extract_claim(&data),
                Err(Error::InvalidAddress),
            );
        }

        #[ink::test]
        fn can_attest_http_get() {

            // Import Phala's test suite: mock accounts and mock http responses
            use pink_extension::chain_extension::{mock, HttpResponse};
            use ink_env::test::{default_accounts, DefaultAccounts};

            fat_utils::test_helper::mock_all();
            let accounts: DefaultAccounts<PinkEnvironment> = default_accounts();

            // Instantiate contract
            let contract = TwitterOracle::new();

            // Test JSON byte array from twitter API
            let json: &str = r#"{"data":[{"id":"1426724855672541191","text":"This tweet is owned by address: 0x0101010101010101010101010101010101010101010101010101010101010101"}]}"#;
            let body = json.as_bytes();
            mock::mock_http_request(|_| { HttpResponse::ok(body.to_vec()) });

            // Test generate attestation
            let result = contract.attest(
                "https://twitter.com/FokChristopher/status/1546748557595930625".to_string());
            assert!(result.is_ok());

            // Test decode attestation data
            let attestation = result.unwrap();
            let data: TweetQuote = Decode::decode(&mut &attestation.data[..]).unwrap();
            assert_eq!(data.username, "FokChristopher");
            assert_eq!(data.account_id, accounts.alice);
        }

        #[ink::test]
        fn can_verify_identify() {

            // Import Openbrush and Phala's test suite
            use openbrush::traits::mock::{Addressable, SharedCallStack};
            use ink_env::test::{default_accounts, DefaultAccounts};
            use pink_extension::chain_extension::{mock, HttpResponse};
            fat_utils::test_helper::mock_all();

            // Instantiate contract with Alice account
            let accounts: DefaultAccounts<PinkEnvironment> = default_accounts();
            let stack = SharedCallStack::new(accounts.alice);
            let contract = Addressable::create_native(1, TwitterOracle::new(), stack);

            // Test JSON byte array from twitter API
            let json: &str = r#"{"data":[{"id":"1426724855672541191","text":"This tweet is owned by address: 0x0101010101010101010101010101010101010101010101010101010101010101"}]}"#;
            let body = json.as_bytes();
            mock::mock_http_request(|_| { HttpResponse::ok(body.to_vec()) });

            // Attest API Response
            let res = contract
                .call()
                .attest(
                "https://twitter.com/FokChristopher/status/1546748557595930625".to_string());
            let attestation = res.unwrap();

            // Add it to linked users
            let result = contract
                .call_mut()
                .verify_identity(attestation);

            assert!(result.is_ok());
            assert_eq!(
                contract.call().linked_users.get("FokChristopher").unwrap(),
                accounts.alice );
        }
    }
}