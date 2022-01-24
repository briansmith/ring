use ring::{hpke, test, test_file};
use std::str::FromStr;

#[derive(Debug, PartialEq)]
enum SectionType {
    Setup,
    Encryption,
    Exporter,
}

impl FromStr for SectionType {
    type Err = ();
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "setup" => Ok(SectionType::Setup),
            "enc" => Ok(SectionType::Encryption),
            "exp" => Ok(SectionType::Exporter),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
struct Setup {
    mode: usize,
    kem_id: usize,
    kdf_id: usize,
    aead_id: usize,
    info: Vec<u8>,
    ikm_e: Vec<u8>,
    pke_m: Vec<u8>,
    ske_m: Vec<u8>,
    ikm_r: Vec<u8>,
    pkr_m: Vec<u8>,
    skr_m: Vec<u8>,
    enc: Vec<u8>,
    shared_secret: Vec<u8>,
    key_schedule_context: Vec<u8>,
    secret: Vec<u8>,
    key: Vec<u8>,
    base_nonce: Vec<u8>,
    exporter_secret: Vec<u8>,
}

struct Context {
    client_ctx: Option<hpke::SenderContext>,
    server_ctx: Option<hpke::ReceiverContext>,
    suite: Option<hpke::Suite>,
    seq: u64,
}

#[derive(Debug, Default, Clone, PartialEq)]
struct Enc {
    sequence_number: usize,
    pt: Vec<u8>,
    aad: Vec<u8>,
    nonce: Vec<u8>,
    ct: Vec<u8>,
}

#[derive(Debug, Default, Clone, PartialEq)]
struct Exp {
    exporter_ctx: Vec<u8>,
    len: usize,
    exported: Vec<u8>,
}

#[test]
fn hpke_tests() {
    let mut latest_s = Setup::default();
    let mut ctx = Context {
        client_ctx: None,
        server_ctx: None,
        suite: None,
        seq: 0,
    };
    test::run(test_file!("hpke_tests.txt"), |section, test_case| {
        let s: Vec<&str> = section.split("-").collect();
        let s_type = SectionType::from_str(s[0]).unwrap();

        match s_type {
            SectionType::Setup => {
                let setup = Setup {
                    mode: test_case.consume_usize("mode"),
                    kem_id: test_case.consume_usize("kem_id"),
                    kdf_id: test_case.consume_usize("kdf_id"),
                    aead_id: test_case.consume_usize("aead_id"),
                    info: test_case.consume_bytes("info"),
                    ikm_e: test_case.consume_bytes("ikmE"),
                    pke_m: test_case.consume_bytes("pkEm"),
                    ske_m: test_case.consume_bytes("skEm"),
                    ikm_r: test_case.consume_bytes("ikmR"),
                    pkr_m: test_case.consume_bytes("pkRm"),
                    skr_m: test_case.consume_bytes("skRm"),
                    enc: test_case.consume_bytes("enc"),
                    shared_secret: test_case.consume_bytes("shared_secret"),
                    key_schedule_context: test_case.consume_bytes("key_schedule_context"),
                    secret: test_case.consume_bytes("secret"),
                    key: test_case.consume_bytes("key"),
                    base_nonce: test_case.consume_bytes("base_nonce"),
                    exporter_secret: test_case.consume_bytes("exporter_secret"),
                };
                latest_s = setup.clone();
                let kem = hpke::Kem::from_u16(setup.kem_id as u16).unwrap();
                let kp = kem.derive_key_pair(&setup.ikm_r).unwrap();
                assert_eq!(setup.pkr_m, kp.public_key_bytes());
                let mut encapped_key = vec![0u8; kem.public_key_length()];
                let suite =
                    hpke::Suite::from_u16_with_existing_kem(kem, setup.kdf_id as u16, setup.aead_id as u16)
                        .unwrap();
                let client_ctx = suite
                    .new_deterministic_sender_context(
                        kp.public_key_bytes(),
                        &setup.info,
                        &setup.ikm_e,
                        &mut encapped_key,
                    )
                    .unwrap();
                assert_eq!(setup.enc, encapped_key);
                let server_ctx = suite
                    .new_receiver_context(&kp, &encapped_key, &setup.info)
                    .unwrap();
                ctx.client_ctx = Some(client_ctx);
                ctx.server_ctx = Some(server_ctx);
                ctx.suite = Some(suite);
                ctx.seq = 0;
            }
            SectionType::Encryption => {
                let enc = Enc {
                    sequence_number: test_case.consume_usize("sequence_number"),
                    pt: test_case.consume_bytes("pt"),
                    aad: test_case.consume_bytes("aad"),
                    nonce: test_case.consume_bytes("nonce"),
                    ct: test_case.consume_bytes("ct"),
                };
                let mut msg = enc.pt.clone();
                let mut tag = vec![0u8; ctx.suite.as_ref().unwrap().aead_tag_len()];
                msg.append(&mut tag);
                for i in 0..enc.sequence_number-ctx.seq as usize {
                    let mut msg = vec![0u8; ctx.suite.as_ref().unwrap().aead_tag_len()];
                    ctx.client_ctx.as_mut().unwrap().encrypt_to_receiver(&mut msg, &[]).unwrap();
                    ctx.server_ctx.as_mut().unwrap().decrypt_from_sender(&[], &mut msg).unwrap();
                    ctx.seq += 1
                }
                ctx.client_ctx
                    .as_mut()
                    .unwrap()
                    .encrypt_to_receiver(&mut msg, &enc.aad)
                    .unwrap();

                msg.extend_from_slice(&tag);
                assert_eq!(enc.ct, msg);
                ctx.server_ctx
                    .as_mut()
                    .unwrap()
                    .decrypt_from_sender(&enc.aad, &mut msg)
                    .unwrap();
                ctx.seq += 1;
                assert_eq!(enc.pt, &msg[0..enc.pt.len()]);
            }
            SectionType::Exporter => {
                let exp = Exp {
                    exporter_ctx: test_case.consume_bytes("exporter_context"),
                    len: test_case.consume_usize("L"),
                    exported: test_case.consume_bytes("exported_value"),
                };
                let mut exported = vec![0u8; exp.len];
                ctx.client_ctx
                    .as_ref()
                    .unwrap()
                    .export(&exp.exporter_ctx, exp.len as u16, &mut exported)
                    .unwrap();
                assert_eq!(exp.exported, exported);
            }
        };
        Ok(())
    });
}
