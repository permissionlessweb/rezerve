//! Private **seam** swaps + FROST IBC deposit. Feature `seam-dex`.

#[cfg(feature = "seam-dex")]
mod live {
    use private_inference_rent::frost::FrostGroup;
    use private_inference_rent::seam_swap::{
        demo_zec_hub_pool, frost_backed_pool, ibc_deposit_then_swap, quote_hub_to_b,
    };
    use private_inference_rent::tagged_hash;
    use terp_seams::dex::SeamState;

    #[test]
    fn ibc_zec_deposit_frost_then_seam_swap() {
        let group = tagged_hash(b"g", &[b"seam-ibc"]);
        let frost = FrostGroup::dealer(3, 2).unwrap();
        let mut fp = frost_backed_pool(group, frost.clone());
        let mut pool = demo_zec_hub_pool();
        let quoted = quote_hub_to_b(&pool, 10_000).unwrap();
        let mut state = SeamState::default();
        let seats = frost.seats();
        let out = ibc_deposit_then_swap(&mut fp, &frost, &seats, &mut pool, &mut state, 10_000, 42)
            .expect("swap");
        assert_eq!(out, quoted);
        assert_eq!(fp.balance_zat, 10_000);
        assert!(state.nullifiers.contains(&42));
    }

    #[test]
    fn unsigned_frost_cannot_open_ibc_note_into_swap() {
        let group = tagged_hash(b"g", &[b"seam-no"]);
        let frost = FrostGroup::dealer(3, 2).unwrap();
        let mut fp = frost_backed_pool(group, frost);
        // credit without frost sig must fail when pool.frost is set
        let note = tagged_hash(b"n", &[b"x"]);
        let att = private_inference_rent::hashmerchant::DepositAttestation::prove_for_test(
            [1u8; 32],
            note,
            10,
            group,
        );
        let parts = [
            ("alpha", &["alpha-s0", "alpha-s2", "alpha-s4"][..]),
            ("beta", &["beta-s0", "beta-s1", "beta-s2"][..]),
        ];
        let auth = private_inference_rent::SpendAuth::from_quorum(
            fp.layered.as_ref().unwrap(),
            &parts,
            group,
            note,
            10,
            None,
        )
        .unwrap();
        assert!(fp.credit_deposit(&att, &auth).is_err());
    }
}

#[test]
fn terp_seams_dir_is_the_private_dex_not_juno() {
    let dir = private_inference_rent::zakura::seam_private_dex_dir();
    if let Some(p) = dir {
        let readme = std::fs::read_to_string(p.join("README.md")).unwrap_or_default();
        assert!(
            readme.contains("private_dex_seams") || readme.contains("DEX"),
            "expected seam private dex readme at {p:?}"
        );
        assert!(
            !readme.to_ascii_lowercase().contains("astroport"),
            "must not be the Juno Astroport DEX"
        );
    }
}
