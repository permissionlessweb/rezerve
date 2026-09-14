//! FROST-ed25519 distributed key generation (`keys::dkg::{part1,part2,part3}`).
//! Trusted-dealer keygen is out of scope for this module. Product seats are
//! part3 KeyPackages (env/stdin encoding), never a dealer share issuance.

use crate::frost::{FrostError, FrostGroup, FrostSeat};
use frost_ed25519 as frost;
use frost_ed25519::keys::dkg::{part1, part2, part3};
use frost_ed25519::keys::{KeyPackage, PublicKeyPackage};
use frost_ed25519::Identifier;
use rand::rngs::OsRng;
use std::collections::BTreeMap;

/// FROST group size. `min_signers` is t, `max_signers` is n (RFC 9591).
/// First demo uses [`FrostParams::FIRST_DEMO`]. Other (n, t) pairs are in-scope
/// for the design; this crate currently constructs DKG with these constants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrostParams {
    pub max_signers: u16,
    pub min_signers: u16,
}

impl FrostParams {
    /// First demonstration: three collaborative sidecars, any two sign.
    pub const FIRST_DEMO: Self = Self {
        max_signers: 3,
        min_signers: 2,
    };

    pub fn validate(self) -> Result<Self, FrostError> {
        if self.min_signers < 2 || self.max_signers < self.min_signers {
            return Err(FrostError::Protocol("frost params".into()));
        }
        Ok(self)
    }
}

pub const DKG_MAX_SIGNERS: u16 = FrostParams::FIRST_DEMO.max_signers;
pub const DKG_MIN_SIGNERS: u16 = FrostParams::FIRST_DEMO.min_signers;

type Round1Package = frost::keys::dkg::round1::Package;
type Round2Package = frost::keys::dkg::round2::Package;

fn proto(e: impl ToString) -> FrostError {
    FrostError::Protocol(e.to_string())
}

/// Same `id:pkg` encoding as `PIR_FROST_SEAT` / stdin. Not argv.
fn seat_from_part3(id: Identifier, kp: &KeyPackage) -> Result<FrostSeat, FrostError> {
    if kp.identifier() != &id {
        return Err(proto("seat identifier"));
    }
    if *kp.min_signers() != DKG_MIN_SIGNERS {
        return Err(proto("seat min_signers"));
    }
    let vk = kp.verifying_key().serialize().map_err(proto)?;
    if vk.iter().all(|b| *b == 0) {
        return Err(proto("dummy verifying key"));
    }
    let pkg = kp.serialize().map_err(proto)?;
    FrostSeat::decode(&format!(
        "{}:{}",
        hex::encode(id.serialize()),
        hex::encode(pkg)
    ))
}

/// One of three DKG participants. Round secrets never leave this party.
pub struct DkgParty {
    id: Identifier,
    r1_secret: Option<frost::keys::dkg::round1::SecretPackage>,
    r2_secret: Option<frost::keys::dkg::round2::SecretPackage>,
    key_package: Option<KeyPackage>,
}

impl std::fmt::Debug for DkgParty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DkgParty")
            .field("id", &self.id)
            .field("has_share", &self.key_package.is_some())
            .finish()
    }
}

impl DkgParty {
    pub fn from_index(i: u16) -> Result<Self, FrostError> {
        if i == 0 || i > DKG_MAX_SIGNERS {
            return Err(FrostError::Protocol("dkg identifier".into()));
        }
        Ok(Self {
            id: Identifier::try_from(i).expect("nonzero identifier"),
            r1_secret: None,
            r2_secret: None,
            key_package: None,
        })
    }

    pub fn identifier(&self) -> Identifier {
        self.id
    }

    /// `keys::dkg::part1`. Publishes a round-1 package; keeps the secret locally.
    pub fn round1(&mut self, rng: &mut OsRng) -> Result<Round1Package, FrostError> {
        if self.r1_secret.is_some() || self.r2_secret.is_some() || self.key_package.is_some() {
            return Err(proto("round1 already"));
        }
        let (sec, pkg) = part1(self.id, DKG_MAX_SIGNERS, DKG_MIN_SIGNERS, rng).map_err(proto)?;
        self.r1_secret = Some(sec);
        Ok(pkg)
    }

    /// `keys::dkg::part2`. Consumes the round-1 secret.
    pub fn round2(
        &mut self,
        others_r1: &BTreeMap<Identifier, Round1Package>,
    ) -> Result<BTreeMap<Identifier, Round2Package>, FrostError> {
        if self.r2_secret.is_some() || self.key_package.is_some() {
            return Err(proto("round2 already"));
        }
        if others_r1.contains_key(&self.id) {
            return Err(proto("round1 includes self"));
        }
        if others_r1.len() != (DKG_MAX_SIGNERS as usize).saturating_sub(1) {
            return Err(proto("round1 others"));
        }
        let sec = self.r1_secret.take().ok_or_else(|| proto("r1 secret"))?;
        let (sec2, pkgs) = part2(sec, others_r1).map_err(proto)?;
        self.r2_secret = Some(sec2);
        Ok(pkgs)
    }

    /// `keys::dkg::part3`. Consumes the round-2 secret; stores only this party's KeyPackage.
    pub fn round3(
        &mut self,
        others_r1: &BTreeMap<Identifier, Round1Package>,
        inbox: &BTreeMap<Identifier, Round2Package>,
    ) -> Result<(KeyPackage, PublicKeyPackage), FrostError> {
        if self.key_package.is_some() {
            return Err(proto("round3 already"));
        }
        if others_r1.contains_key(&self.id) || inbox.contains_key(&self.id) {
            return Err(proto("round includes self"));
        }
        let need = (DKG_MAX_SIGNERS as usize).saturating_sub(1);
        if others_r1.len() != need || inbox.len() != need {
            return Err(proto("round3 others"));
        }
        let sec2 = self.r2_secret.take().ok_or_else(|| proto("r2 secret"))?;
        let (kp, pk) = part3(&sec2, others_r1, inbox).map_err(proto)?;
        if kp.identifier() != &self.id {
            return Err(proto("part3 identifier"));
        }
        if *kp.min_signers() != DKG_MIN_SIGNERS {
            return Err(proto("part3 min_signers"));
        }
        let kp_vk = kp.verifying_key().serialize().map_err(proto)?;
        let pk_vk = pk.verifying_key().serialize().map_err(proto)?;
        if kp_vk != pk_vk {
            return Err(proto("part3 key package vk"));
        }
        if kp_vk.iter().all(|b| *b == 0) {
            return Err(proto("dummy verifying key"));
        }
        let pk_share = pk
            .verifying_shares()
            .get(&self.id)
            .ok_or_else(|| proto("part3 verifying share"))?;
        if kp.verifying_share() != pk_share {
            return Err(proto("part3 verifying share mismatch"));
        }
        self.key_package = Some(kp.clone());
        Ok((kp, pk))
    }

    /// This party's part3 output. None until `round3`.
    pub fn key_package(&self) -> Option<&KeyPackage> {
        self.key_package.as_ref()
    }

    /// PIR_FROST_SEAT / stdin encoding of this party's part3 share. Not argv.
    pub fn seat(&self) -> Result<FrostSeat, FrostError> {
        let kp = self.key_package.as_ref().ok_or_else(|| proto("part3 pending"))?;
        seat_from_part3(self.id, kp)
    }
}

fn others_round1(
    mine: Identifier,
    pkgs: &BTreeMap<Identifier, Round1Package>,
) -> BTreeMap<Identifier, Round1Package> {
    pkgs.iter()
        .filter(|(k, _)| **k != mine)
        .map(|(k, v)| (*k, v.clone()))
        .collect()
}

struct DkgShares {
    packages: Vec<(Identifier, KeyPackage)>,
    pubkeys: PublicKeyPackage,
}

/// Three-party DKG (t=2): part1 → part2 → part3. Identifiers 1, 2, 3.
fn run_three_party_dkg() -> Result<DkgShares, FrostError> {
    let mut rng = OsRng;
    let mut parties = [
        DkgParty::from_index(1)?,
        DkgParty::from_index(2)?,
        DkgParty::from_index(3)?,
    ];

    let mut r1_pkg = BTreeMap::new();
    for p in &mut parties {
        let pkg = p.round1(&mut rng)?;
        r1_pkg.insert(p.id, pkg);
    }

    let mut r2_inbox: BTreeMap<Identifier, BTreeMap<Identifier, Round2Package>> = BTreeMap::new();
    for p in &mut parties {
        let others = others_round1(p.id, &r1_pkg);
        let pkgs = p.round2(&others)?;
        for (recv, pkg) in pkgs {
            r2_inbox.entry(recv).or_default().insert(p.id, pkg);
        }
    }

    let mut packages = Vec::new();
    let mut pubkeys: Option<PublicKeyPackage> = None;
    for p in &mut parties {
        let others = others_round1(p.id, &r1_pkg);
        let inbox = r2_inbox.get(&p.id).ok_or_else(|| proto("r2 inbox"))?;
        let (kp, pk) = p.round3(&others, inbox)?;
        if let Some(prev) = &pubkeys {
            let left = prev.verifying_key().serialize().map_err(proto)?;
            let right = pk.verifying_key().serialize().map_err(proto)?;
            if left != right {
                return Err(proto("part3 verifying key mismatch"));
            }
        }
        packages.push((p.id, kp));
        pubkeys = Some(pk);
    }
    packages.sort_by_key(|(id, _)| *id);

    if packages.len() != DKG_MAX_SIGNERS as usize {
        return Err(FrostError::BelowThreshold {
            have: packages.len() as u16,
            need: DKG_MAX_SIGNERS,
        });
    }
    for (i, (id, _)) in packages.iter().enumerate() {
        let expect = Identifier::try_from((i as u16) + 1).expect("nonzero identifier");
        if *id != expect {
            return Err(proto("dkg seat order"));
        }
    }

    let pubkeys = pubkeys.ok_or_else(|| proto("pubkey package"))?;
    if pubkeys.verifying_shares().len() != DKG_MAX_SIGNERS as usize {
        return Err(proto("part3 verifying share count"));
    }
    let vk = pubkeys.verifying_key().serialize().map_err(proto)?;
    if vk.iter().all(|b| *b == 0) {
        return Err(proto("dummy verifying key"));
    }
    for (id, kp) in &packages {
        let share = pubkeys
            .verifying_shares()
            .get(id)
            .ok_or_else(|| proto("part3 verifying share"))?;
        if kp.verifying_share() != share {
            return Err(proto("part3 verifying share mismatch"));
        }
        let kp_vk = kp.verifying_key().serialize().map_err(proto)?;
        if kp_vk != vk {
            return Err(proto("part3 key package vk"));
        }
    }

    Ok(DkgShares {
        packages,
        pubkeys,
    })
}

/// In-process group that still holds part3 KeyPackages (signing via `seats()`).
pub fn dkg_three_party() -> Result<FrostGroup, FrostError> {
    let shares = run_three_party_dkg()?;
    let group = FrostGroup::from_key_packages(
        DKG_MIN_SIGNERS,
        DKG_MAX_SIGNERS,
        shares.packages,
        shares.pubkeys,
    )?;
    if group.is_dealer() {
        return Err(proto("dealer leftover"));
    }
    Ok(group)
}

/// Product path: verifying group plus ordered seats (tenant, provider, resolver).
/// KeyPackages live only on the seats (part3), not on the group.
pub fn dkg_escrow_seats() -> Result<(FrostGroup, [FrostSeat; 3]), FrostError> {
    let shares = run_three_party_dkg()?;
    let seats = [
        seat_from_part3(shares.packages[0].0, &shares.packages[0].1)?,
        seat_from_part3(shares.packages[1].0, &shares.packages[1].1)?,
        seat_from_part3(shares.packages[2].0, &shares.packages[2].1)?,
    ];
    let group = FrostGroup::from_key_packages(
        DKG_MIN_SIGNERS,
        DKG_MAX_SIGNERS,
        Vec::new(),
        shares.pubkeys,
    )?;
    if group.is_dealer() {
        return Err(proto("dealer leftover"));
    }
    if group.remaining_shares() != 0 {
        return Err(proto("dkg group retained shares"));
    }
    if group.min_signers != DKG_MIN_SIGNERS || group.max_signers != DKG_MAX_SIGNERS {
        return Err(proto("dkg threshold must be 3 parties min=2"));
    }
    if group.verifying_key.iter().all(|b| *b == 0) {
        return Err(proto("dummy verifying key"));
    }
    for (i, seat) in seats.iter().enumerate() {
        let expect = Identifier::try_from((i as u16) + 1).expect("nonzero identifier");
        if seat.identifier_bytes() != expect.serialize() {
            return Err(proto("dkg seat order"));
        }
        let encoded = seat.encode()?;
        let pkg_hex = encoded.split_once(':').ok_or_else(|| proto("seat"))?.1;
        let pkg_b = hex::decode(pkg_hex).map_err(proto)?;
        let package = KeyPackage::deserialize(&pkg_b).map_err(proto)?;
        let vk = package.verifying_key().serialize().map_err(proto)?;
        if vk.as_slice() != group.verifying_key.as_slice() {
            return Err(proto("seat group verifying key"));
        }
        if *package.min_signers() != DKG_MIN_SIGNERS {
            return Err(proto("seat min_signers"));
        }
    }
    Ok((group, seats))
}

/// Product seats: tenant then provider (first two DKG identifiers).
pub fn tenant_provider_seats(group: &FrostGroup) -> Result<(FrostSeat, FrostSeat), FrostError> {
    let seats = group.seats();
    if seats.len() < 2 {
        return Err(FrostError::BelowThreshold {
            have: seats.len() as u16,
            need: 2,
        });
    }
    Ok((seats[0].clone(), seats[1].clone()))
}

/// Threshold sign using tenant + provider seats only.
pub fn sign_tenant_provider(group: &FrostGroup, msg: &[u8]) -> Result<Vec<u8>, FrostError> {
    let (tenant, provider) = tenant_provider_seats(group)?;
    group.sign_with_seats(msg, &[tenant, provider])
}
