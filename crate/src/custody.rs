//! Member_id → FROST seat map. DKG seats are unlabeled until bound here.
//! Happy-path sign is deployer+provider. Resolver seat is used only after grant.
//! Product holder path: KeyPackage via `PIR_FROST_SEAT` or stdin, never argv.

use crate::escrow::{EscrowCell, EscrowError, EscrowMemberIds};
use crate::frost::{FrostError, FrostGroup, FrostSeat};
use crate::frost_dkg::{dkg_escrow_seats, DKG_MAX_SIGNERS, DKG_MIN_SIGNERS};
use frost_ed25519::keys::KeyPackage;
use frost_ed25519::Identifier;
use std::collections::BTreeMap;
use thiserror::Error;

pub const PIR_FROST_SEAT_ENV: &str = "PIR_FROST_SEAT";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CustodyError {
    #[error("unknown member {0}")]
    UnknownMember(String),
    #[error("resolver share not granted")]
    ResolverDenied,
    #[error("empty member id")]
    EmptyMember,
    #[error("duplicate member id")]
    DuplicateMember,
    #[error("need three DKG seats")]
    NeedThreeSeats,
    #[error("frost: {0}")]
    Frost(#[from] FrostError),
    #[error("escrow: {0}")]
    Escrow(#[from] EscrowError),
    #[error("seat env/stdin missing")]
    SeatSource,
    #[error("key package on argv is forbidden")]
    ArgvForbidden,
}

fn proto(e: impl ToString) -> CustodyError {
    CustodyError::Frost(FrostError::Protocol(e.to_string()))
}

fn dkg_identifier_bytes(i: u16) -> Vec<u8> {
    Identifier::try_from(i)
        .expect("nonzero identifier")
        .serialize()
}

/// Product roles are DKG identifiers 1, 2, 3 (deployer, provider, resolver).
fn require_dkg_seat_roles(
    tenant: &FrostSeat,
    provider: &FrostSeat,
    resolver: &FrostSeat,
) -> Result<(), CustodyError> {
    if tenant.identifier_bytes() != dkg_identifier_bytes(1)
        || provider.identifier_bytes() != dkg_identifier_bytes(2)
        || resolver.identifier_bytes() != dkg_identifier_bytes(3)
    {
        return Err(CustodyError::Frost(FrostError::Protocol(
            "dkg seat order".into(),
        )));
    }
    Ok(())
}

fn require_dkg_group(group: &FrostGroup) -> Result<(), CustodyError> {
    if group.is_dealer() {
        return Err(CustodyError::Frost(FrostError::Protocol(
            "dealer leftover".into(),
        )));
    }
    if group.min_signers != DKG_MIN_SIGNERS || group.max_signers != DKG_MAX_SIGNERS {
        return Err(CustodyError::Frost(FrostError::Protocol(
            "dkg threshold must be 3 parties min=2".into(),
        )));
    }
    if group.remaining_shares() != 0 {
        return Err(CustodyError::Frost(FrostError::Protocol(
            "dkg group retained shares".into(),
        )));
    }
    if group.verifying_key.iter().all(|b| *b == 0) {
        return Err(CustodyError::Frost(FrostError::Protocol(
            "dummy verifying key".into(),
        )));
    }
    Ok(())
}

/// Seat KeyPackage verifying key (DKG group vk). Rejects dummy / dealer leftovers
/// that do not match this encoding.
fn seat_group_vk(seat: &FrostSeat) -> Result<Vec<u8>, CustodyError> {
    let encoded = seat.encode()?;
    let decoded = decode_product_seat(&encoded)?;
    if decoded.identifier_bytes() != seat.identifier_bytes() {
        return Err(proto("seat identifier"));
    }
    let pkg_hex = encoded.split_once(':').ok_or_else(|| proto("seat"))?.1;
    let pkg_b = hex::decode(pkg_hex).map_err(|e| proto(e))?;
    let package = KeyPackage::deserialize(&pkg_b).map_err(|e| proto(e))?;
    if package.identifier().serialize() != seat.identifier_bytes() {
        return Err(proto("seat identifier"));
    }
    if *package.min_signers() != DKG_MIN_SIGNERS {
        return Err(proto("seat min_signers"));
    }
    let vk = package.verifying_key().serialize().map_err(proto)?;
    if vk.iter().all(|b| *b == 0) {
        return Err(proto("dummy verifying key"));
    }
    Ok(vk)
}

/// Seat KeyPackage verifying key must be this DKG group's vk (not a dealer leftover).
fn require_seat_in_group(group: &FrostGroup, seat: &FrostSeat) -> Result<(), CustodyError> {
    let vk = seat_group_vk(seat)?;
    if vk.as_slice() != group.verifying_key.as_slice() {
        return Err(proto("seat group verifying key"));
    }
    Ok(())
}

/// Tenant, provider, and resolver seats must be one DKG run (same group vk).
fn require_same_dkg_group(
    tenant: &FrostSeat,
    provider: &FrostSeat,
    resolver: &FrostSeat,
) -> Result<(), CustodyError> {
    let a = seat_group_vk(tenant)?;
    let b = seat_group_vk(provider)?;
    let c = seat_group_vk(resolver)?;
    if a != b || b != c {
        return Err(proto("seat group verifying key"));
    }
    Ok(())
}

/// `id:pkg` from env/stdin. Rejects argv-shaped input and id/package mismatch.
fn decode_product_seat(line: &str) -> Result<FrostSeat, CustodyError> {
    let line = line.trim();
    if line.is_empty() {
        return Err(CustodyError::SeatSource);
    }
    if line.starts_with('-') || line.contains("--key-package") {
        return Err(CustodyError::ArgvForbidden);
    }
    let (id_hex, pkg_hex) = line.split_once(':').ok_or_else(|| proto("seat"))?;
    let id_b = hex::decode(id_hex).map_err(|e| proto(e))?;
    let pkg_b = hex::decode(pkg_hex).map_err(|e| proto(e))?;
    let identifier = Identifier::deserialize(&id_b).map_err(|e| proto(e))?;
    let package = KeyPackage::deserialize(&pkg_b).map_err(|e| proto(e))?;
    if package.identifier() != &identifier {
        return Err(proto("seat identifier"));
    }
    if *package.min_signers() != DKG_MIN_SIGNERS {
        return Err(proto("seat min_signers"));
    }
    let vk = package.verifying_key().serialize().map_err(proto)?;
    if vk.iter().all(|b| *b == 0) {
        return Err(proto("dummy verifying key"));
    }
    let seat = FrostSeat::decode(line)?;
    if seat.identifier_bytes() != identifier.serialize() {
        return Err(proto("seat identifier"));
    }
    Ok(seat)
}

/// Side map: deployer / provider / resolver → issued seats.
/// Seat Debug redacts KeyPackage bytes (see `FrostSeat`).
#[derive(Clone, Debug)]
pub struct EscrowHolders {
    seats: BTreeMap<String, FrostSeat>,
    pub tenant_id: String,
    pub provider_id: String,
    pub resolver_id: String,
}

impl EscrowHolders {
    pub fn bind(
        members: &EscrowMemberIds,
        tenant: FrostSeat,
        provider: FrostSeat,
        resolver: FrostSeat,
    ) -> Result<Self, CustodyError> {
        if members.tenant.is_empty()
            || members.provider.is_empty()
            || members.resolver.is_empty()
        {
            return Err(CustodyError::EmptyMember);
        }
        if members.tenant == members.provider
            || members.provider == members.resolver
            || members.tenant == members.resolver
        {
            return Err(CustodyError::DuplicateMember);
        }
        require_dkg_seat_roles(&tenant, &provider, &resolver)?;
        let tenant = decode_product_seat(&tenant.encode()?)?;
        let provider = decode_product_seat(&provider.encode()?)?;
        let resolver = decode_product_seat(&resolver.encode()?)?;
        require_dkg_seat_roles(&tenant, &provider, &resolver)?;
        require_same_dkg_group(&tenant, &provider, &resolver)?;
        let a = tenant.identifier_bytes();
        let b = provider.identifier_bytes();
        let c = resolver.identifier_bytes();
        if a == b || b == c || a == c {
            return Err(CustodyError::Frost(FrostError::Protocol(
                "dkg seat collision".into(),
            )));
        }
        let mut seats = BTreeMap::new();
        seats.insert(members.tenant.clone(), tenant);
        seats.insert(members.provider.clone(), provider);
        seats.insert(members.resolver.clone(), resolver);
        Ok(Self {
            seats,
            tenant_id: members.tenant.clone(),
            provider_id: members.provider.clone(),
            resolver_id: members.resolver.clone(),
        })
    }

    /// Bind already-held DKG seats (identifiers 1, 2, 3). Product custody is [`from_dkg`].
    pub fn from_issued(
        members: &EscrowMemberIds,
        issued: Vec<FrostSeat>,
    ) -> Result<Self, CustodyError> {
        if issued.len() != 3 {
            return Err(CustodyError::NeedThreeSeats);
        }
        require_dkg_seat_roles(&issued[0], &issued[1], &issued[2])?;
        let mut it = issued.into_iter();
        Self::bind(
            members,
            it.next().unwrap(),
            it.next().unwrap(),
            it.next().unwrap(),
        )
    }

    /// Product custody: seats from DKG part1/2/3 (3 parties, min=2).
    /// Not trusted-dealer issuance. Group keeps verifying material only.
    /// KeyPackages live on seats (`PIR_FROST_SEAT` / stdin, never argv).
    pub fn from_dkg(members: &EscrowMemberIds) -> Result<(FrostGroup, Self), CustodyError> {
        if members.tenant.is_empty()
            || members.provider.is_empty()
            || members.resolver.is_empty()
        {
            return Err(CustodyError::EmptyMember);
        }
        if members.tenant == members.provider
            || members.provider == members.resolver
            || members.tenant == members.resolver
        {
            return Err(CustodyError::DuplicateMember);
        }
        let (group, seats) = dkg_escrow_seats()?;
        require_dkg_group(&group)?;
        let [tenant, provider, resolver] = seats;
        require_dkg_seat_roles(&tenant, &provider, &resolver)?;
        Ok((group, Self::bind(members, tenant, provider, resolver)?))
    }

    pub fn seat(&self, member_id: &str) -> Result<&FrostSeat, CustodyError> {
        self.seats
            .get(member_id)
            .ok_or_else(|| CustodyError::UnknownMember(member_id.into()))
    }

    /// Tenant + provider only (threshold 2). Resolver is not in this set.
    pub fn happy_sign(&self, group: &FrostGroup, msg: &[u8]) -> Result<Vec<u8>, CustodyError> {
        require_dkg_group(group)?;
        let tenant = self.seat(&self.tenant_id)?;
        let provider = self.seat(&self.provider_id)?;
        require_seat_in_group(group, tenant)?;
        require_seat_in_group(group, provider)?;
        let seats = [tenant.clone(), provider.clone()];
        Ok(group.sign_with_seats(msg, &seats)?)
    }

    /// Resolver share only after [`EscrowCell::resolver_may_sign`] grant.
    /// `other` must be the tenant or provider seat (not the resolver).
    pub fn sign_after_grant(
        &self,
        cell: &EscrowCell,
        group: &FrostGroup,
        msg: &[u8],
        other: &str,
    ) -> Result<Vec<u8>, CustodyError> {
        require_dkg_group(group)?;
        if other == self.resolver_id {
            return Err(CustodyError::ResolverDenied);
        }
        if other != self.tenant_id && other != self.provider_id {
            return Err(CustodyError::UnknownMember(other.into()));
        }
        cell.resolver_may_sign(&self.resolver_id)
            .map_err(|_| CustodyError::ResolverDenied)?;
        let resolver = self.seat(&self.resolver_id)?;
        let other_seat = self.seat(other)?;
        require_seat_in_group(group, resolver)?;
        require_seat_in_group(group, other_seat)?;
        let seats = [resolver.clone(), other_seat.clone()];
        Ok(group.sign_with_seats(msg, &seats)?)
    }

    /// Encode for `PIR_FROST_SEAT` (env or stdin). Not argv.
    pub fn encode_seat_env(seat: &FrostSeat) -> Result<String, CustodyError> {
        Ok(seat.encode()?)
    }

    pub fn load_seat_from_env() -> Result<FrostSeat, CustodyError> {
        let s = std::env::var(PIR_FROST_SEAT_ENV).map_err(|_| CustodyError::SeatSource)?;
        decode_product_seat(&s)
    }

    pub fn load_seat_from_stdin(line: &str) -> Result<FrostSeat, CustodyError> {
        decode_product_seat(line)
    }

    /// Product holder never reads a KeyPackage from process argv.
    pub fn load_seat_from_argv(
        _args: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<FrostSeat, CustodyError> {
        Err(CustodyError::ArgvForbidden)
    }
}
