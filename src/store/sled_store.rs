

use dsf_core::prelude::*;

use crate::log::Debug;
use super::*;

pub struct SledStore<Addr: Clone + Debug> {
    db: sled::Db,
    peers: std::collections::HashMap<Id, Peer<Addr>>,
    _addr: PhantomData<Addr>,
}

impl <Addr: Clone + Debug> SledStore<Addr> {
    /// Create a new sled-backed store
    pub fn new(path: &str) -> Result<Self, sled::Error> {
        let db = sled::Config::default()
            .path(path)
            .cache_capacity(100_000_000)
            .flush_every_ms(Some(1_000))
            .open()?;

        let peers = std::collections::HashMap::new();

        Ok(Self{db, peers, _addr: PhantomData})
    }
}

const SLED_IDENT_KEY: &[u8] = b"ident";
const SLED_PAGE_KEY: &[u8] = b"page";
const SLED_LAST_KEY: &[u8] = b"last";

impl <Addr: Clone + Debug + 'static> Store for SledStore<Addr> {
    const FEATURES: StoreFlags = StoreFlags::ALL;

    type Address = Addr;

    type Error = sled::Error;

    type Iter<'a> = std::collections::hash_map::Iter<'a, Id, Peer<Addr>>;

    fn get_ident(&self) -> Result<Option<Keys>, Self::Error> {
        let ident = self.db.open_tree(SLED_IDENT_KEY)?;

        let mut keys = Keys::default();

        if let Some(pri_key) = ident.get("pri_key")? {
            let pri_key = PrivateKey::try_from(pri_key.as_ref()).unwrap();

            keys.pub_key = Some(Crypto::get_public(&pri_key));
            keys.pri_key = Some(pri_key);
        }

        if let Some(sec_key) = ident.get("sec_key")? {
            keys.sec_key = SecretKey::try_from(sec_key.as_ref()).ok();
        }

        match keys.pub_key.is_some() {
            true => Ok(Some(keys)),
            false => Ok(None),
        }
    }

    fn set_ident(&mut self, keys: &Keys) -> Result<(), Self::Error> {
        let ident = self.db.open_tree(SLED_IDENT_KEY)?;

        if let Some(pri_key) = keys.pri_key.as_deref() {
            ident.insert("pri_key", pri_key)?;
        }

        if let Some(sec_key) = keys.sec_key.as_deref() {
            ident.insert("sec_key", sec_key)?;
        }

        Ok(())
    }

    fn get_last(&self) -> Result<Option<ObjectInfo>, Self::Error> {
        match self.db.get(SLED_LAST_KEY)? {
            Some(k) => {
                let d = k.as_ref();

                Ok(Some(ObjectInfo{
                    page_index: LittleEndian::read_u16(&k[0..]),
                    block_index: LittleEndian::read_u16(&k[2..]),
                    sig: Signature::try_from(&k[4..][..SIGNATURE_LEN]).unwrap(),
                }))
            },
            None => Ok(None),
        }
    }

    fn set_last(&mut self, info: &ObjectInfo) -> Result<(), Self::Error> {
        let mut d = [0u8; 2 + 2 + SIGNATURE_LEN];

        LittleEndian::write_u16(&mut d[0..], info.page_index);
        LittleEndian::write_u16(&mut d[2..], info.block_index);
        d[4..].copy_from_slice(&info.sig);

        self.db.insert(SLED_LAST_KEY, d.as_slice())?;

        Ok(())
    }

    fn get_peer(&self, id: &Id) -> Result<Option<Peer<Addr>>, Self::Error> {
        let p = self.peers.get(id);
        Ok(p.map(|p| p.clone() ))
    }

    fn peers<'a>(&'a self) -> Self::Iter<'a> {
        self.peers.iter()
    }

    fn update_peer<R: Debug, F: Fn(&mut Peer<Addr>)-> R>(&mut self, id: &Id, f: F) -> Result<R, Self::Error> {
        let p = self.peers.entry(id.clone()).or_default();
        Ok(f(p))
    }

    fn store_page<T: ImmutableData>(&mut self, sig: &Signature, p: &Container<T>) -> Result<(), Self::Error> {
        let pages = self.db.open_tree(SLED_PAGE_KEY)?;

        pages.insert(sig, p.raw())?;

        Ok(())
    }

    fn fetch_page<T: MutableData>(&mut self, sig: &Signature, mut buff: T) -> Result<Option<Container<T>>, Self::Error> {
        let pages = self.db.open_tree(SLED_PAGE_KEY)?;

        match pages.get(sig)? {
            Some(p) => {
                let b = buff.as_mut();
                let p = p.as_ref();

                b[..p.len()].copy_from_slice(p);

                let (c, _n) = Container::from(buff);
                Ok(Some(c))
            },
            None => Ok(None),
        }
    }
}

impl <Addr: Clone + Debug> KeySource for SledStore<Addr> {
    fn keys(&self, id: &Id) -> Option<Keys> {
        self.peers.get(id).map(|p| p.keys.clone() )
    }
}

#[cfg(test)]
mod tests {
    
}