#[cfg(test)]
pub struct MockComms {
    pub(crate) tx: Vec<(u8, Vec<u8>)>,
}

#[cfg(test)]
impl Default for MockComms {
    fn default() -> Self {
        Self { tx: vec![] }
    }
}

#[cfg(test)]
impl Communications for MockComms {
    type Address = u8;

    type Error = core::convert::Infallible;

    fn recv(&mut self, _buff: &mut [u8]) -> Result<Option<(usize, Self::Address)>, Self::Error> {
        todo!()
    }

    fn send(&mut self, to: &Self::Address, data: &[u8]) -> Result<(), Self::Error> {
        self.tx.push((*to, data.to_vec()));
        Ok(())
    }

    fn broadcast(&mut self, _data: &[u8]) -> Result<(), Self::Error> {
        todo!()
    }
}
